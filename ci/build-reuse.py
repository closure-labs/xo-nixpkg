#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Collect sandboxed CI builds and reuse independently authenticated exact NARs."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
import sys
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import operations

REPOSITORY = 'closure-labs/xo-nixpkg'
WORKFLOW = '.github/workflows/ci.yml'
SHA = re.compile(r'[a-f0-9]{40}')
STORE = re.compile(r'/nix/store/[a-z0-9]{32}-[^/\s]+')
ATTRIBUTES = {
    'xo-latest': 'latest', 'xo-stable': 'stable', 'xo-rolling': 'rolling',
    'libvhdi': 'libvhdi', 'supply-protector-latest': 'supply-protector-latest',
    'supply-protector-stable': 'supply-protector-stable',
    'supply-protector-rolling': 'supply-protector-rolling',
    'automation-runtime': 'automation-runtime',
}


class UnavailableProducer(ValueError):
    """Optional historical run metadata cannot authenticate this cache candidate."""


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 4 * 1024**2,
            'Missing, nonregular or oversized reuse receipt')
    return json.loads(path.read_text())


def command(args, **kwargs):
    if args[0] == 'gh':
        limit = 30 if args[1:2] == ['api'] else 90
        if args[1:3] == ['run', 'download'] and '--name' in args and 'payload' in args[args.index('--name') + 1]:
            limit = 180
        return operations.run(args, capture_output=True, text=True, check=True, timeout=limit, **kwargs).stdout.strip()
    if args[1:3] == ['store', 'verify'] or 'eval' in args:
        return operations.run(args, capture_output=True, text=True, check=True, timeout=600, **kwargs).stdout.strip()
    return subprocess.check_output(args, text=True, **kwargs).strip()


def api(path):
    return json.loads(command(['gh', 'api', path]))


def git(root, *args):
    return command(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(root), *args])


def trusted_cache_policy():
    """Read only the cache policy embedded in the protected packaged launcher."""
    source = os.environ.get('XO_NIXPKG_TRUSTED_CACHE_POLICY', '')
    require(isinstance(source, str) and STORE.fullmatch(source), 'Pinned trusted cache policy required')
    path = Path(source)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 4096,
            'Missing, nonregular or oversized trusted cache policy')
    return validate_trusted_cache_policy(json.loads(path.read_text()))


def validate_trusted_cache_policy(policy):
    require(isinstance(policy, dict) and set(policy) == {'schema', 'name', 'url', 'publicKey'}
            and type(policy['schema']) is int and policy['schema'] == 1,
            'Invalid trusted cache policy schema')
    name, url, key = (policy[field] for field in ('name', 'url', 'publicKey'))
    require(isinstance(name, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name),
            'Invalid trusted cache name')
    host = name + '.cachix.org'
    require(isinstance(url, str) and url in ('https://' + host, 'https://' + host + '/'),
            'Invalid trusted cache HTTPS URL')
    match = re.fullmatch(re.escape(host) + r'-1:([A-Za-z0-9+/]{43}=)', key) if isinstance(key, str) else None
    require(match is not None, 'Trusted cache key does not match its host')
    decoded = base64.b64decode(match[1], validate=True)
    require(len(decoded) == 32 and base64.b64encode(decoded).decode() == match[1],
            'Invalid trusted cache public key')
    return policy


def child_environment(directory):
    """Candidate evaluation cannot read inherited tokens, HOME or Nix settings."""
    cache = trusted_cache_policy()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'nix').mkdir(exist_ok=True)
    (directory / 'nix/nix.conf').write_text('')
    environment = {key: os.environ[key] for key in
                   ('PATH', 'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE', 'LANG', 'LC_ALL')
                   if key in os.environ}
    environment.update(HOME=str(directory), XDG_CONFIG_HOME=str(directory / 'config'),
                       XDG_CACHE_HOME=str(directory / 'cache'),
                       NIX_CONF_DIR=str(directory / 'nix'), NIX_USER_CONF_FILES='/dev/null',
                       NIX_CONFIG='experimental-features = nix-command flakes\n'
                                  'accept-flake-config = false\nsandbox = true\nbuilders =\n'
                                  'require-sigs = true\n'
                                  f'extra-substituters = {cache["url"]}\n'
                                  f'extra-trusted-public-keys = {cache["publicKey"]}\n',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_TERMINAL_PROMPT='0')
    return environment


def nix_arguments(*args):
    binary = os.environ['XO_NIXPKG_TRUSTED_NIX']
    require(binary.startswith('/nix/store/') and binary.endswith('/bin/nix'), 'Pinned native Nix required')
    return [binary, *args, '--no-accept-flake-config', '--option', 'sandbox', 'true',
            '--option', 'builders', '', '--option', 'pure-eval', 'true',
            '--option', 'allow-unsafe-native-code-during-evaluation', 'false']


def nix(environment, *args):
    return command(nix_arguments(*args), env=environment)


def identity(candidate, environment, name):
    attribute = 'packages.x86_64-linux.' + ATTRIBUTES[name]
    result = json.loads(nix(environment, 'eval', '--json', '--no-write-lock-file',
                            'git+file://' + str(candidate) + '#' + attribute,
                            '--apply', 'p: { storePath = p.outPath; derivation = p.drvPath; }'))
    require(set(result) == {'storePath', 'derivation'} and STORE.fullmatch(result['storePath'])
            and STORE.fullmatch(result['derivation']) and result['derivation'].endswith('.drv'),
            'Invalid evaluated output identity')
    return dict(result, attribute=attribute)


def transport():
    source = os.environ['XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE']
    spec = importlib.util.spec_from_file_location('distribution_transport', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def blob(repository, revision, path):
    value = api(f'repos/{repository}/contents/{path}?ref={revision}')
    require(value.get('type') == 'file' and value.get('encoding') == 'base64', 'Missing trusted source blob')
    return hashlib.sha256(base64.b64decode(value['content'], validate=False)).hexdigest()


def producer(receipt, controller, tree):
    """Validate historical provenance; a receipt never supplies its own authority."""
    require(isinstance(receipt, dict) and receipt.get('schema') == 1
            and receipt.get('repository') == REPOSITORY, 'Invalid reuse receipt identity')
    require(receipt.get('tree') == tree and receipt.get('system') == 'x86_64-linux', 'Reuse tree/platform mismatch')
    for key in ('source', 'controller'):
        require(isinstance(receipt.get(key), str) and SHA.fullmatch(receipt[key]), 'Invalid reuse revision')
    require(type(receipt.get('runId')) is int and receipt['runId'] > 0
            and type(receipt.get('runAttempt')) is int and receipt['runAttempt'] > 0,
            'Invalid reuse run identity')
    require(receipt.get('workflow') == WORKFLOW and receipt.get('event') in
            ('pull_request', 'merge_group', 'workflow_dispatch'), 'Invalid reuse workflow/event')
    ref = receipt.get('ref', '')
    patterns = {'pull_request': r'refs/pull/[0-9]+/merge',
                'merge_group': r'refs/heads/gh-readonly-queue/main/.+',
                'workflow_dispatch': r'refs/heads/main'}
    require(isinstance(ref, str) and re.fullmatch(patterns[receipt['event']], ref), 'Invalid reuse source ref')
    run = api(f'repos/{REPOSITORY}/actions/runs/{receipt["runId"]}/attempts/{receipt["runAttempt"]}')
    require(run.get('id') == receipt['runId'] and run.get('run_attempt') == receipt['runAttempt']
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('repository', {}).get('full_name') == REPOSITORY
            and run.get('head_repository', {}).get('full_name') == REPOSITORY
            and run.get('event') == receipt['event'] and run.get('path', '').split('@')[0] == WORKFLOW,
            'Untrusted/incomplete reuse producer')
    source = api(f'repos/{REPOSITORY}/git/commits/{receipt["source"]}')
    require(source.get('sha') == receipt['source'] and source.get('tree', {}).get('sha') == tree,
            'Reuse commit/tree mismatch')
    parents = [item['sha'] for item in source.get('parents', [])]
    require(run.get('head_sha') == receipt['source'] or
            (receipt['event'] == 'pull_request' and len(parents) == 2 and run.get('head_sha') in parents),
            'Reuse run does not identify the built commit')
    if receipt['event'] == 'pull_request':
        pulls = run.get('pull_requests', [])
        # GitHub may omit a merged PR's historical run association. Never infer
        # its protected base from today's mutable PR state; try another cache.
        if pulls == []:
            raise UnavailableProducer('Reuse run must identify one protected-base PR: historical association unavailable')
        require(isinstance(pulls, list) and len(pulls) == 1, 'Reuse run must identify one protected-base PR')
        base, head = pulls[0].get('base', {}), pulls[0].get('head', {})
        repo_url = f'https://api.github.com/repos/{REPOSITORY}'
        require(base.get('ref') == 'main' and base.get('sha') == receipt['controller']
                and base.get('repo', {}).get('url') == repo_url
                and head.get('repo', {}).get('url') == repo_url
                and head.get('sha') == run.get('head_sha')
                and parents == [receipt['controller'], head.get('sha')],
                'Reuse PR controller differs from the actual protected base')
    elif receipt['event'] == 'merge_group':
        require(run.get('head_branch') == ref.removeprefix('refs/heads/')
                and parents and parents[0] == receipt['controller']
                and ref.endswith('-' + receipt['controller']),
                'Reuse merge queue controller differs from its exact base')
    else:
        require(run.get('head_branch') == 'main' and receipt['controller'] == receipt['source'],
                'Reuse dispatch controller must be the exact main revision')
    current = api(f'repos/{REPOSITORY}/git/ref/heads/main')['object']['sha']
    ancestry = api(f'repos/{REPOSITORY}/compare/{receipt["controller"]}...{current}')
    require(ancestry.get('status') in ('ahead', 'identical'), 'Reuse controller was not protected main')
    historical_workflow = blob(REPOSITORY, receipt['controller'], WORKFLOW)
    require(receipt.get('workflowSha256') == historical_workflow
            and blob(REPOSITORY, receipt['source'], WORKFLOW) == historical_workflow,
            'Candidate workflow differs from historical protected controller')
    require(receipt.get('launcherSha256') == blob(REPOSITORY, receipt['controller'], 'ci/build-reuse.py'),
            'Reuse launcher differs from historical protected controller')
    return run


def compatible_producer(receipt, controller):
    # Apply only after historical provenance, signature and output validation.
    # Legitimate protected-controller upgrades make old bytes ineligible.
    if receipt['workflowSha256'] != digest(controller / WORKFLOW) or receipt['launcherSha256'] != digest(Path(__file__)):
        raise UnavailableProducer('Authenticated historical controller differs from current trusted controller')


def verify_attestation(path, receipt):
    try:
        raw = command(['gh', 'attestation', 'verify', str(path), '--repo', REPOSITORY,
                                  '--signer-workflow', REPOSITORY + '/' + WORKFLOW,
                                  '--source-digest', receipt['source'], '--source-ref', receipt['ref'],
                                  '--deny-self-hosted-runners', '--format', 'json'])
    except subprocess.CalledProcessError as error:
        raise ValueError('Reuse attestation verification failed') from error
    results = json.loads(raw)
    expected = f'https://github.com/{REPOSITORY}/actions/runs/{receipt["runId"]}/attempts/{receipt["runAttempt"]}'
    statements = [result.get('verificationResult', {}).get('statement', {}) for result in results]
    require(any(statement.get('predicate', {}).get('runDetails', {}).get('metadata', {}).get('invocationId') == expected
                for statement in statements), 'Attestation is not from the exact reuse run/attempt')


def restore(candidate, controller, output, names):
    state = {'importStarted': False}
    started = time.monotonic()
    try:
        with operations.budget(300):
            return restore_available(candidate, controller, output, names, state)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        if state['importStarted'] or (isinstance(error, subprocess.CalledProcessError) and error.cmd[0] != 'gh'):
            raise
        result = {'schema': 1, 'status': 'miss',
                  'reason': 'optional-transport-timeout' if isinstance(error, subprocess.TimeoutExpired) else 'artifact discovery/transport unavailable',
                  'elapsedSeconds': round(time.monotonic() - started, 3), 'authorityClaim': False}
        write_json(output, result)
        return result


def restore_available(candidate, controller, output, names, state=None):
    state = state if state is not None else {'importStarted': False}
    """An authentic cache hit imports bytes, never a validation/admission verdict."""
    started = time.monotonic()
    reuse_builds = os.environ.get('XO_NIXPKG_REUSE_BUILDS', 'true')
    require(reuse_builds in ('true', 'false'), 'XO_NIXPKG_REUSE_BUILDS must be true or false')
    if reuse_builds == 'false':
        result = {'schema': 1, 'status': 'miss', 'reason': 'Actions artifact imports disabled',
                  'authorityClaim': False}
        write_json(output, result)
        return result
    if not os.environ.get('GH_TOKEN'):
        result = {'schema': 1, 'status': 'miss', 'reason': 'no read-only artifact credential', 'authorityClaim': False}
        write_json(output, result)
        return result
    tree = git(candidate, 'rev-parse', 'HEAD^{tree}')
    with tempfile.TemporaryDirectory(prefix='xo-reuse-') as temporary:
        temporary = Path(temporary)
        environment = child_environment(temporary / 'native')
        expected = {name: identity(candidate, environment, name) for name in names}
        preimport_deadline = operations.DEADLINE.get()
        operations.DEADLINE.set(min(preimport_deadline, time.monotonic() + 90))
        discovery_deadline = time.monotonic() + 90
        runs = api(f'repos/{REPOSITORY}/actions/workflows/ci.yml/runs?status=success&per_page=30')['workflow_runs']
        for run in runs:
            if time.monotonic() >= discovery_deadline:
                raise subprocess.TimeoutExpired(['optional-discovery'], 90)
            if run.get('event') not in ('pull_request', 'merge_group', 'workflow_dispatch'):
                continue
            run_id, attempt = run['id'], run['run_attempt']
            artifact_name = f'xo-ci-reuse-receipt-{run_id}-{attempt}'
            artifacts = api(f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts')['artifacts']
            eligible = [item for item in artifacts if item.get('name') == artifact_name and not item.get('expired')]
            if not eligible:
                continue
            require(len(eligible) == 1 and eligible[0]['size_in_bytes'] <= 4 * 1024**2, 'Ambiguous/oversized reuse artifact')
            directory = temporary / str(run_id)
            command(['gh', 'run', 'download', str(run_id), '--repo', REPOSITORY,
                     '--name', artifact_name, '--dir', str(directory)])
            path = directory / 'receipt.json'
            receipt = read_json(path)
            if receipt.get('tree') != tree:
                continue
            require(receipt.get('runId') == run_id and receipt.get('runAttempt') == attempt, 'Artifact/run substitution')
            try:
                producer(receipt, controller, tree)
            except UnavailableProducer:
                continue
            verify_attestation(path, receipt)
            outputs = receipt.get('outputs')
            require(isinstance(outputs, dict) and outputs and set(outputs) <= ATTRIBUTES.keys(), 'Invalid reuse output set')
            matched = []
            for name, item in outputs.items():
                require(isinstance(item, dict) and set(item) == {'attribute', 'derivation', 'storePath', 'narHash'}
                        and STORE.fullmatch(item['storePath']) and STORE.fullmatch(item['derivation'])
                        and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', item['narHash']), 'Invalid authenticated output')
                if name in expected and all(item[key] == expected[name][key] for key in expected[name]):
                    matched.append(name)
            try:
                compatible_producer(receipt, controller)
            except UnavailableProducer:
                continue
            if not matched:
                continue
            operations.DEADLINE.set(preimport_deadline)
            payload = directory / 'payload'
            command(['gh', 'run', 'download', str(run_id), '--repo', REPOSITORY,
                     '--name', f'xo-ci-reuse-payload-{run_id}-{attempt}', '--dir', str(payload)])
            roots = [{'storePath': item['storePath'], 'narHash': item['narHash']} for item in outputs.values()]
            # Optional availability fallback ends before any store import.
            state['importStarted'] = True
            with operations.budget(600, inherit=False):
                transport().restore(payload, receipt['transport'], roots, recursive_verify=False)
                nix(environment, 'store', 'verify', '--no-trust', '--recursive', *sorted({root['storePath'] for root in roots}))
            result = {'schema': 1, 'status': 'hit', 'runId': run_id, 'runAttempt': attempt,
                      'source': receipt['source'], 'matchedOutputs': sorted(matched),
                      'elapsedSeconds': round(time.monotonic() - started, 3), 'authorityClaim': False}
            write_json(output, result)
            return result
    result = {'schema': 1, 'status': 'miss', 'reason': 'no authenticated exact-tree/output cache',
              'elapsedSeconds': round(time.monotonic() - started, 3), 'authorityClaim': False}
    write_json(output, result)
    return result


def validate_plan(plan):
    require(isinstance(plan, dict) and set(plan) == {'schemaVersion', 'name', 'targets'}
            and plan['schemaVersion'] == 2 and isinstance(plan['targets'], list) and plan['targets'], 'Invalid selected CI plan')
    names, attributes = set(), set()
    for item in plan['targets']:
        require(isinstance(item, dict) and set(item) == {'name', 'attribute'}
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', item.get('name', ''))
                and re.fullmatch(r'checks\.x86_64-linux\.[A-Za-z0-9][A-Za-z0-9._+-]*', item.get('attribute', ''))
                and '..' not in item['attribute'] and item['name'] not in names and item['attribute'] not in attributes,
                'Unsafe/duplicate selected target')
        names.add(item['name']); attributes.add(item['attribute'])


def validate(candidate, controller, evidence):
    prepared = json.loads(os.environ['PREPARED_CI_WORKFLOW'])
    plan = prepared['jobs']['validate']['plan']
    validate_plan(plan)
    evidence.mkdir(parents=True, exist_ok=True)
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as stream: stream.write('cache_eligible=false\n')
    with tempfile.TemporaryDirectory(prefix='xo-trusted-build-') as temporary:
        temporary = Path(temporary)
        environment = child_environment(temporary / 'native')
        wrapper = os.environ['XO_NIXPKG_TRUSTED_PLAN_NIX']
        require(wrapper.startswith('/nix/store/') and wrapper.endswith('/bin/xo-nixpkg-candidate-nix'),
                'Pinned sandboxed plan Nix required')
        environment['FLAKE_PLAN_RUNNER_NIX'] = wrapper
        reference = 'git+file://' + str(candidate)
        nix(environment, 'flake', 'check', '--no-build', '--no-write-lock-file', reference)
        contract = json.loads((controller / 'ci/classifier.json').read_text())
        cheap = set(contract['preflightTargets'])
        for phase, targets in [('preflight', [x for x in plan['targets'] if x['name'] in cheap]),
                               ('runtime', [x for x in plan['targets'] if x['name'] not in cheap])]:
            if not targets:
                continue
            if phase == 'runtime':
                names = sorted({x['name'] for x in targets} & ATTRIBUTES.keys())
                if names:
                    restore(candidate, controller, evidence / 'reuse-restore.json', names)
            phase_plan = dict(plan, name=plan['name'] + '-' + phase, targets=targets)
            plan_path = temporary / (phase + '.json')
            write_json(plan_path, phase_plan)
            jobs = os.environ.get('XO_NIXPKG_BUILD_JOBS', '1') if phase == 'runtime' else '1'
            require(jobs in ('1', '2'), 'Build concurrency must be 1 or 2')
            subprocess.run([os.environ['XO_NIXPKG_PLAN_RUNNER'], '--flake', reference,
                            '--plan-file', str(plan_path), '--manifest', str(evidence / (phase + '.json')),
                            '--timings', str(evidence / (phase + '-timings.json')), '--jobs', jobs],
                           env=environment, check=True)
        event = os.environ.get('GITHUB_EVENT_NAME')
        if event not in ('pull_request', 'merge_group', 'workflow_dispatch') or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
            return
        if digest(candidate / WORKFLOW) != digest(controller / WORKFLOW):
            return
        event_data = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        if event == 'pull_request' and event_data['pull_request']['head']['repo']['full_name'] != REPOSITORY:
            return
        if event == 'workflow_dispatch' and os.environ.get('GITHUB_REF') != 'refs/heads/main':
            return
        runtime = evidence / 'runtime.json'
        if not runtime.exists():
            return
        outputs = {}
        for result in read_json(runtime)['results']:
            name = result['name']
            if name not in ATTRIBUTES:
                continue
            item = identity(candidate, environment, name)
            require(result['status'] == 'success' and result['outputs'] == [item['storePath']], 'Built/evaluated output mismatch')
            metadata = json.loads(nix(environment, 'path-info', '--json', item['storePath']))
            metadata = metadata[0] if isinstance(metadata, list) else metadata[item['storePath']]
            outputs[name] = dict(item, narHash=metadata['narHash'])
        if not outputs:
            return
        source = git(candidate, 'rev-parse', 'HEAD')
        require(source == os.environ['GITHUB_SHA'], 'Built checkout differs from GitHub source identity')
        roots = [{'storePath': value['storePath'], 'narHash': value['narHash']} for value in outputs.values()]
        payload = evidence / 'reuse-payload'
        started = time.monotonic()
        manifest = transport().export(payload, roots)
        receipt = {'schema': 1, 'repository': REPOSITORY, 'workflow': WORKFLOW,
                   'source': source, 'tree': git(candidate, 'rev-parse', 'HEAD^{tree}'),
                   'controller': git(controller, 'rev-parse', 'HEAD'),
                   'workflowSha256': digest(controller / WORKFLOW), 'launcherSha256': digest(Path(__file__)),
                   'system': 'x86_64-linux', 'event': event, 'ref': os.environ['GITHUB_REF'],
                   'runId': int(os.environ['GITHUB_RUN_ID']), 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
                   'outputs': outputs, 'transport': manifest, 'authorityClaim': False,
                   'exportSeconds': round(time.monotonic() - started, 3)}
        write_json(evidence / 'reuse-receipt/receipt.json', receipt)
        if github_output:
            with open(github_output, 'a') as stream: stream.write('cache_eligible=true\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['validate', 'restore'])
    parser.add_argument('--candidate', type=Path, default=os.environ.get('CI_CANDIDATE_ROOT', '.'))
    parser.add_argument('--controller', type=Path, default=os.environ.get('CI_CONTROLLER_ROOT', '.'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--names', nargs='+', choices=sorted(ATTRIBUTES), default=['xo-latest', 'xo-stable', 'xo-rolling', 'libvhdi'])
    args = parser.parse_args()
    if args.output is None:
        args.output = Path(os.environ.get('XO_NIXPKG_CI_EVIDENCE', 'ci-evidence'))
        if args.operation == 'restore':
            args.output /= 'reuse-restore.json'
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Native x86_64 Linux required')
    if args.operation == 'validate':
        validate(args.candidate.resolve(), args.controller.resolve(), args.output.resolve())
    else:
        print(json.dumps(restore(args.candidate.resolve(), args.controller.resolve(), args.output.resolve(), args.names)))


if __name__ == '__main__':
    main()
