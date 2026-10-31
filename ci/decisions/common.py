"""Shared validation and live trust boundaries for small automation commands."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

import operations
import observability
import decision_authority as authority
import decision_packets as packets
from security_decisions import (canonical_hash, load_json, evaluate, validate_normalized,
                                validate_context, compare_context)

HASH = re.compile(r'[0-9a-f]{64}')
SHA = authority.SHA


def require(value, message):
    if not value:
        raise ValueError(message)


def command(args, timeout=None, **kwargs):
    return operations.run(args, check=True, capture_output=True, text=True,
                          timeout=timeout if timeout is not None else (30 if args[:2] == ['gh', 'api'] else 180),
                          **kwargs).stdout


def emit(result, output=None):
    value = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n'
    if output:
        Path(output).write_text(value)
    print(value, end='')


def run(main):
    try:
        return main() or 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'schema': 1, 'status': 'blocked', 'error': str(error)}), file=sys.stderr)
        return 2


def parser(description):
    result = argparse.ArgumentParser(description=description)
    result.add_argument('--config', required=True, type=Path)
    result.add_argument('--output', type=Path)
    return result


def config(path, live=False, enabled=False, api=None):
    api = api or authority.github_api
    value = load_json(path)
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1, 'Invalid decision policy')
    authority.validate_context(value.get('repository'), value.get('botLogin'))
    require(type(value.get('enabled')) is bool, 'Explicit enabled policy required')
    require(type(value.get('appId')) is int and value['appId'] > 0, 'Pinned App integration ID required')
    profiles = value.get('profiles')
    require(isinstance(profiles, list) and profiles and len(set(profiles)) == len(profiles)
            and all(isinstance(p, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', p) for p in profiles),
            'Invalid complete profile set')
    coverage = value.get('requiredCoverage', {})
    require(isinstance(coverage, dict) and set(coverage).issubset(profiles)
            and all(isinstance(contract, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', contract)
                    for contract in coverage.values()), 'Invalid required native coverage policy')
    require(value.get('decisionRoot', 'automation/decisions') == 'automation/decisions', 'Unsupported decision root')
    require(isinstance(value.get('producerWorkflows'), list) and value['producerWorkflows']
            and all(re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', w)
                    for w in value['producerWorkflows']), 'Pinned producer workflows required')
    policy_path = value.get('policyPath')
    require(isinstance(policy_path, str) and re.fullmatch(r'(?:nix/automation|ci)/decision-policy\.json', policy_path),
            'Pinned policy repository path required')
    packets.REGISTRY = 'ghcr.io/' + value['repository'].lower() + '-decisions'
    packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
    if live:
        revision = main_revision(value, api)
        checked = authority.document_at(api, value['repository'], policy_path, revision)
        require(canonical_hash(checked) == canonical_hash(value), 'Local policy differs from current main')
    if enabled:
        require(value['enabled'], 'Publication is disabled pending coordinated activation')
    return value


def main_revision(cfg, api=None):
    api = api or authority.github_api
    result = api('repos/' + cfg['repository'] + '/git/ref/heads/main')
    revision = result.get('object', {}).get('sha', '')
    require(SHA.fullmatch(revision), 'Invalid main revision')
    return revision


def ledger(cfg, api=None, *, with_policy=False):
    """Fetch every immutable canonical decision from an untruncated current-main tree."""
    api = api or authority.github_api
    revision = main_revision(cfg, api)
    tree = api(f'repos/{cfg["repository"]}/git/trees/{revision}?recursive=1')
    require(isinstance(tree, dict) and tree.get('truncated') is False and isinstance(tree.get('tree'), list),
            'Complete current-main Git tree required')
    records, seen = {}, set()
    for item in tree['tree']:
        path = item.get('path', '')
        if not path.startswith('automation/decisions/') or item.get('type') == 'tree':
            continue
        require(path not in seen, 'Duplicate ledger Git tree entry')
        seen.add(path)
        require(item.get('type') == 'blob' and item.get('mode') == '100644'
                and re.fullmatch(r'automation/decisions/(security|releases)/[0-9a-f]{64}\.json', path),
                'Malformed decision ledger path or mode')
        # The freshly read, complete tree already binds this regular path to
        # its immutable blob. Avoid a redundant Contents lookup for every row.
        proposal = authority.document_blob(api, cfg['repository'], item.get('sha'), item.get('size'))
        require(authority.proposal_path(proposal) == path, 'Decision content hash/path mismatch')
        records[canonical_hash(proposal)] = proposal
    if with_policy:
        entries = [entry for entry in tree['tree'] if entry.get('path') == cfg['policyPath']]
        require(len(entries) == 1 and entries[0].get('type') == 'blob'
                and entries[0].get('mode') == '100644', 'Current policy must be one regular Git blob')
        entry = entries[0]
        policy = authority.document_blob(api, cfg['repository'], entry.get('sha'), entry.get('size'))
        return revision, records, policy
    return revision, records


def authorize(cfg, proposal, api=None, pr=None, allow_open=False):
    api = api or authority.github_api
    number = pr or authority.find_origin_pr(proposal, cfg['repository'], cfg['botLogin'], github=api)
    return authority.verify_proposal(proposal, number, cfg['repository'], cfg['botLogin'],
                                     require_merged=not allow_open, github=api)


def historical_provenance(cfg, proposal, api=None):
    """A superseded parent needs immutable bot merge provenance, never live authority."""
    api = api or authority.github_api
    number = authority.find_origin_pr(proposal, cfg['repository'], cfg['botLogin'], github=api)
    return authority.verify_proposal(proposal, number, cfg['repository'], cfg['botLogin'],
                                     require_merged=True, github=api, require_live_review=False)


def security_contexts(native):
    return {profile: validate_context(scan['securityContext'])
            for profile, scan in native['profiles'].items() if 'securityContext' in scan}


def accepted_contexts(payload):
    """Retain policy review even when a profile has no vulnerability findings."""
    profiles = payload['profiles']
    if 'securityContexts' in payload:
        contexts = payload['securityContexts']
        require(isinstance(contexts, dict) and set(contexts).issubset(profiles),
                'Invalid accepted profile security contexts')
        return {profile: validate_context(context) for profile, context in contexts.items()}
    # Existing nonempty decisions already bind a context in each finding.
    # Empty legacy decisions cannot claim knowledge of an unrecorded policy.
    contexts = {}
    for profile, findings in profiles.items():
        values = [finding['securityContext'] for finding in findings if 'securityContext' in finding]
        if values:
            require(len(values) == len(findings) and all(value == values[0] for value in values),
                    'Ambiguous accepted profile security context')
            contexts[profile] = validate_context(values[0])
    return contexts


def compare_security_contexts(native, payload):
    current, accepted = security_contexts(native), accepted_contexts(payload)
    return {profile: compare_context(current.get(profile), accepted.get(profile))
            for profile in native['profiles']}


def active_security(cfg, records, api=None, authenticate=True):
    candidates = {h: p for h, p in records.items() if p['kind'] in ('security-findings', 'security-revocation')}
    superseded = set()
    for digest, proposal in candidates.items():
        payload = proposal['payload']
        require(payload.get('disposition') in ('accepted', 'rejected', 'revoked'), 'Invalid security disposition')
        require(isinstance(payload.get('profiles'), dict) and set(payload['profiles']) == set(cfg['profiles']),
                'Security decision must cover complete configured profile set')
        for profile, findings in payload['profiles'].items():
            validate_normalized(findings)
            require(all(f['profile'] == profile for f in findings), 'Cross-profile decision confusion')
        accepted_contexts(payload)
        parents = payload.get('supersedes', [])
        require(isinstance(parents, list) and len(set(parents)) == len(parents)
                and all(h in candidates and h != digest for h in parents), 'Invalid supersession parents')
        require(isinstance(payload.get('rationale'), str) and payload['rationale'].strip(), 'Decision rationale required')
        packet = payload.get('packet', {})
        require(isinstance(packet, dict) and packets.REFERENCE.fullmatch(packet.get('reference', ''))
                and HASH.fullmatch(packet.get('sha256', '')), 'Immutable decision packet required')
        if proposal['kind'] == 'security-revocation':
            require(payload['disposition'] == 'revoked' and len(parents) == 1, 'Revocation requires one parent')
            parent = candidates[parents[0]]['payload']
            require(parent['disposition'] == 'accepted' and payload['profiles'] == parent['profiles']
                    and payload.get('securityContexts') == parent.get('securityContexts')
                    and packet == parent['packet'], 'Revocation must preserve exact accepted scope and evidence')
        superseded.update(parents)
    # Detect cycles even when a separate apparently-valid leaf exists.
    visited, visiting = set(), set()
    def visit(digest):
        require(digest not in visiting, 'Cyclic decision supersession')
        if digest in visited:
            return
        visiting.add(digest)
        for parent in candidates[digest]['payload'].get('supersedes', []):
            visit(parent)
        visiting.remove(digest)
        visited.add(digest)
    for digest in candidates:
        visit(digest)
    for digest in superseded:
        historical_provenance(cfg, candidates[digest], api)
    leaves = set(candidates) - superseded
    require(len(leaves) <= 1, 'Ambiguous concurrent security decisions require explicit reconciliation')
    if not leaves:
        return None, None
    digest = next(iter(leaves))
    if authenticate:
        authorize(cfg, candidates[digest], api)
    return digest, candidates[digest]


def active_release(cfg, records, identity, api=None, authenticate=True):
    """Select one explicitly superseding release approval for these exact bytes."""
    product_hash = canonical_hash(identity)
    candidates = {h: p for h, p in records.items() if p['kind'] == 'release-product'
                  and canonical_hash(p['payload'].get('product')) == product_hash}
    superseded = set()
    for digest, proposal in candidates.items():
        payload = proposal['payload']
        require(payload.get('disposition') in ('accepted', 'rejected', 'revoked')
                and isinstance(payload.get('rationale'), str) and payload['rationale'].strip(),
                'Invalid release decision disposition or rationale')
        packet = payload.get('packet', {})
        require(isinstance(packet, dict) and packets.REFERENCE.fullmatch(packet.get('reference', ''))
                and HASH.fullmatch(packet.get('sha256', '')), 'Immutable release packet required')
        parents = payload.get('supersedes', [])
        require(isinstance(parents, list) and len(parents) == len(set(parents))
                and all(parent in candidates and parent != digest for parent in parents),
                'Release supersession must preserve exact product identity')
        superseded.update(parents)
    visited, visiting = set(), set()
    def visit(digest):
        require(digest not in visiting, 'Cyclic release decision supersession')
        if digest in visited:
            return
        visiting.add(digest)
        for parent in candidates[digest]['payload'].get('supersedes', []):
            visit(parent)
        visiting.remove(digest)
        visited.add(digest)
    for digest in candidates:
        visit(digest)
    for digest in superseded:
        historical_provenance(cfg, candidates[digest], api)
    leaves = set(candidates) - superseded
    require(len(leaves) <= 1, 'Ambiguous release decisions require explicit supersession')
    if not leaves:
        return None, None
    digest = next(iter(leaves))
    if authenticate:
        authorize(cfg, candidates[digest], api)
    return digest, candidates[digest]


def timestamp(value):
    require(isinstance(value, str), 'UTC timestamp required')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(), 'UTC timestamp required')
    return parsed


ATTESTATION_STDOUT_LIMIT = 2 * 1024**2
ATTESTATION_STDERR_LIMIT = 16 * 1024
ATTESTATION_TIMEOUT = 180


def attestation_diagnostic(code, stderr, stderr_bytes, **metadata):
    # Never return arbitrary verifier output: it may contain credentials or URLs.
    text = stderr.decode('utf-8', errors='replace').lower()
    statuses = sorted({int(value) for value in re.findall(
        r'\b(?:http(?:/[0-9.]+)?|status(?:\s+code)?)\s*[:=( ]\s*(401|403|404|408|429|500|502|503|504)\b', text)})
    patterns = {
        'authorization-denied': r'\bunauthorized\b|\bforbidden\b|resource not accessible by integration',
        'rate-limited': r'rate limit|too many requests',
        'network': r'connection reset|connection refused|no such host|temporary failure in name resolution|unexpected eof',
        'tls': r'tls handshake|certificate signed by unknown authority|certificate verify failed|x509:',
        'timeout': r'context deadline exceeded|i/o timeout|timed out',
        'disk-full': r'no space left on device|disk quota exceeded',
        'signature-invalid': r'invalid signature|signature verification failed|failed to verify signature',
        'identity-mismatch': r'source digest.*(?:mismatch|does not match)|(?:signer|subject|identity).*(?:mismatch|does not match)',
        'attestation-unavailable': r'no attestations found|no matching attestations',
        'trust-root': r'failed to (?:initialize|update|refresh).*tuf|failed to.*trusted root|expired.*(?:metadata|root)',
    }
    categories = {name for name, pattern in patterns.items() if re.search(pattern, text)}
    if any(status in (401, 403) for status in statuses):
        categories.add('authorization-denied')
    if 429 in statuses:
        categories.add('rate-limited')
    if any(status >= 500 for status in statuses):
        categories.add('remote-server')
    if metadata.get('timedOut'):
        categories.add('timeout')
    if metadata.get('outputLimitExceeded'):
        categories.add('output-limit')
    if metadata.get('errno') is not None:
        categories.add('start-failed')
    return 'Attestation verification failed: ' + json.dumps({
        'exitCode': code, 'signal': -code if code is not None and code < 0 else None,
        'categories': sorted(categories or {'unclassified'}), 'httpStatus': statuses,
        'stderrBytes': stderr_bytes, 'stderrTruncated': stderr_bytes > ATTESTATION_STDERR_LIMIT,
        'timeoutSeconds': ATTESTATION_TIMEOUT,
        **metadata}, sort_keys=True)


class AttestationCommandError(subprocess.CalledProcessError):
    def __str__(self):
        return self.cmd


class AttestationTimeout(subprocess.TimeoutExpired):
    def __str__(self):
        return self.cmd


def attestation_command(arguments):
    with operations.termination_guard():
        return bounded_attestation_command(arguments)


def bounded_attestation_command(arguments):
    timeout = operations.remaining(ATTESTATION_TIMEOUT)
    output, tail, stderr_bytes = bytearray(), bytearray(), 0
    try:
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as error:
        raise ValueError(attestation_diagnostic(None, tail, 0, errno=error.errno, timeoutSeconds=timeout)) from None
    with child:
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired('attestation', timeout)
                    for key, _ in selector.select(min(remaining, 1)):
                        block = os.read(key.fd, 64 * 1024)
                        if not block:
                            selector.unregister(key.fileobj)
                        elif key.data == 'stderr':
                            stderr_bytes += len(block)
                            tail.extend(block)
                            del tail[:-ATTESTATION_STDERR_LIMIT]
                        else:
                            if len(output) + len(block) > ATTESTATION_STDOUT_LIMIT:
                                raise ValueError(attestation_diagnostic(
                                    None, tail, stderr_bytes, outputLimitExceeded=True, timeoutSeconds=timeout))
                            output.extend(block)
            child.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            operations.terminate(child)
            raise AttestationTimeout(attestation_diagnostic(
                child.returncode, tail, stderr_bytes, timedOut=True, timeoutSeconds=timeout), timeout) from None
        except BaseException:
            operations.terminate(child)
            raise
        if child.returncode:
            raise AttestationCommandError(child.returncode,
                                          attestation_diagnostic(child.returncode, tail, stderr_bytes, timeoutSeconds=timeout))
    try:
        return json.loads(output.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise ValueError('Invalid attestation verifier JSON output') from None


def attest(path, cfg, revision, workflow):
    return attestation_command(['gh', 'attestation', 'verify', str(path), '--repo', cfg['repository'],
                               '--signer-workflow', cfg['repository'] + '/' + workflow,
                               '--source-digest', revision, '--source-ref', 'refs/heads/main',
                               '--deny-self-hosted-runners', '--format', 'json'])


def attest_product(path, cfg, revision):
    """Original product bytes may have a different producer than a later rescan."""
    for workflow in cfg['producerWorkflows']:
        try:
            return attest(path, cfg, revision, workflow)
        except subprocess.CalledProcessError:
            continue
    raise ValueError('Product has no trusted original producer attestation')


def verify_producer(cfg, producer, source_revision, api=None, require_main=False):
    """Authenticate the caller run separately from its reusable signing workflow."""
    api = api or authority.github_api
    require(isinstance(producer, dict), 'Invalid producer metadata')
    workflow = producer.get('workflow')
    signer = producer.get('signerWorkflow', workflow)
    revision = producer.get('revision', source_revision)
    require(workflow in cfg['producerWorkflows'] and signer in cfg['producerWorkflows']
            and type(producer.get('runId')) is int and producer['runId'] > 0
            and type(producer.get('runAttempt')) is int and producer['runAttempt'] > 0
            and isinstance(revision, str) and SHA.fullmatch(revision), 'Invalid producer identity')
    run = api(f'repos/{cfg["repository"]}/actions/runs/{producer["runId"]}/attempts/{producer["runAttempt"]}')
    require(run.get('id') == producer['runId'] and run.get('run_attempt') == producer['runAttempt']
            and run.get('head_sha') == revision and run.get('head_branch') == 'main'
            and run.get('event') in ('push', 'workflow_dispatch', 'schedule', 'workflow_run')
            and run.get('path', '').split('@')[0] == workflow and run.get('status') == 'completed'
            and run.get('conclusion') == 'success'
            and run.get('repository', {}).get('full_name') == cfg['repository'], 'Untrusted or incomplete native producer')
    if revision != source_revision:
        comparison = api(f'repos/{cfg["repository"]}/compare/{source_revision}...{revision}')
        require(comparison.get('status') in ('ahead', 'identical'), 'Rescan source must be an ancestor of trusted producer')
    if require_main:
        current = main_revision(cfg, api)
        comparison = api(f'repos/{cfg["repository"]}/compare/{revision}...{current}')
        require(comparison.get('status') in ('ahead', 'identical'), 'Original product producer is not on current protected main ancestry')
    return revision, signer


def coverage_roots(native, contract):
    coverage = native.get('coverage')
    require(isinstance(coverage, dict) and coverage.get('contract') == contract,
            'Native scan predates required distribution coverage')
    manifest = coverage.get('manifest')
    roots = manifest.get('roots') if isinstance(manifest, dict) else None
    require(isinstance(roots, dict) and roots
            and all(isinstance(name, str) and name and isinstance(path, str)
                    and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', path)
                    for name, path in roots.items()), 'Invalid distribution coverage roots')
    require(set(roots.values()) <= {subject.get('storePath') for subject in native.get('subjects', [])},
            'Distribution coverage roots absent from authenticated scanned subjects')
    return set(roots.values())


def scans(path, cfg, api=None, allow_expired=False):
    api = api or authority.github_api
    value = load_json(path)
    require(value.get('schema') == 1 and value.get('repository') == cfg['repository']
            and SHA.fullmatch(value.get('revision', '')), 'Invalid scan source identity')
    require(isinstance(value.get('profiles'), dict) and value['profiles']
            and set(value['profiles']).issubset(cfg['profiles']), 'Invalid scanned profile set')
    now = dt.datetime.now(dt.timezone.utc)
    scanned, expires = timestamp(value['scannedAt']), timestamp(value['expiresAt'])
    evidence_hours = cfg.get('maxEvidenceAgeHours', 24)
    database_hours = cfg.get('maxDatabaseAgeHours', 48)
    require(type(evidence_hours) is int and 0 < evidence_hours <= 48
            and type(database_hours) is int and 0 < database_hours <= 168, 'Invalid native health age policy')
    require(scanned <= now and scanned < expires and expires - scanned <= dt.timedelta(hours=evidence_hours)
            and (allow_expired or now < expires), 'Expired or future native health')
    if cfg.get('repositorySecretPolicy') and not allow_expired:
        require(value.get('repositorySecretPolicy') == cfg['repositorySecretPolicy'], 'Old-policy qualification is not current native evidence')
    producer = value.get('producer', {})
    producer_revision, signer = verify_producer(cfg, producer, value['revision'], api)
    attest(path, cfg, producer_revision, signer)
    for profile, native in value['profiles'].items():
        require(native.get('status') == 'complete' and native.get('scannerHealth') == 'healthy', 'Native scanner unhealthy')
        required_coverage = cfg.get('requiredCoverage', {}).get(profile)
        if required_coverage and not allow_expired:
            coverage_roots(native, required_coverage)
        native_time = timestamp(native.get('scannedAt'))
        require(scanned <= native_time <= now, 'Native observation predates envelope or is in the future')
        database = native.get('database', {})
        require(isinstance(database, dict) and database.get('valid') is True, 'Native scanner database is invalid')
        database_time = timestamp(database.get('built'))
        reference_time = native_time if allow_expired else now
        require(database_time <= native_time and reference_time - database_time <= dt.timedelta(hours=database_hours),
                'Native scanner database is stale or newer than its observation')
    return value


def product(path, cfg, scan, api=None):
    value = load_json(path)
    require(set(value).issubset({'schema', 'repository', 'revision', 'products', 'assets', 'roots', 'repositorySecretPolicy'})
            and type(value.get('schema')) is int and value['schema'] == 1 and value.get('repository') == cfg['repository']
            and value.get('revision') == scan['revision'], 'Invalid immutable product identity')
    require(isinstance(value.get('products'), dict) and value['products']
            and set(value['products']).issubset(scan['profiles']), 'Product profiles lack native evidence')
    def root(identity, profile):
        require(isinstance(identity, dict) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', identity.get('storePath', ''))
                and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', identity.get('narHash', '')),
                'Invalid output store/NAR identity')
        subjects = scan['profiles'][profile].get('subjects', [])
        require({'storePath': identity['storePath'], 'narHash': identity['narHash']} in subjects,
                'Distribution root absent from authenticated scanned subjects')
    for profile, identity in value['products'].items():
        require(set(identity) == {'storePath', 'narHash'}, 'Unsupported product root fields')
        root(identity, profile)
    require(isinstance(value.get('roots', {}), dict), 'Invalid auxiliary roots')
    for name, identity in value.get('roots', {}).items():
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and isinstance(identity, dict)
                and set(identity) == {'storePath', 'narHash', 'profile'}
                and identity['profile'] in value['products'], 'Invalid auxiliary root profile')
        root(identity, identity['profile'])
    for profile, primary in value['products'].items():
        native = scan['profiles'][profile]
        contract = cfg.get('requiredCoverage', {}).get(profile)
        # Historical products without the new marker remain restorable. A product
        # claiming complete coverage must retain every authenticated manifest root.
        if contract and native.get('coverage', {}).get('contract') == contract:
            retained = {primary['storePath']} | {
                identity['storePath'] for identity in value.get('roots', {}).values()
                if identity['profile'] == profile}
            require(coverage_roots(native, contract) <= retained,
                    'Distribution coverage roots absent from retained product')
    require(isinstance(value.get('assets'), dict)
            and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', name) and isinstance(digest, str) and HASH.fullmatch(digest)
                    for name, digest in value['assets'].items()), 'Invalid product asset hashes')
    if 'productProducer' in scan:
        original = scan['productProducer']
        require(isinstance(original, dict) and isinstance(original.get('revision'), str), 'Original product producer revision required')
        revision, signer = verify_producer(cfg, original, value['revision'], api, require_main=True)
        attest(path, cfg, revision, signer)
    else:
        attest_product(path, cfg, value['revision'])
    return value


def admission(cfg, scan, records, api=None):
    digest, proposal = active_security(cfg, records, api)
    require(proposal is not None and proposal['payload']['disposition'] == 'accepted', 'Current human risk acceptance required')
    require(all(not expanded for expanded, _ in compare_security_contexts(scan, proposal['payload']).values()),
            'Runtime security policy changes require a human decision')
    result = {profile: evaluate(native, profile, proposal['payload']['profiles'][profile])
              for profile, native in scan['profiles'].items()}
    require(all(r['status'] == 'covered' for r in result.values()), 'New or worsened findings require a human decision')
    return {'schema': 1, 'status': 'covered', 'decisionHash': digest, 'profiles': result}


def required_check(cfg, api=None):
    api = api or authority.github_api
    rules = api(f'repos/{cfg["repository"]}/rules/branches/main')
    require(isinstance(rules, list), 'Effective main rules must be readable')
    checks = [check for rule in rules if rule.get('type') == 'required_status_checks'
              for check in rule.get('parameters', {}).get('required_status_checks', [])]
    require(any(c.get('context') == cfg.get('requiredAuthorityCheck', 'Maintainer decision authority')
                and c.get('integration_id') == cfg['appId'] for c in checks),
            'Expected App-bound main authority check is not enforced')


def gate(cfg, scan_path, product_path=None, purpose='rolling', api=None):
    raw_api = api or authority.github_api
    calls, state = 0, 'blocked'
    def counted(endpoint):
        nonlocal calls
        calls += 1
        return raw_api(endpoint)
    try:
        result = _gate(cfg, scan_path, product_path, purpose, counted)
        state = 'passed'
        return result
    finally:
        try:
            observability.authority_requests(calls, state)
        except OSError:
            print('Could not retain authority request-count diagnostics.', file=sys.stderr)


def _gate(cfg, scan_path, product_path, purpose, api):
    require(cfg['enabled'], 'Publication disabled')
    required_check(cfg, api)
    revision, records = ledger(cfg, api)
    scan = scans(scan_path, cfg, api)
    comparison = api(f'repos/{cfg["repository"]}/compare/{scan["revision"]}...{revision}')
    require(comparison.get('status') in ('ahead', 'identical'), 'Candidate source is not on protected main ancestry')
    producer_revision = scan['producer'].get('revision', scan['revision'])
    if producer_revision != scan['revision']:
        comparison = api(f'repos/{cfg["repository"]}/compare/{producer_revision}...{revision}')
        require(comparison.get('status') in ('ahead', 'identical'), 'Rescan producer is not on protected main ancestry')
    result = admission(cfg, scan, records, api)
    if product_path:
        identity = product(product_path, cfg, scan, api)
        if cfg.get('repositorySecretPolicy'):
            require(identity.get('repositorySecretPolicy') == cfg['repositorySecretPolicy']
                    and scan.get('repositorySecretPolicy') == cfg['repositorySecretPolicy'], 'New policy-bound qualification required')
        digest = canonical_hash(identity)
        result['productHash'] = digest
        release_digest, release = active_release(cfg, records, identity, api)
        require(release is not None and release['payload'].get('disposition') == 'accepted',
                'Exact immutable product approval required')
    # Final complete-ledger refresh catches concurrent additions/revocations.
    current_revision, current, policy = ledger(cfg, api, with_policy=True)
    require(current == records, 'Current-main ledger changed during admission')
    active_security(cfg, current, api)
    if product_path:
        authorize(cfg, release, api)
    # The freshly read complete tree already binds policy to a verified blob.
    # Reuse hash-verified immutable bytes, never cache live authority conclusions.
    require(main_revision(cfg, api) == current_revision, 'Protected main moved during final admission')
    require(policy == cfg and policy['enabled'], 'Publication policy changed during admission')
    required_check(cfg, api)
    return result
