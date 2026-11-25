"""Shared native protection and evidence validation. Planning grants no approval."""
import os
import json
from pathlib import Path
import re
import subprocess

import common
import decision_authority as github
import decision_packets as packets
from security_decisions import canonical_hash, load_json, normalize_findings

REPOSITORY = 'closure-labs/xo-nixpkg'
POLICY = 'ci/publication-policy.json'
CHECKS = {'CI gate', 'Analyze (actions)', 'Analyze (python)',
          'Analyze (javascript-typescript)', 'Repository security audit'}
CODEQL_RULE = {'type': 'code_scanning', 'parameters': {'code_scanning_tools': [
    {'tool': 'CodeQL', 'alerts_threshold': 'errors', 'security_alerts_threshold': 'high_or_higher'}]}}
RULESET_BYPASS_QUERY = '''query NativeRulesetBypassCount {
  repository(owner: "closure-labs", name: "xo-nixpkg") {
    nameWithOwner
    ruleset(databaseId: 21015412) {
      databaseId enforcement bypassActors(first: 1) { totalCount }
    }
  }
}'''


def policy(path=Path(POLICY), *, live=False, api=None):
    api = api or github.github_api
    cfg = load_json(path)
    common.require(isinstance(cfg, dict) and type(cfg.get('schema')) is int and cfg['schema'] == 1
                   and cfg.get('approvalMode') == 'github-pr-v1'
                   and cfg.get('repository') == REPOSITORY and cfg.get('policyPath') == POLICY
                   and type(cfg.get('enabled')) is bool, 'Invalid native publication policy')
    common.require(cfg.get('environment') == 'publication'
                   and cfg.get('publisherWorkflow') == '.github/workflows/publish.yml'
                   and cfg.get('producerWorkflows') == ['.github/workflows/qualification.yml'],
                   'Native workflow and environment identities must be pinned')
    common.require(cfg.get('profiles') == ['xo-latest', 'xo-stable', 'xo-rolling', 'libvhdi']
                   and cfg.get('codeOwners') == ['@closure-labs/maintainers', '@closure-labs/super-admins']
                   and cfg.get('releaseRequestPath') == '.github/release-request.json'
                   and cfg.get('rulesetId') == 21015412
                   and type(cfg.get('minimumQueueTimeoutMinutes')) is int
                   and cfg['minimumQueueTimeoutMinutes'] >= 300, 'Incomplete native protection policy')
    for key, maximum in [('maxEvidenceAgeHours', 48), ('maxDatabaseAgeHours', 168)]:
        common.require(type(cfg.get(key)) is int and 0 < cfg[key] <= maximum, 'Invalid native evidence age')
    binding = cfg.get('repositorySecretPolicy')
    common.require(isinstance(binding, dict) and set(binding) == {'policyId', 'policySha256'}
                   and isinstance(binding['policyId'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,127}', binding['policyId'])
                   and isinstance(binding['policySha256'], str) and common.HASH.fullmatch(binding['policySha256']),
                   'Native secret policy required')
    packets.REGISTRY = 'ghcr.io/' + REPOSITORY + '-decisions'
    packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
    if live:
        revision = common.main_revision(cfg, api)
        current = github.document_at(api, REPOSITORY, POLICY, revision)
        common.require(current == cfg, 'Native publication policy differs from current protected main')
        owners = api(f'repos/{REPOSITORY}/contents/.github/CODEOWNERS?ref={revision}')
        common.require(owners.get('type') == 'file' and owners.get('target') is None
                       and type(owners.get('size')) is int and 0 < owners['size'] <= 65536,
                       'Native CODEOWNERS must be one bounded regular Git blob')
        data = github.decode_blob(owners, owners.get('sha'), owners.get('size')).decode('utf-8')
        entries = [line.strip() for line in data.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        common.require(entries == ['* ' + ' '.join(cfg['codeOwners'])], 'Native CODEOWNERS differs from review policy')
    return cfg


def validate_rules(cfg, rules):
    common.require(isinstance(rules, list), 'Effective native rules are unavailable')
    kinds = {r.get('type') for r in rules}
    common.require({'deletion', 'non_fast_forward', 'pull_request', 'merge_queue', 'required_status_checks'} <= kinds,
                   'Effective native main protections are incomplete')
    pull_rules = [r.get('parameters', {}) for r in rules if r.get('type') == 'pull_request']
    common.require(any(type(p.get('required_approving_review_count')) is int
                       and p['required_approving_review_count'] >= 1
                       and p.get('dismiss_stale_reviews_on_push') is True
                       and p.get('require_code_owner_review') is True
                       and p.get('required_review_thread_resolution') is True for p in pull_rules),
                   'Native PR reviews, stale dismissal and CODEOWNERS must be enforced')
    checks = {c.get('context') for r in rules if r.get('type') == 'required_status_checks'
              for c in r.get('parameters', {}).get('required_status_checks', [])
              if c.get('integration_id') == 15368}
    common.require(CHECKS <= checks, 'Required native Actions checks must retain their integration identity')
    scanners = [tool for rule in rules if rule.get('type') == 'code_scanning'
                for tool in rule.get('parameters', {}).get('code_scanning_tools', [])]
    common.require(any(tool.get('tool') == 'CodeQL'
                       and tool.get('alerts_threshold') in ('errors', 'errors_and_warnings', 'all')
                       and tool.get('security_alerts_threshold') in ('high_or_higher', 'medium_or_higher', 'all')
                       for tool in scanners), 'Native CodeQL finding protection must block errors and high-severity alerts')
    queues = [r.get('parameters', {}) for r in rules if r.get('type') == 'merge_queue']
    common.require(any(p.get('max_entries_to_merge') == 1 for p in queues), 'Native queue must merge one PR at a time')
    common.require(any(type(p.get('check_response_timeout_minutes')) is int
                       and p['check_response_timeout_minutes'] >= cfg['minimumQueueTimeoutMinutes'] for p in queues),
                   'Merge queue response timeout is shorter than the bounded CI lifecycle')


def validate_environment(cfg, environment):
    common.require(isinstance(environment, dict) and environment.get('name') == cfg['environment']
                   and type(environment.get('id')) is int
                   and environment.get('can_admins_bypass') is False,
                   'Publication environment must disallow administrator bypass')
    common.require(environment.get('deployment_branch_policy') == {
        'protected_branches': True, 'custom_branch_policies': False}, 'Publication requires protected branches')
    common.require(not any(r.get('type') == 'required_reviewers'
                           for r in environment.get('protection_rules', [])),
                   'Publication approval is supplied by the release PR, not a second environment review')
    return environment['id']


def validate_ruleset(cfg, ruleset, graphql):
    common.require(isinstance(ruleset, dict) and ruleset.get('enforcement') == 'active',
                   'Native main ruleset must remain active without bypass actors')
    if 'bypass_actors' in ruleset:
        common.require(ruleset['bypass_actors'] == [], 'Native main ruleset must remain active without bypass actors')
        return
    # REST omits bypass_actors for read-only observers. Missing is not empty:
    # require an explicit GraphQL count using the same observer permissions.
    proof = graphql()
    common.require(isinstance(proof, dict) and proof.get('errors') in (None, []),
                   'Ruleset bypass visibility is unavailable')
    data = proof.get('data')
    common.require(isinstance(data, dict) and isinstance(data.get('repository'), dict),
                   'Ruleset bypass visibility is unavailable')
    repository = data['repository']
    ruleset = repository.get('ruleset')
    common.require(repository.get('nameWithOwner') == cfg['repository'] and isinstance(ruleset, dict)
                   and type(ruleset.get('databaseId')) is int and ruleset['databaseId'] == cfg['rulesetId']
                   and ruleset.get('enforcement') == 'ACTIVE', 'Native ruleset GraphQL identity is invalid')
    actors = ruleset.get('bypassActors')
    common.require(isinstance(actors, dict) and type(actors.get('totalCount')) is int,
                   'Ruleset bypass visibility is unavailable')
    common.require(actors['totalCount'] == 0, 'Native main ruleset must remain active without bypass actors')


def protections(cfg, api=None, *, graphql=None):
    api = api or protection_api
    prefix = 'repos/' + cfg['repository']
    validate_rules(cfg, api(prefix + '/rules/branches/main'))
    ruleset = api(prefix + '/rulesets/' + str(cfg['rulesetId']))
    validate_ruleset(cfg, ruleset, graphql or protection_graphql)
    return validate_environment(cfg, api(prefix + '/environments/' + cfg['environment']))


def protection_graphql(*, token=None):
    """One pinned read query; POST does not require any write permission."""
    if token is None:
        token = os.environ.get('NATIVE_SECRET_OBSERVER_TOKEN')
    common.require(isinstance(token, str) and token.strip(), 'Read-only native protection observer required')
    response = subprocess.run(['gh', 'api', '--method', 'POST', 'graphql', '--input', '-'],
                              input=json.dumps({'query': RULESET_BYPASS_QUERY}),
                              check=True, capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, GH_TOKEN=token))
    return json.loads(response.stdout)


def protection_api(endpoint):
    common.require(endpoint in ('repos/' + REPOSITORY + '/rules/branches/main',
                                'repos/' + REPOSITORY + '/rulesets/21015412',
                                'repos/' + REPOSITORY + '/environments/publication'),
                   'Unexpected native protection endpoint')
    token = os.environ.get('NATIVE_SECRET_OBSERVER_TOKEN')
    common.require(isinstance(token, str) and token.strip(), 'Read-only native protection observer required')
    value = subprocess.run(['gh', 'api', '--method', 'GET', endpoint], check=True, capture_output=True,
                           text=True, timeout=30, env=dict(os.environ, GH_TOKEN=token))
    return json.loads(value.stdout)


def qualified(cfg, directory, api=None):
    """Authenticate full coverage, current health and exact output identities once."""
    api = api or github.github_api
    native = common.scans(Path(directory) / 'scans.json', cfg, api)
    product = common.product(Path(directory) / 'product.json', cfg, native, api)
    latest = api(f'repos/{cfg["repository"]}/actions/runs/{native["producer"]["runId"]}')
    common.require(latest.get('id') == native['producer']['runId']
                   and latest.get('run_attempt') == native['producer']['runAttempt']
                   and latest.get('status') == 'completed' and latest.get('conclusion') == 'success',
                   'Qualification attempt changed or is no longer successful')
    common.require(set(native['profiles']) == set(product['products']) == set(cfg['profiles']),
                   'Native publication requires every configured profile')
    common.require(product.get('repositorySecretPolicy') == native.get('repositorySecretPolicy')
                   == cfg['repositorySecretPolicy'], 'New policy-bound qualification required')
    current = common.main_revision(cfg, api)
    for revision in {native['revision'], native['producer'].get('revision', native['revision'])}:
        common.require(api(f'repos/{cfg["repository"]}/compare/{revision}...{current}').get('status')
                       in ('ahead', 'identical'), 'Qualification is not on protected main ancestry')
    # This validates normalized findings and context even when there is no ledger.
    findings = {name: normalize_findings(scan, name) for name, scan in native['profiles'].items()}
    return native, product, findings


def plan(cfg, directory, purpose, run_id, attempt, api=None):
    common.require(cfg['enabled'] and purpose in ('rolling', 'release'), 'Invalid publication request')
    native, product, findings = qualified(cfg, directory, api)
    if attempt is None:
        attempt = native['producer']['runAttempt']
    common.require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
                   and native['producer']['runId'] == run_id and native['producer']['runAttempt'] == attempt,
                   'Qualification differs from the selected run and attempt')
    return {'schema': 1, 'approvalMode': cfg['approvalMode'], 'repository': cfg['repository'],
            'sourceRevision': product['revision'],
            'qualificationRun': run_id, 'qualificationAttempt': attempt, 'purpose': purpose,
            'environment': cfg['environment'], 'policyHash': canonical_hash(cfg),
            'product': product, 'productHash': canonical_hash(product), 'scansHash': canonical_hash(native),
            'findingsHash': canonical_hash(findings),
            'findingCounts': {name: len(values) for name, values in findings.items()},
            'authorityClaim': False}


def validate_plan(expected, actual):
    common.require(isinstance(expected, dict) and expected == actual,
                   'Qualified bytes or publication request differ from the reviewed plan; request a new approval')


def validate_request(cfg, request):
    fields = {'schema', 'approvalMode', 'repository', 'sourceRevision', 'qualificationRun',
              'qualificationAttempt', 'purpose', 'environment', 'policyHash', 'productHash',
              'scansHash', 'findingsHash', 'findingCounts', 'authorityClaim', 'product'}
    common.require(isinstance(request, dict) and set(request) == fields
                   and type(request.get('schema')) is int and request['schema'] == 1
                   and request.get('approvalMode') == cfg['approvalMode']
                   and request.get('repository') == cfg['repository']
                   and request.get('environment') == cfg['environment']
                   and request.get('purpose') in ('rolling', 'release')
                   and request.get('authorityClaim') is False, 'Invalid native release request')
    common.require(isinstance(request.get('sourceRevision'), str)
                   and common.SHA.fullmatch(request['sourceRevision'])
                   and all(type(request.get(key)) is int and request[key] > 0
                           for key in ('qualificationRun', 'qualificationAttempt')), 'Invalid native release producer')
    common.require(all(isinstance(request.get(key), str) and common.HASH.fullmatch(request[key])
                       for key in ('policyHash', 'productHash', 'scansHash', 'findingsHash'))
                   and request['policyHash'] == canonical_hash(cfg), 'Release request uses a different policy')
    product = request.get('product')
    common.require(isinstance(product, dict) and product.get('repository') == cfg['repository']
                   and product.get('revision') == request['sourceRevision']
                   and isinstance(product.get('products'), dict) and set(product['products']) == set(cfg['profiles'])
                   and canonical_hash(product) == request['productHash'], 'Release request product identity differs')
    counts = request.get('findingCounts')
    common.require(isinstance(counts, dict) and set(counts) == set(cfg['profiles'])
                   and all(type(count) is int and 0 <= count <= 1000000 for count in counts.values()),
                   'Release request lacks complete finding counts')
    return request


def read_request(cfg, path=None):
    path = Path(path or cfg['releaseRequestPath'])
    common.require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 65536,
                   'Release request must be one bounded regular file')
    return validate_request(cfg, packets.decode_json(path.read_bytes()))


def current_request(cfg, request, api=None):
    api = api or github.github_api
    revision = common.main_revision(cfg, api)
    value = github.document_at(api, cfg['repository'], cfg['releaseRequestPath'], revision)
    common.require(validate_request(cfg, value) == request,
                   'Protected main has a different approved release request')
    return revision


def publication_context(cfg, api=None, environ=None):
    """Require the real publisher on protected main; native PR rules supply approval."""
    api, env = api or github.github_api, os.environ if environ is None else environ
    common.require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_JOB') == 'publish'
                   and env.get('GITHUB_REPOSITORY') == cfg['repository'] and env.get('GITHUB_REF') == 'refs/heads/main'
                   and env.get('GITHUB_WORKFLOW_REF') == cfg['repository'] + '/' + cfg['publisherWorkflow'] + '@refs/heads/main',
                   'Publication must execute in the native protected environment job')
    run_id, attempt = env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')
    common.require(re.fullmatch(r'[1-9][0-9]*', run_id) and re.fullmatch(r'[1-9][0-9]*', attempt),
                   'Native publication run and attempt required')
    prefix = f'repos/{cfg["repository"]}/actions/runs/{run_id}'
    current = api(prefix)
    common.require(current.get('id') == int(run_id) and current.get('run_attempt') == int(attempt)
                   and current.get('head_sha') == env.get('GITHUB_SHA')
                   and current.get('head_branch') == 'main' and current.get('status') == 'in_progress'
                   and current.get('event') in ('workflow_dispatch', 'push')
                   and current.get('path') == cfg['publisherWorkflow']
                   and current.get('repository', {}).get('full_name') == cfg['repository'],
                   'Native publication run changed or has an untrusted workflow identity')
    jobs = api(prefix + f'/attempts/{attempt}/jobs?per_page=100')
    common.require(type(jobs.get('total_count')) is int and 0 < jobs['total_count'] < 100
                   and len(jobs.get('jobs', [])) == jobs['total_count'], 'Incomplete native publication jobs')
    publishing = [j for j in jobs['jobs'] if j.get('name') == 'Publish reviewed immutable product']
    common.require(len(publishing) == 1 and publishing[0].get('status') == 'in_progress'
                   and publishing[0].get('head_sha') == env.get('GITHUB_SHA'),
                   'Protected publishing job has not started')
    return {'runId': int(run_id), 'runAttempt': int(attempt)}
