"""Shared validation and live trust boundaries for small automation commands."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import decision_authority as authority
import decision_packets as packets
from security_decisions import canonical_hash, load_json, evaluate, validate_normalized

HASH = re.compile(r'[0-9a-f]{64}')
SHA = authority.SHA


def require(value, message):
    if not value:
        raise ValueError(message)


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=180,
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


def ledger(cfg, api=None):
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
        proposal = authority.document_at(api, cfg['repository'], path, revision)
        require(authority.proposal_path(proposal) == path, 'Decision content hash/path mismatch')
        records[canonical_hash(proposal)] = proposal
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
    candidates = {h: p for h, p in records.items() if p['kind'] == 'release-product'
                  and p['payload'].get('product') == identity}
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


def attest(path, cfg, revision, workflow):
    return json.loads(command(['gh', 'attestation', 'verify', str(path), '--repo', cfg['repository'],
                              '--signer-workflow', cfg['repository'] + '/' + workflow,
                              '--source-digest', revision, '--source-ref', 'refs/heads/main',
                              '--deny-self-hosted-runners', '--format', 'json']))


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
    producer = value.get('producer', {})
    producer_revision, signer = verify_producer(cfg, producer, value['revision'], api)
    attest(path, cfg, producer_revision, signer)
    for native in value['profiles'].values():
        require(native.get('status') == 'complete' and native.get('scannerHealth') == 'healthy', 'Native scanner unhealthy')
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
    require(set(value).issubset({'schema', 'repository', 'revision', 'products', 'assets', 'roots'})
            and value.get('schema') == 1 and value.get('repository') == cfg['repository']
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
    api = api or authority.github_api
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
        digest = canonical_hash(identity)
        result['productHash'] = digest
        if purpose == 'release':
            release_digest, release = active_release(cfg, records, identity, api)
            require(release is not None and release['payload'].get('disposition') == 'accepted',
                    'Exact immutable official product approval required')
    # Final complete-ledger refresh catches concurrent additions/revocations.
    _, current = ledger(cfg, api)
    require(current == records, 'Current-main ledger changed during admission')
    active_security(cfg, current, api)
    if product_path and purpose == 'release':
        authorize(cfg, release, api)
    policy = authority.document_at(api, cfg['repository'], cfg['policyPath'], main_revision(cfg, api))
    require(policy == cfg and policy['enabled'], 'Publication policy changed during admission')
    required_check(cfg, api)
    return result
