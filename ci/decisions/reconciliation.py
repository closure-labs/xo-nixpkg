"""Authenticated packet/proposal operations shared by dedicated CLI leaves."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import decision_authority as authority
import decision_packets as packets
from common import (require, command, scans, product, ledger, active_security, active_release,
                    authorize, historical_provenance, config, attest, required_check,
                    security_contexts, accepted_contexts, compare_security_contexts)
from security_decisions import load_json, canonical_hash, normalize_findings, compare_findings

CHECK_CONFIG = None


def validate_proposal_packet(proposal, cfg=None):
    cfg = cfg or CHECK_CONFIG
    require(cfg is not None, 'Checked policy required for packet validation')
    payload = proposal['payload']
    require(payload.get('disposition') in ('accepted', 'rejected', 'revoked'), 'Invalid disposition')
    packet = payload.get('packet')
    require(isinstance(packet, dict) and set(packet) == {'reference', 'sha256', 'producer'}, 'Invalid packet reference')
    if proposal['kind'] == 'security-revocation':
        _, records = ledger(cfg)
        digest, parent = active_security(cfg, records, authenticate=False)
        require(parent is not None and parent['payload']['disposition'] == 'accepted'
                and payload.get('supersedes') == [digest]
                and payload.get('profiles') == parent['payload']['profiles']
                and payload.get('securityContexts') == parent['payload'].get('securityContexts')
                and packet == parent['payload']['packet'] and payload['disposition'] == 'revoked',
                'Revocation must copy current accepted decision exactly')
        return
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / 'packet'
        manifest = packets.fetch(packet['reference'], root, packet['sha256'])
        require(manifest['producer'] == packet['producer'], 'Packet producer differs from proposal')
        # Immutable review evidence remains authentic after scan freshness
        # expires. Publication separately requires a fresh scan and admission.
        native = scans(root / 'scans.json', cfg, allow_expired=True)
        expected_producer = dict(native['producer'], repository=cfg['repository'],
                                 revision=native['producer'].get('revision', native['revision']),
                                 sourceRevision=native['revision'])
        require(packet['producer'] == expected_producer, 'Packet producer differs from authenticated native scan')
        if proposal['kind'] == 'security-findings':
            expected = {profile: normalize_findings(scan, profile) for profile, scan in native['profiles'].items()}
            require(set(expected) == set(cfg['profiles']) and payload.get('profiles') == expected,
                    'Proposed findings differ from complete authenticated native observations')
            if 'securityContexts' in payload:
                require(accepted_contexts(payload) == security_contexts(native),
                        'Proposed policy differs from authenticated native context')
            _, records = ledger(cfg)
            digest, _ = active_security(cfg, records, authenticate=False)
            require(payload.get('supersedes') == ([digest] if digest else []), 'Security proposal has stale supersession parent')
        elif proposal['kind'] == 'release-product':
            identity = product(root / 'product.json', cfg, native)
            require(canonical_hash(payload.get('product')) == canonical_hash(identity) and payload['disposition'] == 'accepted',
                    'Release approval differs from authenticated exact product')
            for name, digest in identity['assets'].items():
                require((root / name).is_file() and packets.file_hash(root / name) == digest,
                        'Approved release bytes missing or mismatched in immutable packet')
            _, records = ledger(cfg)
            digest, parent = active_release(cfg, records, identity, authenticate=False)
            require(payload.get('supersedes', []) == ([digest] if digest else []),
                    'Release proposal has stale supersession parent')
            if parent is not None:
                historical_provenance(cfg, parent)
        else:
            raise ValueError('Unsupported proposal kind')


def api_write(endpoint, body, method='POST'):
    return json.loads(command(['gh', 'api', '--method', method, endpoint, '--input', '-'], input=json.dumps(body)))


def queue_state(cfg, number, head, node_id):
    """Read exact-head native state; this observation grants no authorization."""
    result = json.loads(command(['gh', 'api', 'graphql', '-f',
        'query=query($id:ID!){node(id:$id){... on PullRequest{id headRefOid state merged mergeStateStatus autoMergeRequest{enabledAt} mergeQueueEntry{id}}}}',
        '-f', 'id=' + node_id]))
    require(not result.get('errors'), 'Queue state API unavailable')
    value = result.get('data', {}).get('node')
    require(isinstance(value, dict) and value.get('id') == node_id
            and value.get('state') in ('OPEN', 'CLOSED', 'MERGED'), 'Invalid queue state identity')
    if value.get('headRefOid') != head:
        return 'changed-head', value
    if value.get('merged') or value['state'] == 'MERGED':
        return 'merged', value
    if value['state'] == 'CLOSED':
        return 'closed', value
    if value.get('mergeQueueEntry'):
        return 'queued', value
    return 'waiting', value


def queue_proposal(cfg, number):
    """Reconcile native queue state and read back ambiguous mutations once."""
    required_check(cfg)
    pull = authority.github_api(f'repos/{cfg["repository"]}/pulls/{number}')
    if pull.get('merged'):
        return 'merged'
    if pull.get('state') == 'closed':
        return 'closed'
    require(pull.get('state') == 'open', 'Invalid proposal state')
    head, node_id = pull['head']['sha'], pull['node_id']
    state, value = queue_state(cfg, number, head, node_id)
    if state != 'waiting':
        return state
    try:
        authority.approval(authority.github_api, cfg['repository'], number, head)
    except authority.HumanDecisionRequired:
        return 'awaiting-review'
    if not value.get('autoMergeRequest'):
        try:
            command(['gh', 'pr', 'merge', str(number), '--auto', '--merge',
                     '--match-head-commit', head, '--repo', cfg['repository']])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            state, value = queue_state(cfg, number, head, node_id)
            if state != 'waiting':
                return state
            require(value.get('autoMergeRequest'), 'Auto-merge acknowledgement unavailable')
    state, value = queue_state(cfg, number, head, node_id)
    if state != 'waiting':
        return state
    if value.get('mergeStateStatus') in ('BLOCKED', 'BEHIND', 'DRAFT', 'UNKNOWN', 'UNSTABLE'):
        return 'awaiting-checks'
    if value.get('mergeStateStatus') == 'DIRTY':
        return 'conflict'
    require(value.get('mergeStateStatus') in ('CLEAN', 'HAS_HOOKS'), 'Unknown merge readiness')
    # App-authored events sometimes need explicit enqueue. Recheck membership
    # and exact-head approval immediately before this write, even after planning.
    authority.approval(authority.github_api, cfg['repository'], number, head)
    try:
        result = json.loads(command(['gh', 'api', 'graphql', '-f',
            'query=mutation($id:ID!,$head:GitObjectID!){enqueuePullRequest(input:{pullRequestId:$id,expectedHeadOid:$head}){mergeQueueEntry{id}}}',
            '-f', 'id=' + node_id, '-f', 'head=' + head]))
        acknowledged = not result.get('errors') and result.get('data', {}).get('enqueuePullRequest', {}).get('mergeQueueEntry')
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        acknowledged = False
    state, value = queue_state(cfg, number, head, node_id)
    if state != 'waiting':
        return state
    if value.get('mergeStateStatus') in ('BLOCKED', 'BEHIND', 'UNKNOWN', 'UNSTABLE'):
        return 'awaiting-checks'
    require(acknowledged, 'Enqueue acknowledgement unavailable; native state remains waiting')
    return 'enqueue-pending'

def propose(cfg, proposal):
    """Create one immutable bot branch/PR without checking out or executing candidate code."""
    repository = cfg['repository']
    digest = canonical_hash(proposal)
    path = authority.proposal_path(proposal)
    branch = 'automation/decision-' + digest
    pulls = authority.collection(authority.github_api, f'repos/{repository}/pulls?state=open&base=main&head={repository.split("/")[0]}:{branch}')
    require(len(pulls) <= 1, 'Ambiguous existing proposal PR')
    if pulls:
        pull = pulls[0]
        require(pull.get('user', {}).get('login') == cfg['botLogin']
                and pull.get('head', {}).get('repo', {}).get('full_name') == repository
                and authority.document_at(authority.github_api, repository, path, pull['head']['sha']) == proposal,
                'Existing proposal branch differs; refusing overwrite')
        files = authority.collection(authority.github_api, f'repos/{repository}/pulls/{pull["number"]}/files')
        require(len(files) == 1 and files[0].get('filename') == path and files[0].get('status') == 'added',
                'Existing proposal PR changes unexpected paths')
        return {'schema': 1, 'status': queue_proposal(cfg, pull['number']), 'proposalHash': digest, 'pullRequest': pull['number']}
    base = authority.github_api(f'repos/{repository}/git/ref/heads/main')['object']['sha']
    commit = authority.github_api(f'repos/{repository}/git/commits/{base}')
    tree = api_write(f'repos/{repository}/git/trees', {'base_tree': commit['tree']['sha'],
                    'tree': [{'path': path, 'mode': '100644', 'type': 'blob',
                              'content': json.dumps(proposal, sort_keys=True, indent=2) + '\n'}]})
    commit = api_write(f'repos/{repository}/git/commits', {'message': 'chore: propose ' + proposal['kind'] + ' ' + digest[:12],
                       'tree': tree['sha'], 'parents': [base]})
    # Existing divergent refs fail; never force-update an unattended branch.
    api_write(f'repos/{repository}/git/refs', {'ref': 'refs/heads/' + branch, 'sha': commit['sha']})
    pull = api_write(f'repos/{repository}/pulls', {'head': branch, 'base': 'main',
                     'title': 'Review ' + proposal['kind'] + ' ' + digest[:12],
                     'body': 'Approve this exact content-addressed proposal head. Publication rechecks current Super Admin membership and maintain/admin access.'})
    require(pull.get('user', {}).get('login') == cfg['botLogin'] and pull.get('user', {}).get('type') == 'Bot',
            'Proposal author must be the configured App bot')
    return {'schema': 1, 'status': queue_proposal(cfg, pull['number']), 'proposalHash': digest, 'pullRequest': pull['number']}


def reconcile(cfg, scan_path, product_path, kind, directory, rationale, disposition='accepted', decision_hash=None):
    _, records = ledger(cfg)
    digest, current = active_security(cfg, records, authenticate=False)
    if kind == 'security-revocation':
        require(current is not None and current['payload']['disposition'] == 'accepted' and digest == decision_hash,
                'Revocation requires exact current accepted decision hash')
        payload = dict(current['payload'], disposition='revoked', rationale=rationale, supersedes=[digest])
        proposal = {'schema': 1, 'kind': kind, 'payload': payload}
        validate_proposal_packet(proposal, cfg)
        return propose(cfg, proposal)
    require(scan_path is not None, 'Authenticated complete producer scans required')
    native = scans(scan_path, cfg)
    identity = product(product_path, cfg, native) if product_path else None
    if kind == 'security-findings':
        require(set(native['profiles']) == set(cfg['profiles']), 'Baseline proposals require every configured profile')
        findings = {p: normalize_findings(s, p) for p, s in native['profiles'].items()}
        if current and current['payload']['disposition'] == 'accepted' and disposition == 'accepted':
            comparisons = [compare_findings(findings[p], current['payload']['profiles'][p]) for p in findings]
            if (all(not c['new'] and not c['worsened'] for c in comparisons)
                    and all(not expanded for expanded, _ in compare_security_contexts(native, current['payload']).values())):
                try:
                    authorize(cfg, current)
                    return {'schema': 1, 'status': 'covered', 'decisionHash': digest}
                except authority.HumanDecisionRequired:
                    pass  # A fresh proposal can recover withdrawn historical authority.
    else:
        require(identity is not None and disposition == 'accepted', 'Release proposal requires exact product')
        release_digest, release = active_release(cfg, records, identity, authenticate=False)
        if release is not None and release['payload']['disposition'] == 'accepted':
            try:
                authorize(cfg, release)
                return {'schema': 1, 'status': 'approved', 'productHash': canonical_hash(identity)}
            except authority.HumanDecisionRequired:
                historical_provenance(cfg, release)
    directory = Path(directory).resolve()
    require(directory.is_dir() and (directory / 'scans.json').read_bytes() == Path(scan_path).read_bytes(),
            'Packet directory must include exact verified scans.json')
    if identity:
        require((directory / 'product.json').read_bytes() == Path(product_path).read_bytes(), 'Packet product mismatch')
        for name, value in identity['assets'].items():
            require((directory / name).is_file() and packets.file_hash(directory / name) == value,
                    'Complete immutable release bytes must be present before requesting approval')
    producer = dict(native['producer'], repository=cfg['repository'],
                    revision=native['producer'].get('revision', native['revision']), sourceRevision=native['revision'])
    packet = packets.push(directory, producer)
    payload = {'disposition': disposition, 'rationale': rationale, 'packet': packet}
    if kind == 'security-findings':
        payload.update(profiles=findings, securityContexts=security_contexts(native), supersedes=[digest] if digest else [])
    else:
        payload['product'] = identity
        payload['supersedes'] = [release_digest] if release_digest else []
    proposal = {'schema': 1, 'kind': kind, 'payload': payload}
    validate_proposal_packet(proposal, cfg)
    return propose(cfg, proposal)
