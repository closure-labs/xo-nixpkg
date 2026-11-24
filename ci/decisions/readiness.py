#!/usr/bin/env python3
"""Live activation preflight; disabled policy is deliberately not publication-ready."""
import sys
import os
from common import (parser, config, required_check, ledger, active_security, security_leaves,
                    accepted_contexts, canonical_hash, emit, run, require)


def graph_report(cfg, revision, records):
    leaves = security_leaves(cfg, records)
    details = []
    for digest, proposal in leaves.items():
        payload = proposal['payload']
        details.append({'decisionHash': digest, 'disposition': payload['disposition'],
                        'findings': {profile: len(values) for profile, values in payload['profiles'].items()},
                        'scopeHash': canonical_hash({'profiles': payload['profiles'],
                                                    'securityContexts': accepted_contexts(payload)})})
    ambiguous = len(details) > 1
    return {'schema': 1, 'status': 'ambiguous-security-graph' if ambiguous else 'valid-security-graph',
            'repository': cfg['repository'], 'mainRevision': revision,
            'graphHash': canonical_hash(records), 'policyHash': canonical_hash(cfg),
            'decisionHash': details[0]['decisionHash'] if len(details) == 1 else None,
            'leafCount': len(details), 'leaves': details,
            'scopesIdentical': len({entry['scopeHash'] for entry in details}) <= 1,
            'requiresHumanReview': ambiguous, 'authorityClaim': False, 'publicationReady': False}


def summary(report):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if not path or not report['requiresHumanReview']:
        return
    with open(path, 'a') as output:
        output.write('## Release blocked: concurrent security decisions\n\n'
                     'The following unsuperseded decisions require explicit maintainer reconciliation. '
                     'This report does not grant admission or choose a decision.\n\n'
                     'Main revision: `' + report['mainRevision'] + '`\n\n')
        for entry in report['leaves']:
            output.write('- `' + entry['decisionHash'] + '` — ' + entry['disposition'] + '\n')
        output.write('\nRecorded finding scopes and contexts are ' +
                     ('identical' if report['scopesIdentical'] else 'different') +
                     '; packet authenticity, current human authority and fresh evidence still require verification.\n')


def main():
    cli = parser(__doc__)
    cli.add_argument('--graph-only', action='store_true',
                     help='Validate current-main supersession before bulk transport; grants no admission')
    args = cli.parse_args()
    cfg = config(args.config, live=True, enabled=True)
    if not args.graph_only:
        required_check(cfg)
    revision, records = ledger(cfg)
    if args.graph_only:
        report = graph_report(cfg, revision, records)
        try:
            emit(report, args.output)
        except OSError:
            print('Could not retain security-graph report; graph verdict is unchanged.', file=sys.stderr)
            emit(report)
        try:
            summary(report)
        except OSError:
            print('Could not retain security-graph summary; graph verdict is unchanged.', file=sys.stderr)
        return 2 if report['requiresHumanReview'] else 0
    digest, decision = active_security(cfg, records)
    require(decision is not None and decision['payload']['disposition'] == 'accepted', 'Accepted initial baseline required')
    emit({'schema': 1, 'status': 'ready', 'repository': cfg['repository'], 'decisionHash': digest}, args.output)


if __name__ == '__main__':
    sys.exit(run(main))
