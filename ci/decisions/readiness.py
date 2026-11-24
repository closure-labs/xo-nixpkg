#!/usr/bin/env python3
"""Live activation preflight; disabled policy is deliberately not publication-ready."""
import sys
from common import parser, config, required_check, ledger, active_security, emit, run, require


def main():
    cli = parser(__doc__)
    cli.add_argument('--graph-only', action='store_true',
                     help='Validate current-main supersession before bulk transport; grants no admission')
    args = cli.parse_args()
    cfg = config(args.config, live=True, enabled=True)
    if not args.graph_only:
        required_check(cfg)
    _, records = ledger(cfg)
    digest, decision = active_security(cfg, records, authenticate=not args.graph_only)
    if args.graph_only:
        emit({'schema': 1, 'status': 'valid-security-graph', 'repository': cfg['repository'],
              'decisionHash': digest, 'authorityClaim': False}, args.output)
        return
    require(decision is not None and decision['payload']['disposition'] == 'accepted', 'Accepted initial baseline required')
    emit({'schema': 1, 'status': 'ready', 'repository': cfg['repository'], 'decisionHash': digest}, args.output)


if __name__ == '__main__':
    sys.exit(run(main))
