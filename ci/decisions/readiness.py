#!/usr/bin/env python3
"""Live activation preflight; disabled policy is deliberately not publication-ready."""
import sys
from common import parser, config, required_check, ledger, active_security, emit, run, require


def main():
    args = parser(__doc__).parse_args()
    cfg = config(args.config, live=True, enabled=True)
    required_check(cfg)
    _, records = ledger(cfg)
    digest, decision = active_security(cfg, records)
    require(decision is not None and decision['payload']['disposition'] == 'accepted', 'Accepted initial baseline required')
    emit({'schema': 1, 'status': 'ready', 'repository': cfg['repository'], 'decisionHash': digest}, args.output)


if __name__ == '__main__':
    sys.exit(run(main))
