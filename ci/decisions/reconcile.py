#!/usr/bin/env python3
"""Persist authenticated evidence and propose bounded App-authored human decisions."""
import sys
from pathlib import Path
from common import parser, config, require, emit, run
from reconciliation import reconcile


def main():
    cli = parser(__doc__)
    cli.add_argument('--scans', type=Path)
    cli.add_argument('--product', type=Path)
    cli.add_argument('--directory', type=Path)
    cli.add_argument('--kind', choices=('security-findings', 'security-revocation', 'release-product'), required=True)
    cli.add_argument('--rationale', default='Review the complete authenticated native evidence and exact proposed scope.')
    cli.add_argument('--disposition', choices=('accepted', 'rejected'), default='accepted')
    cli.add_argument('--decision-hash')
    args = cli.parse_args()
    cfg = config(args.config, live=True)
    require(args.rationale.strip(), 'Decision rationale required')
    directory = args.directory or (args.scans.parent if args.scans else Path('.'))
    emit(reconcile(cfg, args.scans, args.product, args.kind, directory, args.rationale,
                   args.disposition, args.decision_hash), args.output)


if __name__ == '__main__':
    sys.exit(run(main))
