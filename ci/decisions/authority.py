#!/usr/bin/env python3
"""Verify independently authenticated decision approval; open checks cannot publish."""
import sys
from pathlib import Path
from common import parser, config, authorize, emit, run, require
from security_decisions import load_json, canonical_hash


def main():
    cli = parser(__doc__)
    cli.add_argument('--proposal', type=Path, required=True)
    cli.add_argument('--pr', type=int)
    cli.add_argument('--allow-open', action='store_true')
    cli.add_argument('--queued-proposal', type=Path)
    args = cli.parse_args()
    cfg = config(args.config, live=True)
    proposal = load_json(args.proposal)
    if args.queued_proposal:
        require(args.allow_open, 'Queue comparisons are premerge only')
        require(canonical_hash(load_json(args.queued_proposal)) == canonical_hash(proposal),
                'Queued proposal differs from reviewed proposal')
    emit(authorize(cfg, proposal, pr=args.pr, allow_open=args.allow_open), args.output)


if __name__ == '__main__':
    sys.exit(run(main))
