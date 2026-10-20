#!/usr/bin/env python3
"""Render a content-addressed proposal; rendering grants no human authority."""
import sys
from pathlib import Path
from common import parser, config, emit, run
from decision_authority import proposal_path
from security_decisions import load_json, canonical_hash


def main():
    cli = parser(__doc__)
    cli.add_argument('--kind', required=True, choices=('security-findings', 'security-revocation', 'release-product'))
    cli.add_argument('--payload', type=Path, required=True)
    args = cli.parse_args()
    config(args.config)
    proposal = {'schema': 1, 'kind': args.kind, 'payload': load_json(args.payload)}
    path = proposal_path(proposal)
    if args.output:
        args.output.write_text(__import__('json').dumps(proposal, sort_keys=True, indent=2) + '\n')
    emit({'schema': 1, 'status': 'rendered', 'path': path, 'proposalHash': canonical_hash(proposal)})


if __name__ == '__main__':
    sys.exit(run(main))
