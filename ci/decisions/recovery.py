#!/usr/bin/env python3
"""Validate recovery identity and replay the ordinary live release gate."""
import sys
import re
from pathlib import Path
from common import parser, config, gate, require, emit, run
from security_decisions import load_json, canonical_hash


def validate_journal(journal, product):
    require(isinstance(journal, dict) and set(journal) == {'schema', 'productHash', 'steps'}
            and journal['schema'] == 1 and journal['productHash'] == canonical_hash(product),
            'Recovery journal differs from exact immutable product')
    require(isinstance(journal['steps'], dict), 'Invalid recovery steps')
    require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', name)
                and state in ('pending', 'complete') for name, state in journal['steps'].items()),
            'Invalid recovery journal step')
    return journal


def main():
    cli = parser(__doc__)
    cli.add_argument('--journal', required=True, type=Path)
    cli.add_argument('--product', required=True, type=Path)
    cli.add_argument('--scans', required=True, type=Path)
    args = cli.parse_args()
    journal = validate_journal(load_json(args.journal), load_json(args.product))
    cfg = config(args.config, live=True, enabled=True)
    result = gate(cfg, args.scans, args.product, 'release')
    result['pendingSteps'] = sorted(name for name, state in journal['steps'].items() if state == 'pending')
    result['note'] = 'Publisher must independently compare remote immutable identities before every replay.'
    emit(result, args.output)


if __name__ == '__main__':
    sys.exit(run(main))
