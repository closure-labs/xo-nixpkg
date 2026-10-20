#!/usr/bin/env python3
"""Recheck immutable candidate and current authority at each distribution boundary."""
import sys
from pathlib import Path
from common import parser, config, gate, emit, run


def main():
    cli = parser(__doc__)
    cli.add_argument('--scans', type=Path, required=True)
    cli.add_argument('--product', type=Path, required=True)
    cli.add_argument('--purpose', choices=('rolling', 'release'), default='rolling')
    args = cli.parse_args()
    cfg = config(args.config, live=True, enabled=True)
    emit(gate(cfg, args.scans, args.product, args.purpose), args.output)


if __name__ == '__main__':
    sys.exit(run(main))
