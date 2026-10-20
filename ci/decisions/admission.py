#!/usr/bin/env python3
"""Admit healthy authenticated scans against live merged human authority."""
import sys
from pathlib import Path
from common import parser, config, gate, emit, run


def main():
    cli = parser(__doc__)
    cli.add_argument('--scans', type=Path, required=True)
    args = cli.parse_args()
    cfg = config(args.config, live=True, enabled=True)
    emit(gate(cfg, args.scans), args.output)


if __name__ == '__main__':
    sys.exit(run(main))
