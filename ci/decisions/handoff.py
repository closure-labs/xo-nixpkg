#!/usr/bin/env python3
"""Verify an exact pinned upstream product; a handoff notification grants no authority."""
import sys
from pathlib import Path
from common import parser, config, require, attest, gate, emit, run
from security_decisions import load_json, canonical_hash


def main():
    cli = parser(__doc__)
    cli.add_argument('--handoff', type=Path, required=True)
    cli.add_argument('--directory', type=Path)
    cli.add_argument('--expected-revision', required=True)
    cli.add_argument('--expected-channel', required=True)
    cli.add_argument('--expected-store-path', required=True)
    cli.add_argument('--expected-nar-hash', required=True)
    args = cli.parse_args()
    cfg = config(args.config, live=True, enabled=True)
    require(cfg['repository'] == 'closure-labs/xo-nixpkg', 'Handoff requires the checked upstream XO policy')
    value = load_json(args.handoff)
    require(set(value) == {'schema', 'repository', 'revision', 'channel', 'product', 'scans'}
            and value['schema'] == 1 and value['repository'] == cfg['repository']
            and value['revision'] == args.expected_revision and value['channel'] == args.expected_channel,
            'Handoff differs from exact locked upstream revision/channel')
    directory = args.directory or args.handoff.parent
    require(load_json(directory / 'scans.json') == value['scans']
            and load_json(directory / 'product.json') == value['product'], 'Handoff differs from retained attested documents')
    require(value['product']['revision'] == args.expected_revision
            and args.expected_channel in value['product']['products'], 'Handoff product channel absent')
    require(value['product']['products'][args.expected_channel] == {
        'storePath': args.expected_store_path, 'narHash': args.expected_nar_hash},
        'Handoff output differs from exact independently resolved locked package')
    from common import attest_product
    attest_product(args.handoff, cfg, value['scans']['producer'].get('revision', value['revision']))
    result = gate(cfg, directory / 'scans.json', directory / 'product.json', 'rolling')
    result['handoffHash'] = canonical_hash(value)
    result['product'] = value['product']['products'][args.expected_channel]
    emit(result, args.output)


if __name__ == '__main__':
    sys.exit(run(main))
