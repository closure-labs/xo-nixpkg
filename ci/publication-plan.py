#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plan and validate exact qualified products; GitHub owns human approvals."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import common
import native_approvals as native
import decision_packets as packets


def controller():
    value = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    common.require(common.SHA.fullmatch(value) is not None, 'Immutable controller revision required')
    return value


def candidate(cfg, directory, purpose):
    attempt = os.environ.get('QUALIFICATION_ATTEMPT')
    return native.plan(cfg, directory, purpose,
                       int(os.environ['QUALIFICATION_RUN']), int(attempt) if attempt else None)


def review(cfg, directory, plan, output):
    scans = common.load_json(directory / 'scans.json')
    common.require(common.canonical_hash(scans) == plan['scansHash'], 'Review observations changed')
    findings = {name: native.normalize_findings(value, name) for name, value in scans['profiles'].items()}
    common.require(common.canonical_hash(findings) == plan['findingsHash'], 'Review findings changed')
    output.write_text(json.dumps({'plan': plan, 'findings': findings}, sort_keys=True, indent=2, allow_nan=False) + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('## Publication awaiting native GitHub approval\n\n'
                          'Review the exact product, fresh findings and requested destination below. '
                          'Merging the release PR approves these exact bytes and purpose.\n\n'
                          '| Binding | Value |\n| --- | --- |\n')
            for key in ('purpose', 'sourceRevision', 'qualificationRun',
                        'qualificationAttempt', 'productHash', 'scansHash', 'policyHash'):
                summary.write('| ' + key + ' | `' + str(plan[key]) + '` |\n')
            summary.write('\n| Profile | Findings requiring review |\n| --- | --- |\n')
            for name, count in plan['findingCounts'].items():
                summary.write('| ' + name + ' | ' + str(count) + ' |\n')
            summary.write('\nDownload `publication-review` in this run for the complete findings. '
                          '[Qualified producer](https://github.com/' + cfg['repository'] + '/actions/runs/'
                          + str(plan['qualificationRun']) + ').\n')


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('operation', choices=('plan', 'request', 'verify', 'gate'))
    cli.add_argument('--config', type=Path, default=Path(native.POLICY))
    cli.add_argument('--output', type=Path)
    args = cli.parse_args()
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    cfg = native.policy(args.config, live=True)
    native.protections(cfg)
    revision = controller()
    if args.operation == 'request':
        request = native.read_request(cfg)
        native.current_request(cfg, request)
        common.emit(request, args.output)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('request=' + json.dumps(request, separators=(',', ':'), allow_nan=False) + '\n')
                for key in ('qualificationRun', 'qualificationAttempt', 'purpose'):
                    output.write(key + '=' + str(request[key]) + '\n')
        return
    request = native.read_request(cfg) if args.operation in ('verify', 'gate') else None
    if request is not None:
        native.current_request(cfg, request)
    if args.operation == 'gate':
        context = native.publication_context(cfg)
        common.require(revision == os.environ.get('GITHUB_WORKFLOW_SHA'), 'Publisher controller differs from its workflow source')
    plan = candidate(cfg, directory, os.environ['XO_NIXPKG_PUBLICATION_PURPOSE'])
    if request is not None:
        native.validate_plan(request, plan)
        if os.environ.get('XO_NIXPKG_PUBLICATION_PLAN'):
            native.validate_plan(request, packets.decode_json(os.environ['XO_NIXPKG_PUBLICATION_PLAN']))
        # Re-read mutable protections and policy at each distribution boundary.
        common.require(native.policy(args.config, live=True) == cfg, 'Publication policy changed')
        native.current_request(cfg, request)
        native.protections(cfg)
        common.emit({'schema': 1, 'status': 'approved-native-pr', 'productHash': plan['productHash'],
                     **(context if args.operation == 'gate' else {})}, args.output)
    else:
        common.emit(plan, args.output)
        review(cfg, directory, plan, directory.parent / 'publication-review.json')


if __name__ == '__main__':
    sys.exit(common.run(main))
