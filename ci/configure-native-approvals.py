#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare native review protections, then activate only after reviewed source lands."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).with_name('decisions')))
sys.path.insert(0, str(Path(__file__).parent))
import native_approvals as native
import common
from importlib.util import spec_from_file_location, module_from_spec
spec = spec_from_file_location('release_proposal_api', Path(__file__).with_name('propose-release.py'))
proposal = module_from_spec(spec)
spec.loader.exec_module(proposal)
api = proposal.api


def ruleset_body(value):
    return {key: value[key] for key in ('name', 'target', 'enforcement', 'conditions', 'rules', 'bypass_actors')}


def prepare_rules(value):
    result = ruleset_body(deepcopy(value))
    pulls = [r for r in result['rules'] if r['type'] == 'pull_request']
    common.require(len(pulls) == 1 and result['bypass_actors'] == [], 'Expected one main PR rule without bypasses')
    pulls[0]['parameters'].update(required_approving_review_count=1, dismiss_stale_reviews_on_push=True,
                                 require_code_owner_review=True, require_last_push_approval=True,
                                 required_review_thread_resolution=True)
    return result


def activate_rules(value):
    result = ruleset_body(deepcopy(value))
    for rule in result['rules']:
        if rule['type'] == 'required_status_checks':
            rule['parameters']['required_status_checks'] = [c for c in rule['parameters']['required_status_checks']
                if not (c.get('context') == 'Maintainer decision authority' and c.get('integration_id') == 5384448)]
    return result


def enabled_variable(prefix, enabled):
    endpoint = prefix + '/actions/variables/NATIVE_RELEASE_APPROVALS_ENABLED'
    existing = api(endpoint, missing=True)
    value = {'name': 'NATIVE_RELEASE_APPROVALS_ENABLED', 'value': 'true' if enabled else 'false'}
    api(endpoint if existing else prefix + '/actions/variables', value,
        method='PATCH' if existing else 'POST')
    common.require(api(endpoint).get('value') == value['value'], 'Native activation flag readback differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'activate', 'check'))
    parser.add_argument('--backup-dir', type=Path, default=Path('/tmp/xo-native-approval-migration'))
    args = parser.parse_args()
    cfg = native.policy(live=args.phase != 'prepare', api=api)
    prefix = 'repos/' + cfg['repository']
    rules_path = prefix + '/rulesets/' + str(cfg['rulesetId'])
    environment_path = prefix + '/environments/' + cfg['environment']
    ruleset, environment = api(rules_path), api(environment_path)
    if args.phase == 'check':
        native.protections(cfg, api)
        print('Native PR and publication protections verified.')
        return
    args.backup_dir.mkdir(parents=True, exist_ok=True)
    backup = args.backup_dir / (args.phase + '.json')
    common.require(not backup.exists(), 'Migration backup already exists; choose a new backup directory')
    backup.write_text(json.dumps({'ruleset': ruleset, 'environment': environment}, indent=2) + '\n')
    if args.phase == 'prepare':
        # Preserve the legacy App gate until the new workflow has passed review.
        api(rules_path, prepare_rules(ruleset), method='PUT')
        common.require(not any(r.get('type') == 'required_reviewers' for r in environment.get('protection_rules', [])),
                       'An existing environment reviewer gate needs explicit migration')
        api(environment_path, {'deployment_branch_policy': environment['deployment_branch_policy'],
                               'can_admins_bypass': False}, method='PUT')
        enabled_variable(prefix, False)
    else:
        revision = common.main_revision(cfg, api)
        for path in ('.github/workflows/decision-authority.yml', '.github/workflows/security-reconcile.yml'):
            common.require(api(prefix + '/contents/' + path + '?ref=' + revision, missing=True) is None,
                           'Retired decision workflows are still present on protected main')
        for path in ('.github/workflows/publish.yml', '.github/workflows/release-proposal.yml'):
            document = api(prefix + '/contents/' + path + '?ref=' + revision)
            common.require(native.github.decode_blob(document, document.get('sha'), document.get('size'))
                           == Path(path).read_bytes(), 'Reviewed native workflow differs from local migration source')
        native.protections(cfg, api)
        api(rules_path, activate_rules(ruleset), method='PUT')
        enabled_variable(prefix, True)
    native.protections(cfg, api)
    print('Native approval migration ' + args.phase + ' completed; no review or deployment was approved.')


if __name__ == '__main__':
    sys.exit(common.run(main))
