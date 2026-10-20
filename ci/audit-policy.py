#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Audit effective protection using a separate read-only administration App."""
from pathlib import Path
import json
import os
import subprocess

import decision_authority as authority
from common import config, require, required_check


def repository_api(endpoint):
    """Read source metadata without expanding the administration audit App."""
    prefix = 'repos/closure-labs/xo-nixpkg/'
    require(endpoint == prefix + 'git/ref/heads/main'
            or endpoint.startswith(prefix + 'contents/ci/decision-policy.json?ref='),
            'Unexpected repository metadata endpoint')
    token = os.environ.get('REPOSITORY_READ_TOKEN')
    require(isinstance(token, str) and token.strip(), 'Scoped repository metadata reader required')
    response = subprocess.run(['gh', 'api', '--method', 'GET', endpoint],
                              env=dict(os.environ, GH_TOKEN=token), check=True,
                              text=True, capture_output=True, timeout=60)
    return json.loads(response.stdout)


def main():
    cfg = config(Path('ci/decision-policy.json'), live=True, api=repository_api)
    required_check(cfg)
    rules = authority.github_api(f'repos/{cfg["repository"]}/rules/branches/main')
    types = {rule['type'] for rule in rules}
    require({'deletion', 'non_fast_forward', 'pull_request', 'merge_queue', 'required_status_checks'} <= types,
            'effective main protections are incomplete')
    require(any(rule['type'] == 'merge_queue' and rule['parameters']['max_entries_to_merge'] == 1 for rule in rules),
            'decision authority requires a single-PR merge queue')
    require(any(rule['type'] == 'pull_request' and rule['parameters']['required_review_thread_resolution'] is True for rule in rules),
            'main review threads must be resolved')
    print(json.dumps({'schema': 1, 'status': 'verified', 'publicationEnabled': cfg['enabled']}))


if __name__ == '__main__':
    main()
