#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Audit effective protection using a separate read-only administration App."""
from pathlib import Path
import json
import os
import subprocess

import decision_authority as authority
from common import require
import native_approvals as native


def repository_api(endpoint):
    """Read source metadata without expanding the administration audit App."""
    prefix = 'repos/closure-labs/xo-nixpkg/'
    require(endpoint == prefix + 'git/ref/heads/main'
            or endpoint.startswith(prefix + 'contents/ci/publication-policy.json?ref=')
            or endpoint.startswith(prefix + 'contents/.github/CODEOWNERS?ref='),
            'Unexpected repository metadata endpoint')
    token = os.environ.get('REPOSITORY_READ_TOKEN')
    require(isinstance(token, str) and token.strip(), 'Scoped repository metadata reader required')
    response = subprocess.run(['gh', 'api', '--method', 'GET', endpoint],
                              env=dict(os.environ, GH_TOKEN=token), check=True,
                              text=True, capture_output=True, timeout=60)
    return json.loads(response.stdout)


def audit_api(endpoint):
    """Keep effective rules on the administration reader, metadata on contents."""
    if endpoint in ('repos/closure-labs/xo-nixpkg/rules/branches/main',
                    'repos/closure-labs/xo-nixpkg/rulesets/21015412',
                    'repos/closure-labs/xo-nixpkg/environments/publication'):
        return authority.github_api(endpoint)
    return repository_api(endpoint)


def main():
    cfg = native.policy(Path(native.POLICY), live=True, api=audit_api)
    native.protections(cfg, audit_api)
    print(json.dumps({'schema': 1, 'status': 'verified', 'publicationEnabled': cfg['enabled']}))


if __name__ == '__main__':
    main()
