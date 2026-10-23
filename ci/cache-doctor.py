#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read cache permissions using Devenv's private built-in SecretSpec namespace."""
import argparse
import json
import os
import resource
import signal
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
import operations


class DiagnosticError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiagnosticError('cache-redirect-rejected')


def resolve_token(name, provider):
    # Matches native Devenv load_cachix_secretspec. No secret enters the
    # manifest, command arguments, Nix evaluation, or the calling environment.
    manifest = ('[project]\nname = "devenv-cachix"\nrevision = "1.0"\n'
                'require_reason = false\n\n[profiles.default]\n'
                + name + ' = { description = "Cachix authentication token", required = true }\n')
    with tempfile.TemporaryDirectory(prefix='cache-doctor-') as directory:
        path = Path(directory) / 'secretspec.toml'
        path.write_text(manifest)
        try:
            result = operations.run(
                ['secretspec', 'get', '--file', str(path), '--provider', provider,
                 '--profile', 'default', '--reason', 'Check Cachix cache identity and permissions', name],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            raise DiagnosticError('secret-resolution-timeout') from None
        if result.returncode:
            raise DiagnosticError('secret-unavailable-run-interactive-devenv-shell-first')
    token = result.stdout.decode('ascii').removesuffix('\n')
    if not token or len(token) > 16384 or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
        raise DiagnosticError('invalid-token-format')
    return token


def inspect_cache(cache, public_key, token, opener):
    request = urllib.request.Request('https://cachix.org/api/v1/cache/' + cache,
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Accept': 'application/json',
                                              'User-Agent': 'xo-nixpkg-cache-doctor/1'})
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200:
                raise DiagnosticError('cache-unavailable')
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        request_blocked = (code == 403
                           and error.headers.get('Server', '').lower() == 'cloudflare'
                           and not error.headers.get('Content-Type', '').lower().startswith('application/json'))
        error.close()
        if request_blocked:
            raise DiagnosticError('cache-request-blocked') from None
        raise DiagnosticError('token-rejected' if code in (401, 403)
                              else 'cache-unavailable') from None
    if len(body) > 1024 * 1024:
        raise DiagnosticError('cache-response-too-large')
    value = json.loads(body)
    if (not isinstance(value, dict) or value.get('name') != cache
            or value.get('uri') != 'https://' + cache + '.cachix.org'
            or not isinstance(value.get('publicSigningKeys'), list)
            or not all(isinstance(key, str) for key in value['publicSigningKeys'])
            or public_key not in value['publicSigningKeys']
            or value.get('permission') not in ('Read', 'Write', 'Admin')):
        raise DiagnosticError('cache-identity-or-permission-mismatch')
    permission = value['permission']
    return {'schemaVersion': 1, 'cache': cache, 'publicKeyMatches': True,
            'permission': permission, 'canWrite': permission in ('Write', 'Admin')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('keyring', 'env'), default='keyring')
    args = parser.parse_args()
    # The packaged command fixes these public constants; tests can import the
    # implementation and exercise requests without contacting external services.
    cache = 'xen-orchestra-ce'
    key = 'xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E='
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if os.environ.get('CACHIX_AUTH_TOKEN'):
            raise DiagnosticError('unset-generic-CACHIX_AUTH_TOKEN-to-test-the-named-token')
        token = resolve_token('CACHIX_XO_DEVENV_TOKEN', args.provider)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        def expired(signum, frame):
            raise DiagnosticError('cache-metadata-timeout')
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(30)
        try:
            result = inspect_cache(cache, key, token, opener)
        finally:
            signal.alarm(0)
        print(json.dumps(result, sort_keys=True))
        # Public read access cannot prove that this token is valid. No write is
        # attempted, and this diagnostic never authorizes publication.
        return 0 if result['canWrite'] else 1
    except DiagnosticError as error:
        print(json.dumps({'schemaVersion': 1, 'cache': cache, 'error': str(error)}))
    except Exception:
        # Exception strings and raw provider/API bodies may contain credentials.
        print(json.dumps({'schemaVersion': 1, 'cache': cache, 'error': 'diagnostic-unavailable'}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
