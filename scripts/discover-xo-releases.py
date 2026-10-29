#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Discover official XO channels from release commits and immutable changelogs.

Conventional commit subjects identify release cuts, not authoritative versions.
The channel snapshot and each cut's own latest badge must agree on identity.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SHA = re.compile(r'[a-f0-9]{40}')
MARKER = re.compile(r'^feat: release\s+(?:XO\s+)?(?P<version>[0-9]+(?:\.[0-9]+)+)(?: \(#[0-9]+\))?$')
HEADING = re.compile(r'^## \*\*([0-9]+(?:\.[0-9]+)+)\*\*', re.M)
CANDIDATE_HEADING = re.compile(r'^##[ \t]+\*\*[ \t]*([0-9]+(?:\.[0-9]+)+)[ \t]*\*\*', re.M)
BADGE = re.compile(r'<img\b[^>]*\bid=["\'](latest|stable)["\'][^>]*>')
ROOT = 'https://api.github.com/repos/vatesfr/xen-orchestra'
MAX_BYTES = 16 * 1024**2


def version_key(version):
    parts = list(map(int, version.split('.')))
    while len(parts) > 2 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def channel_versions(text, required=('latest', 'stable')):
    channels, current = {}, None
    for line in text.splitlines():
        if line.startswith('## '):
            heading = HEADING.match(line)
            current = heading[1] if heading else None
        for badge in BADGE.finditer(line):
            channel = badge[1]
            if current is None or channel in channels:
                raise ValueError('Missing release heading or duplicate root changelog channel badge')
            channels[channel] = current
    if any(channel not in channels for channel in required):
        raise ValueError('Root changelog lacks required official channel badges')
    if 'stable' in channels and version_key(channels['latest']) <= version_key(channels['stable']):
        raise ValueError('Root changelog latest/stable ordering is invalid')
    return channels


def select(changelog, commits, load_context, excluded=()):
    channels = channel_versions(changelog)
    if any(version_key(channels['stable']) == version_key(value) for value in excluded):
        raise ValueError('Upstream stable channel conflicts with excluded stable version policy')
    selected, seen = {}, set()
    channel_keys = {version_key(version) for version in channels.values()}
    for commit in commits:
        if not isinstance(commit, dict) or not SHA.fullmatch(str(commit.get('sha', ''))):
            raise ValueError('Invalid immutable upstream commit identity')
        metadata = commit.get('commit')
        if not isinstance(metadata, dict):
            raise ValueError('Invalid upstream commit metadata')
        message = metadata.get('message')
        if not isinstance(message, str):
            raise ValueError('Invalid upstream commit subject')
        subject = message.split('\n', 1)[0]
        marker = MARKER.fullmatch(subject)
        if marker is None or commit['sha'] in seen:
            continue
        seen.add(commit['sha'])
        context = load_context(commit['sha'])
        # Historical cuts have older changelog layouts. Only validate the
        # current channels strictly, but inspect every cut in the fetched batch
        # for duplicate identities (including subjects with a version typo).
        candidate = CANDIDATE_HEADING.search(context)
        if (version_key(marker['version']) not in channel_keys
                and (candidate is None or version_key(candidate[1]) not in channel_keys)):
            continue
        local = channel_versions(context, required=('latest',))
        first = HEADING.search(context)
        if first is None or version_key(first[1]) != version_key(local['latest']):
            raise ValueError('Release commit root heading disagrees with its latest channel badge')
        canonical = local['latest']
        matches = [channel for channel, version in channels.items()
                   if version_key(canonical) == version_key(version)]
        if not matches:
            continue
        channel = matches[0]
        if channel in selected and selected[channel]['sha'] != commit['sha']:
            raise ValueError('Ambiguous duplicate release commits for official channel ' + channel)
        if version_key(marker['version']) != version_key(canonical):
            print('Release subject version ' + marker['version'] + ' disagrees with canonical ' + canonical
                  + ' at ' + commit['sha'] + '; immutable channel snapshot and commit-local latest badge agree.',
                  file=sys.stderr)
        selected[channel] = {'sha': commit['sha'], 'subject': subject, 'version': channels[channel]}
    if set(selected) == {'latest', 'stable'}:
        return [selected['latest'], selected['stable']]
    return None


def fetch(url, *, api=False):
    args = ['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '2',
            '--retry-all-errors', '--retry-delay', '1', '--connect-timeout', '10',
            '--max-time', '45', '--max-filesize', str(MAX_BYTES)]
    if api:
        args += ['--header', 'Accept: application/vnd.github+json',
                 '--header', 'X-GitHub-Api-Version: 2022-11-28']
        if os.environ.get('GITHUB_TOKEN'):
            args += ['--header', 'Authorization: Bearer ' + os.environ['GITHUB_TOKEN']]
    try:
        result = subprocess.run([*args, url], capture_output=True, timeout=150)
    except (OSError, subprocess.SubprocessError):
        # Exception strings may include the authenticated command arguments.
        raise ValueError('Bounded upstream request could not complete') from None
    if result.returncode:
        raise ValueError('Bounded upstream request failed (curl exit ' + str(result.returncode)
                         + '); check connectivity, API rate limits and token permissions')
    if len(result.stdout) > MAX_BYTES:
        raise ValueError('Upstream response exceeds discovery byte bound')
    return result.stdout.decode('utf-8')


def commit_metadata(ref):
    value = json.loads(fetch(ROOT + '/commits/' + ref, api=True))
    sha = value.get('sha') if isinstance(value, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha) or (SHA.fullmatch(ref) and sha != ref):
        raise ValueError('Upstream commit metadata disagrees with requested immutable identity')
    return value


def rolling_metadata(revision):
    if not SHA.fullmatch(revision):
        raise ValueError('Rolling revision must be an immutable 40-character commit')
    value = commit_metadata(revision)
    try:
        date = value['commit']['committer']['date']
    except (KeyError, TypeError) as error:
        raise ValueError('Rolling commit metadata lacks committer date') from error
    if not isinstance(date, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', date):
        raise ValueError('Invalid rolling commit date')
    return {'rev': revision, 'date': date[:10]}


def discover(pin):
    pages = int(os.environ.get('XO_NIXPKG_RELEASE_SCAN_PAGES', '5'))
    if not 1 <= pages <= 20:
        raise ValueError('Release discovery page bound must be 1-20')
    snapshot_file = os.environ.get('XO_NIXPKG_RELEASE_CHANNELS_FILE')
    if snapshot_file:
        changelog = Path(snapshot_file).read_text()
        snapshot = None
    else:
        value = commit_metadata('master')
        snapshot = value.get('sha')
        if not isinstance(snapshot, str) or not SHA.fullmatch(snapshot):
            raise ValueError('Upstream master lacks immutable commit identity')
        changelog = fetch('https://raw.githubusercontent.com/vatesfr/xen-orchestra/' + snapshot + '/CHANGELOG.md')
    cache = {}
    def context(sha):
        if sha not in cache:
            directory = os.environ.get('XO_NIXPKG_RELEASE_CHANGELOG_DIR')
            cache[sha] = ((Path(directory) / (sha + '.md')).read_text() if directory else
                          fetch('https://raw.githubusercontent.com/vatesfr/xen-orchestra/' + sha + '/CHANGELOG.md'))
        return cache[sha]
    commits = []
    fixture = os.environ.get('XO_NIXPKG_COMMITS_JSON')
    for page in range(1, pages + 1):
        if fixture:
            response = json.loads(Path(fixture).read_text())
        else:
            print('Scanning root CHANGELOG.md commits page ' + str(page) + ' at immutable upstream snapshot...', file=sys.stderr)
            suffix = '&sha=' + snapshot if snapshot else ''
            response = json.loads(fetch(ROOT + '/commits?path=CHANGELOG.md&per_page=100&page=' + str(page) + suffix, api=True))
        if not isinstance(response, list):
            raise ValueError('GitHub commit response is not a JSON array')
        commits.extend(response)
        selected = select(changelog, commits, context, pin.get('excludedStableVersions', []))
        if selected:
            return selected
        if fixture or not response:
            break
    raise ValueError('Could not bind both official channel badges to release commits within the page bound')


def check_progress(pin, releases):
    for channel, release in zip(('latest', 'stable'), releases):
        current_pin = pin['channels'][channel]
        current = current_pin['version']
        if version_key(release['version']) < version_key(current):
            raise ValueError('Refusing to downgrade ' + channel + ' XO from ' + current + ' to ' + release['version'])
        if version_key(release['version']) == version_key(current) and release['sha'] != current_pin['rev']:
            raise ValueError('Refusing to remap immutable ' + channel + ' XO version ' + current
                             + ' to a different commit')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--pin')
    modes.add_argument('--rolling-rev')
    args = parser.parse_args()
    try:
        if args.rolling_rev:
            result = rolling_metadata(args.rolling_rev)
        else:
            pin = json.loads(Path(args.pin).read_text())
            result = discover(pin)
            check_progress(pin, result)
        print(json.dumps(result, separators=(',', ':')))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('XO release discovery failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
