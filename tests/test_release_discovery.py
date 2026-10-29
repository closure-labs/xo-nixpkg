# SPDX-License-Identifier: Apache-2.0
"""Release subjects are candidates; two immutable changelogs corroborate identity."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_discovery', ROOT / 'scripts/discover-xo-releases.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
LATEST, STABLE = 'a' * 40, 'b' * 40
SNAPSHOT = '## **6.10.0**\n<img id="latest" />\n## **6.9.1**\n<img id="stable" />\n'


def commit(sha, subject):
    return {'sha': sha, 'commit': {'message': subject}}


def context(version):
    return '## **' + version + '**\n<img id="latest" />\n'


class ReleaseDiscovery(unittest.TestCase):
    def setUp(self):
        self.commits = [commit(LATEST, 'feat: release 6.10.0 (#10689)'),
                        commit(STABLE, 'feat: release 6.9.1 (#10533)')]
        self.contexts = {LATEST: context('6.10.0'), STABLE: context('6.9.1')}

    def select(self, snapshot=SNAPSHOT, commits=None):
        return mod.select(snapshot, commits or self.commits, self.contexts.__getitem__)

    def test_official_grammar_excludes_lite_technical_and_scoped_package_releases(self):
        for subject in ('feat(lite): 0.27.0 (#1)', 'feat: technical release (#2)',
                        'feat(xo-server): 5.1.0', 'feat!: release 6.10.0', 'release 6.10.0'):
            self.assertIsNone(mod.MARKER.fullmatch(subject))
        for subject in ('feat: release 6.10.0 (#1)', 'feat: release XO 6.10.0 (#1)',
                        'feat: release  6.10.0 (#1)', 'feat: release 6.10.0'):
            self.assertIsNotNone(mod.MARKER.fullmatch(subject))

    def test_subject_typo_needs_snapshot_and_immutable_cut_agreement(self):
        self.commits[0]['commit']['message'] = 'feat: release 9.10.0 (#10689)'
        result = self.select()
        self.assertEqual([(v['version'], v['sha']) for v in result], [('6.10.0', LATEST), ('6.9.1', STABLE)])
        self.contexts[LATEST] = context('6.11.0')
        self.assertIsNone(self.select())

    def test_repeated_page_boundary_commit_is_idempotent(self):
        result = self.select(commits=[self.commits[0], *self.commits])
        self.assertEqual(result[0]['sha'], LATEST)

    def test_two_different_cuts_for_same_channel_are_ambiguous(self):
        other = 'c' * 40
        self.contexts[other] = context('6.10.0')
        with self.assertRaisesRegex(ValueError, 'Ambiguous duplicate'):
            self.select(commits=[self.commits[0], commit(other, 'feat: release 6.10.0 (#3)'), self.commits[1]])
        with self.assertRaisesRegex(ValueError, 'Ambiguous duplicate'):
            self.select(commits=[*self.commits, commit(other, 'feat: release 6.10.0 (#3)')])

    def test_missing_duplicate_reversed_or_unreleased_channel_badges_fail(self):
        for snapshot in (SNAPSHOT.replace('<img id="stable" />', ''),
                         SNAPSHOT + '<img id="latest" />',
                         SNAPSHOT.replace('6.10.0', '6.8.0'),
                         SNAPSHOT.replace('## **6.10.0**', '## **next**')):
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                self.select(snapshot=snapshot)

    def test_excluded_stable_policy_normalizes_trailing_zero(self):
        with self.assertRaisesRegex(ValueError, 'excluded stable'):
            mod.select(SNAPSHOT, self.commits, self.contexts.__getitem__, ['6.9.1.0'])

    def test_canonical_heading_must_own_latest_badge_at_release_cut(self):
        self.contexts[LATEST] = '## **6.11.0**\n' + context('6.10.0')
        with self.assertRaisesRegex(ValueError, 'heading disagrees'):
            self.select()

    def test_both_channels_reject_downgrades_and_accept_equal_canonical_versions(self):
        releases = self.select()
        pin = {'channels': {'latest': {'version': '6.10', 'rev': LATEST},
                            'stable': {'version': '6.9.1.0', 'rev': STABLE}}}
        mod.check_progress(pin, releases)
        for channel in ('latest', 'stable'):
            with self.subTest(channel=channel):
                pin['channels'][channel]['version'] = '99.0.0'
                with self.assertRaisesRegex(ValueError, 'Refusing to downgrade ' + channel):
                    mod.check_progress(pin, releases)
                pin['channels'][channel]['version'] = releases[0 if channel == 'latest' else 1]['version']

    def test_equal_version_cannot_be_remapped_to_a_different_commit(self):
        releases = self.select()
        for channel in ('latest', 'stable'):
            pin = {'channels': {'latest': {'version': '6.10', 'rev': LATEST},
                                'stable': {'version': '6.9.1.0', 'rev': STABLE}}}
            pin['channels'][channel]['rev'] = 'c' * 40
            with self.subTest(channel=channel), self.assertRaisesRegex(ValueError, 'remap immutable ' + channel):
                mod.check_progress(pin, releases)

    def test_rolling_metadata_is_bound_to_requested_commit_and_date(self):
        response = {'sha': LATEST, 'commit': {'committer': {'date': '2026-10-29T12:00:00Z'}}}
        with patch.object(mod, 'fetch', return_value=json.dumps(response)):
            self.assertEqual(mod.rolling_metadata(LATEST), {'rev': LATEST, 'date': '2026-10-29'})
        for value in ({**response, 'sha': STABLE}, {'sha': LATEST, 'commit': {}}):
            with patch.object(mod, 'fetch', return_value=json.dumps(value)), self.assertRaises(ValueError):
                mod.rolling_metadata(LATEST)

    def test_rate_limit_or_network_failure_exposes_no_token_or_remote_body(self):
        result = subprocess.CompletedProcess([], 22, b'', b'HTTP 403 secret-token private-body')
        with patch.object(mod.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'rate limits') as raised:
            mod.fetch(mod.ROOT + '/commits/master', api=True)
        self.assertNotIn('secret-token', str(raised.exception))
        self.assertNotIn('private-body', str(raised.exception))

    def test_subprocess_exceptions_do_not_expose_authenticated_arguments(self):
        for error in (subprocess.TimeoutExpired(['curl', 'secret-token'], 150),
                      OSError('secret-token launch error')):
            with patch.object(mod.subprocess, 'run', side_effect=error), self.assertRaises(ValueError) as raised:
                mod.fetch(mod.ROOT + '/commits/master', api=True)
            self.assertNotIn('secret-token', str(raised.exception))
