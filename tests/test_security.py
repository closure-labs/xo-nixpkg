# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'ci' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inventory = module('security-inventory')
normalize = module('security-normalize')


class InventoryTests(unittest.TestCase):
    def test_installed_npm_and_native_exact_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / 'libexec/xen-orchestra/node_modules/@scope/dependency'
            package.mkdir(parents=True)
            (package / 'package.json').write_text(json.dumps({'name': '@scope/dependency', 'version': '1.2.3'}))
            (package / 'index.js').write_text('module.exports = 1')
            binary = root / 'bin/native'
            binary.parent.mkdir()
            binary.write_bytes(b'\x7fELFfixture')
            drv = {'fixture.drv': {'env': {'pname': 'native', 'version': '2.3.4', 'out': str(root)}, 'outputs': {'out': {'path': str(root)}}}}
            result = inventory.inventory(root, {str(root): {}}, drv)
            self.assertEqual({item['purl'] for item in result['components']}, {'pkg:npm/%40scope/dependency@1.2.3', 'pkg:nix/native@2.3.4'})
            report = {'matches': [{'artifact': {'purl': 'pkg:npm/%40scope/dependency@1.2.3'},
                'vulnerability': {'id': 'GHSA-fixture', 'severity': 'Low', 'cvss': [{'metrics': {'baseScore': 3.1}}]},
                'relatedVulnerabilities': [{'id': 'CVE-fixture'}]}]}
            observation = normalize.normalize(result, report)['observations'][0]
            self.assertIn(str(package / 'index.js'), observation['locations'])
            self.assertEqual(observation['aliases'], ['CVE-fixture', 'GHSA-fixture'])
            self.assertEqual(observation['exposureBindings'][0]['outputName'], 'out')
            self.assertTrue(all(not Path(path).is_dir() for path in observation['locations']))

    def test_native_version_cannot_be_guessed_from_store_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'native').write_bytes(b'\x7fELFfixture')
            drv = {'fixture.drv': {'env': {'name': 'openssl-1.2.3'}, 'outputs': {'out': {'path': str(root)}}}}
            with self.assertRaisesRegex(ValueError, 'unversioned'):
                inventory.inventory(root, {str(root): {}}, drv, xo=False)

    def test_version_four_relative_output_identity(self):
        record = {'env': {'out': '/nix/store/identity-native'},
                  'outputs': {'out': {'path': 'identity-native'}}}
        self.assertEqual(inventory.exact_output(record, 'out', record['outputs']['out']), '/nix/store/identity-native')
        record['env']['out'] = '/nix/store/conflicting'
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            inventory.exact_output(record, 'out', record['outputs']['out'])

    def test_empty_npm_inventory_and_unknown_advisories_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'no installed npm'):
                inventory.npm_components(Path(temporary))
        with self.assertRaisesRegex(ValueError, 'outside'):
            normalize.normalize({'components': []}, {'matches': [{'artifact': {'purl': 'pkg:npm/unbound@1'}, 'vulnerability': {'id': 'CVE-fixture'}}]})

    def test_all_severities_and_exploitation_preserved(self):
        component = {'purl': 'pkg:nix/lib@1', 'properties': [
            {'name': 'nix:storePath', 'value': '/nix/store/root'},
            {'name': 'xo-nixpkg:outputName', 'value': 'lib'},
            {'name': 'xo-nixpkg:installedPath', 'value': '/nix/store/root/lib/code.so'}]}
        for severity in ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']:
            match = {'artifact': {'purl': component['purl']}, 'vulnerability': {'id': 'CVE-fixture', 'severity': severity, 'knownExploited': [{}]}}
            result = normalize.normalize({'components': [component]}, {'matches': [match]})
            self.assertEqual(result['observations'][0]['severity'], severity)
            self.assertTrue(result['observations'][0]['knownExploited'])



class InventoryCollectorTests(unittest.TestCase):
    def collect(self, *, unknown_native=False, unknown_npm=False,
                malformed_native=None, unversioned=False,
                unrelated_native=False, unrelated_npm=False,
                native_candidate=None, npm_candidate=None):
        """Exercise the real CLI with a closure containing literal store source."""
        import os
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, native = directory / 'xo', directory / 'native'
            package = root / 'libexec/xen-orchestra/node_modules/dependency'
            package.mkdir(parents=True)
            (package / 'package.json').write_text('{"name":"dependency","version":"1.2.3"}')
            if not (unknown_npm or unrelated_npm or npm_candidate):
                (root / 'binary').write_bytes(b'\x7fELFprimary')
            native.mkdir()
            (native / 'library.so').write_bytes(b'\x7fELFnative')
            literal, derived = directory / 'source.py', directory / 'derived.txt'
            literal.write_text('#!/usr/bin/env python3\nprint("source")\n')
            derived.write_text('known derived data\n')
            closure = {str(path): {'narHash': 'sha256-fixture-' + path.name,
                                  'references': [str(literal)] if path == root else []}
                       for path in (root, native, literal, derived)}
            root_drv = '/nix/store/' + 'a' * 32 + '-xo.drv'
            native_drv = '/nix/store/' + 'b' * 32 + '-native.drv'
            derived_drv = '/nix/store/' + 'c' * 32 + '-derived.drv'
            records = {drv: {'env': {'pname': name, 'version': version, 'out': str(path)},
                             'outputs': {'out': {'path': str(path)}}}
                       for drv, name, version, path in (
                           (root_drv, 'xo', '6.9.1', root),
                           (native_drv, 'native-library', '2.3.4', native),
                           (derived_drv, 'derived-data', '1', derived))}
            if unversioned:
                del records[native_drv]['env']['version']
            for enabled, drv in ((unrelated_native, native_drv), (unrelated_npm, root_drv)):
                if enabled:
                    records[drv]['env']['out'] = str(directory / 'unrelated-output')
                    records[drv]['outputs']['out']['path'] = str(directory / 'unrelated-output')
            # The cached primary pointer is absent, while the valid producer
            # index knows the exact same output under its current derivation.
            stale_primary = '/nix/store/' + 'e' * 32 + '-missing-cached-producer.drv'
            derivers = ([] if unknown_npm else [root_drv])
            if malformed_native is not None:
                derivers.append(malformed_native)
            elif not unknown_native:
                derivers.append(native_drv)
            derivers.append(derived_drv)
            for variant, original, suffix in ((native_candidate, native_drv, 'd'),
                                               (npm_candidate, root_drv, 'f')):
                if variant is None:
                    continue
                duplicate = '/nix/store/' + suffix * 32 + '-duplicate.drv'
                record = json.loads(json.dumps(records[original]))
                if variant in ('pname', 'version'):
                    record['env'][variant] += '-conflicting'
                elif variant == 'missing-version':
                    del record['env']['version']
                elif variant == 'empty-pname':
                    record['env']['pname'] = ''
                elif variant in ('output-name', 'empty-output-name'):
                    name = 'other' if variant == 'output-name' else ''
                    record['outputs'] = {name: record['outputs']['out']}
                    record['env'][name] = record['env'].pop('out')
                elif variant == 'multiple-outputs':
                    record['outputs']['other'] = record['outputs']['out']
                    record['env']['other'] = record['env']['out']
                else:
                    assert variant == 'equivalent'
                records[duplicate] = record
                derivers.append(duplicate)
            fixture = directory / 'fixture.json'
            fixture.write_text(json.dumps({'closure': closure, 'derivers': derivers,
                                           'records': records, 'stalePrimary': stale_primary}))
            log = directory / 'commands.jsonl'
            executable = directory / 'bin'
            executable.mkdir()
            script = '#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
fixture = json.loads(Path(os.environ['INVENTORY_FIXTURE']).read_text())
args = sys.argv[1:]
with Path(os.environ['INVENTORY_COMMANDS']).open('a') as handle:
    handle.write(json.dumps([Path(sys.argv[0]).name, *args]) + '\\n')
if Path(sys.argv[0]).name == 'nix-store':
    assert set(args[2:]) == set(fixture['closure'])
    if args[:2] == ['--query', '--deriver']:
        print(fixture['stalePrimary'])
    else:
        assert args[:2] == ['--query', '--valid-derivers']
        print('\\n'.join(fixture['derivers']))
elif args[:4] == ['path-info', '--recursive', '--json', os.environ['INVENTORY_ROOT']]:
    print(json.dumps(fixture['closure']))
else:
    assert args[:2] == ['derivation', 'show']
    assert all(arg in fixture['records'] for arg in args[2:])
    print(json.dumps({'derivations': {arg: fixture['records'][arg] for arg in args[2:]}}))
'''
            for name in ('nix', 'nix-store'):
                command = executable / name
                command.write_text(script)
                command.chmod(0o755)
            output = directory / 'evidence'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'ci/security-inventory.py'), '--root', str(root),
                 '--profile', 'xo-latest', '--output', str(output), '--additional-root', str(native)],
                env=dict(os.environ, PATH=str(executable) + os.pathsep + os.environ.get('PATH', ''),
                         INVENTORY_FIXTURE=str(fixture), INVENTORY_COMMANDS=str(log),
                         INVENTORY_ROOT=str(root), PYTHONDONTWRITEBYTECODE='1'),
                capture_output=True, text=True, timeout=30)
            documents = {path.name: json.loads(path.read_text()) for path in output.glob('*.json')}
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            return result, documents, calls, closure, records

    def test_stale_primary_uses_valid_index_and_preserves_complete_inventory(self):
        result, documents, calls, closure, records = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(documents['closure.json'], closure)
        self.assertEqual(documents['derivations.json'], records)
        components = documents['runtime.cdx.json']['components']
        self.assertEqual({component['purl'] for component in components},
                         {'pkg:npm/dependency@1.2.3', 'pkg:nix/xo@6.9.1',
                          'pkg:nix/native-library@2.3.4'})
        native_locations = {prop['value'] for component in components
                            if component['purl'].startswith('pkg:nix/')
                            for prop in component['properties']
                            if prop['name'] == 'xo-nixpkg:installedPath'}
        self.assertEqual(len(native_locations), 2)
        self.assertTrue(all(path.endswith(('/binary', '/library.so')) for path in native_locations))
        queried = [arg for call in calls if call[:3] == ['nix', 'derivation', 'show']
                   for arg in call[3:]]
        self.assertEqual(set(queried), set(records))
        self.assertFalse(any('--deriver' in call for call in calls))
        self.assertTrue(any(call[:3] == ['nix-store', '--query', '--valid-derivers'] for call in calls))
        manifest = documents['inventory.json']
        self.assertEqual(manifest['coverage'], 'complete')
        self.assertEqual(set(manifest['documents']),
                         {'runtime.cdx.json', 'closure.json', 'derivations.json'})

    def test_unknown_native_producer_still_fails(self):
        result, documents, _, _, _ = self.collect(unknown_native=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no exact output producer', result.stderr)
        self.assertNotIn('inventory.json', documents)

    def test_malformed_deriver_is_not_treated_as_unknown(self):
        for malformed in ('missing', 'unknown-deriver', 'unknown-deriver-extra', ' unknown-deriver', 'unknown-deriver '):
            with self.subTest(malformed=malformed):
                result, documents, calls, _, _ = self.collect(malformed_native=malformed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('closure derivation metadata is missing', result.stderr)
                self.assertFalse(any(call[:3] == ['nix', 'derivation', 'show'] for call in calls))
                self.assertNotIn('inventory.json', documents)

    def test_valid_index_producer_for_unrelated_output_is_rejected(self):
        for options, message in (({'unrelated_native': True}, 'no exact output producer'),
                                 ({'unrelated_npm': True}, 'ambiguous installed npm output producer')):
            with self.subTest(options=options):
                result, documents, _, _, _ = self.collect(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn('inventory.json', documents)

    def test_unknown_installed_npm_root_still_fails(self):
        result, documents, _, _, _ = self.collect(unknown_npm=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ambiguous installed npm output producer', result.stderr)
        self.assertNotIn('inventory.json', documents)

    def test_unversioned_native_producer_still_fails(self):
        result, documents, _, _, _ = self.collect(unversioned=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unversioned shipped native code', result.stderr)
        self.assertNotIn('inventory.json', documents)

    def test_equivalent_native_producers_preserve_all_provenance(self):
        result, documents, _, _, records = self.collect(native_candidate='equivalent')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(documents['derivations.json'], records)
        component = next(item for item in documents['runtime.cdx.json']['components']
                         if item['purl'] == 'pkg:nix/native-library@2.3.4')
        producers = {prop['value'] for prop in component['properties']
                     if prop['name'] == 'nix:derivation'}
        self.assertEqual(producers, {drv for drv in records if drv.endswith(('-native.drv', '-duplicate.drv'))})
        self.assertEqual(len(producers), 2)

    def test_equivalent_npm_root_producers_require_identity_and_preserve_provenance(self):
        result, documents, _, _, records = self.collect(npm_candidate='equivalent')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(documents['derivations.json'], records)
        component = next(item for item in documents['runtime.cdx.json']['components']
                         if item['purl'] == 'pkg:npm/dependency@1.2.3')
        producers = {prop['value'] for prop in component['properties']
                     if prop['name'] == 'nix:derivation'}
        self.assertEqual(producers, {drv for drv in records if drv.endswith(('-xo.drv', '-duplicate.drv'))})
        self.assertEqual(len(producers), 2)

    def test_conflicting_or_incomplete_producer_candidates_fail(self):
        for kind in ('native_candidate', 'npm_candidate'):
            for variant in ('pname', 'version', 'output-name', 'missing-version',
                            'empty-pname', 'empty-output-name', 'multiple-outputs'):
                with self.subTest(kind=kind, variant=variant):
                    result, documents, _, _, _ = self.collect(**{kind: variant})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('inventory.json', documents)
                    message = ('conflicting exact output producer identities' if variant in ('pname', 'version', 'output-name')
                               else 'multiple derivation outputs map' if variant == 'multiple-outputs'
                               else 'unversioned shipped native code or invalid output identity')
                    self.assertIn(message, result.stderr)


class PublicationJournalTests(unittest.TestCase):
    def test_checkpoints_use_fast_forward_cas_and_reject_conflicting_step(self):
        from unittest.mock import patch
        controller = module('publication-controller')
        calls = []
        reference = {}

        def fake_api(repository, endpoint, body=None, method=None, missing=False):
            calls.append((endpoint, body, method))
            if endpoint.startswith('git/ref/heads/'):
                return {'object': {'sha': reference['sha']}} if reference else None
            if endpoint == 'git/trees':
                return {'sha': 'tree'}
            if endpoint == 'git/commits':
                return {'sha': 'commit-' + str(len(calls))}
            if endpoint == 'git/refs':
                reference['sha'] = body['sha']
                return {}
            if endpoint.startswith('git/refs/heads/'):
                self.assertFalse(body['force'])
                self.assertEqual(method, 'PATCH')
                reference['sha'] = body['sha']
                return {}
            self.fail(endpoint)

        with patch.object(controller, 'api', side_effect=fake_api):
            journal = controller.Journal('closure-labs/xo-nixpkg', {'schema': 1})
            original = journal.commit
            journal.complete('cache', {'output': 'immutable'})
            parent = next(body['parents'] for endpoint, body, _ in reversed(calls) if endpoint == 'git/commits')
            self.assertEqual(parent, [original])
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                journal.complete('cache', {'output': 'different'})

    def test_ref_race_does_not_silently_overwrite_checkpoint(self):
        from unittest.mock import patch
        controller = module('publication-controller')
        calls = 0

        def fake_api(repository, endpoint, body=None, method=None, missing=False):
            nonlocal calls
            if endpoint.startswith('git/ref/heads/'):
                calls += 1
                return None if calls == 1 else {'object': {'sha': 'concurrent-writer'}}
            if endpoint == 'git/trees':
                return {'sha': 'tree'}
            if endpoint == 'git/commits':
                return {'sha': 'ours'}
            return {}

        with patch.object(controller, 'api', side_effect=fake_api):
            with self.assertRaisesRegex(ValueError, 'concurrently'):
                controller.Journal('closure-labs/xo-nixpkg', {'schema': 1})


class HandoffPublicationTests(unittest.TestCase):
    def test_registry_token_and_historical_provenance_survive_push_and_cleanup(self):
        import os
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        controller = module('publication-controller')
        source_revision, producer_revision = 'a' * 40, 'b' * 40
        scans = {'producer': {'workflow': '.github/workflows/qualification.yml',
                             'revision': producer_revision, 'runId': 3, 'runAttempt': 1}}
        for failing in (False, True):
            with self.subTest(failing=failing):
                calls, directories = [], []

                def fake_run(*args, **kwargs):
                    calls.append(args)
                    self.assertEqual(os.environ['REGISTRY_TOKEN'], 'registry-fixture')
                    self.assertNotEqual(os.environ['DOCKER_CONFIG'], '/caller/auth')

                def fake_push(directory, producer):
                    self.assertEqual(os.environ['REGISTRY_TOKEN'], 'registry-fixture')
                    self.assertEqual(producer['revision'], producer_revision)
                    self.assertEqual(producer['sourceRevision'], source_revision)
                    self.assertEqual(producer['repository'], 'closure-labs/xo-nixpkg')
                    directories.append(Path(os.environ['DOCKER_CONFIG']))
                    self.assertTrue(directories[-1].is_dir())
                    if failing:
                        raise RuntimeError('registry upload failed')
                    return {'reference': 'immutable-packet'}

                packet_module = SimpleNamespace(push=fake_push)
                with patch.dict(os.environ, {'REGISTRY_TOKEN': 'registry-fixture',
                                             'GITHUB_ACTOR': 'fixture', 'DOCKER_CONFIG': '/caller/auth'}), \
                        patch.dict(sys.modules, {'decision_packets': packet_module}), \
                        patch.object(controller, 'run', side_effect=fake_run):
                    if failing:
                        with self.assertRaisesRegex(RuntimeError, 'upload failed'):
                            controller.publish_handoff(Path('/candidate'), scans, 'closure-labs/xo-nixpkg', source_revision)
                    else:
                        result = controller.publish_handoff(Path('/candidate'), scans, 'closure-labs/xo-nixpkg', source_revision)
                        self.assertEqual(result, {'reference': 'immutable-packet'})
                    self.assertEqual(os.environ['DOCKER_CONFIG'], '/caller/auth')
                    self.assertEqual(os.environ['REGISTRY_TOKEN'], 'registry-fixture')
                self.assertIn(('xo-nixpkg-publication-gate',), calls)
                self.assertEqual(calls[-1], ('oras', 'logout', 'ghcr.io'))
                self.assertTrue(directories)
                self.assertTrue(all(not path.exists() for path in directories))


class RefreshTests(unittest.TestCase):
    def test_refresh_preserves_approved_product_and_rebinds_current_producer(self):
        import hashlib
        import os
        from unittest.mock import patch
        refresh = module('refresh-products')
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'source', Path(temporary) / 'fresh'
            native = source / 'xo-latest'
            native.mkdir(parents=True)
            sbom = b'{"components":[]}\n'
            (native / 'runtime.cdx.json').write_bytes(sbom)
            (source / 'xo-latest--runtime.cdx.json').write_bytes(sbom)
            product = {'schema': 1, 'repository': 'closure-labs/xo-nixpkg', 'revision': 'a' * 40,
                       'products': {'xo-latest': {'storePath': '/nix/store/immutable', 'narHash': 'sha256-fixture'}},
                       'assets': {'xo-latest--runtime.cdx.json': hashlib.sha256(sbom).hexdigest()}}
            original = json.dumps(product, indent=3).encode()
            (source / 'product.json').write_bytes(original)
            (source / 'scans.json').write_text(json.dumps({'transport': {'fixture': 1}, 'producer': {'workflow': '.github/workflows/qualification.yml', 'runId': 1, 'runAttempt': 1}}))
            transport_source = Path(temporary) / 'transport.py'
            transport_source.write_text('def restore(directory, manifest, roots):\n    assert manifest == {"fixture": 1}\n')

            def fake_run(args, **kwargs):
                self.assertNotIn('GH_TOKEN', os.environ)
                if args[0] == 'xo-nixpkg-security-native-scan':
                    (Path(args[2]) / 'scan.json').write_text(json.dumps({'status': 'complete', 'scannerHealth': 'healthy', 'observations': []}))

            def fake_command(*args):
                if args[0] == 'xo-nixpkg-security-database':
                    self.assertEqual(args[1], 'prepare')
                    return 'c' * 64
                return 'b' * 40 if args[0] == 'git' else json.dumps({'/nix/store/immutable': {'narHash': 'sha256-fixture'}})

            with patch.dict(os.environ, {'XO_NIXPKG_RESCAN_SOURCE': str(source), 'XO_NIXPKG_EVIDENCE': str(output),
                                         'GITHUB_RUN_ID': '3', 'GITHUB_RUN_ATTEMPT': '1', 'GH_TOKEN': 'must-be-removed',
                                         'XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE': str(transport_source)}), \
                    patch.object(refresh.subprocess, 'run', side_effect=fake_run), \
                    patch.object(refresh, 'command', side_effect=fake_command):
                refresh.main()
            self.assertEqual((output / 'product.json').read_bytes(), original)
            scans = json.loads((output / 'scans.json').read_text())
            self.assertEqual(scans['revision'], 'a' * 40)
            self.assertEqual(scans['producer']['revision'], 'b' * 40)
            self.assertEqual(scans['productProducer']['revision'], 'a' * 40)
            self.assertEqual(scans['productProducer']['runId'], 1)
            self.assertEqual(scans['profiles']['xo-latest']['subjects'], [product['products']['xo-latest']])


class PolicyCredentialTests(unittest.TestCase):
    def test_metadata_reader_does_not_expand_audit_app(self):
        import os
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        sys.path.insert(0, str(ROOT / 'ci/decisions'))
        audit = module('audit-policy')
        endpoint = 'repos/closure-labs/xo-nixpkg/git/ref/heads/main'
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-audit-reader',
                                    'REPOSITORY_READ_TOKEN': 'fixture-repository-reader'}), \
                patch.object(audit.subprocess, 'run', return_value=SimpleNamespace(stdout='{"ok":true}')) as run:
            self.assertEqual(audit.repository_api(endpoint), {'ok': True})
            self.assertEqual(run.call_args.kwargs['env']['GH_TOKEN'], 'fixture-repository-reader')
            self.assertEqual(os.environ['GH_TOKEN'], 'fixture-audit-reader')
            with self.assertRaisesRegex(ValueError, 'Unexpected'):
                audit.repository_api('repos/closure-labs/xo-nixpkg/rules/branches/main')
        with patch.dict(os.environ, {'REPOSITORY_READ_TOKEN': ''}):
            with self.assertRaisesRegex(ValueError, 'metadata reader'):
                audit.repository_api(endpoint)

    def test_workflows_use_inherited_variables_and_minted_queue_token(self):
        audit = (ROOT / '.github/workflows/security-audit.yml').read_text()
        queue = (ROOT / '.github/workflows/queue-automation.yml').read_text()
        self.assertIn('client-id: ${{ vars.SECAUDIT_CLIENTID }}', audit)
        self.assertNotIn('permission-contents: read', audit)
        self.assertIn('REPOSITORY_READ_TOKEN: ${{ github.token }}', audit)
        self.assertIn('steps.queue.outputs.token', queue)
        self.assertNotIn('secrets.MERGE_QUEUE_TOKEN', queue)


if __name__ == '__main__':
    unittest.main()
