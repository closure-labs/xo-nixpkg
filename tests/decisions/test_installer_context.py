#!/usr/bin/env python3
"""Schema evolution preserves package-only profiles and installer review boundaries."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('security_decisions', Path(__file__).parents[2] / 'ci/decisions/security_decisions.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


def context():
    return {'schema': 2, 'tcpPorts': [], 'udpPorts': [], 'managementCIDRs': ['10.0.0.0/8'],
            'ssh': {}, 'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'},
            'capabilities': [], 'ambientCapabilities': [], 'helpers': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'fileRestore': False},
            'sudo': [], 'mountsDir': '/run/xo', 'installer': {
                'ssh': {'PasswordAuthentication': False, 'AuthorizedKeysFile': '/run/maestro-bootstrap/authorized_keys'},
                'firewall': {'allowedTCPPorts': [], 'allowedUDPPorts': [], 'extraCommands': 'management-only SSH'},
                'sudo': {'enable': True, 'wheelNeedsPassword': False, 'extraRules': []},
                'operator': {'extraGroups': ['wheel'], 'passwordState': 'locked', 'rootPasswordState': 'empty', 'mutableUsers': True},
                'systemdInitrd': True, 'bootModes': {'bios': True, 'efi': True, 'memtest': True},
                'bootPolicy': {'kernelParams': ['console=hvc0'], 'emergencyMode': True, 'initrdEmergencyAccess': 'disabled'}}}


class InstallerContext(unittest.TestCase):
    def test_schema_one_and_package_only_remain_supported(self):
        value = context()
        value.pop('installer')
        value['schema'] = 1
        self.assertEqual(core.validate_context(value), value)
        self.assertEqual(core.compare_context(None, None), (False, False))

    def test_known_installer_policy_cannot_disappear(self):
        old = context()
        current = deepcopy(old)
        current.pop('installer')
        current['schema'] = 1
        with self.assertRaisesRegex(core.TechnicalError, 'installer security context disappeared'):
            core.compare_context(current, old)
        self.assertEqual(core.compare_context(old, current), (True, False))

    def test_every_installer_policy_change_requires_review(self):
        old = context()
        self.assertEqual(core.compare_context(deepcopy(old), old), (False, False))
        for field, change in [('ssh', {'PasswordAuthentication': True}),
                              ('operator', {**old['installer']['operator'], 'passwordState': 'empty'}),
                              ('bootPolicy', {**old['installer']['bootPolicy'], 'initrdEmergencyAccess': 'unauthenticated'}),
                              ('bootModes', {'bios': True, 'efi': False, 'memtest': True})]:
            current = deepcopy(old)
            current['installer'][field] = change
            self.assertEqual(core.compare_context(current, old), (True, False))

    def test_invalid_policy_shape_is_technical_failure(self):
        for change in [{'schema': 3}, {'installer': {}}, {'unexpected': True}]:
            with self.assertRaises(core.TechnicalError):
                core.validate_context({**context(), **change})


if __name__ == '__main__':
    unittest.main()
