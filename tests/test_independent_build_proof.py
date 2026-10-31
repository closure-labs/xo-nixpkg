"""Fast mocked guards. Full builds execute only on hosted runners."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("proof", Path(__file__).resolve().parents[1] / "nix/independent-build-proof.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
DRV = "/nix/store/" + "a" * 32 + "-dependency.drv"


class Guards(unittest.TestCase):
    def test_versioned_envelope_and_legacy_exact_path_map(self):
        output = DRV.removesuffix(".drv")
        description = {"version": 4, "outputs": {"out": {"path": output.removeprefix('/nix/store/')}},
                       "env": {"out": output, "doInstallCheck": "1"}}
        mapping = {DRV.removeprefix('/nix/store/'): description}
        self.assertEqual(proof.exact_derivation({"version": 4, "derivations": mapping}, DRV, output), description)
        self.assertEqual(proof.exact_derivation({DRV: description}, DRV, output), description)

    def test_wrong_version_identity_extra_derivation_or_output_rejected(self):
        output = DRV.removesuffix(".drv")
        description = {"version": 4, "outputs": {"out": {"path": output}},
                       "env": {"out": output, "doInstallCheck": "1"}}
        good = {"version": 4, "derivations": {DRV: description}}
        bad = [dict(good, version=5), dict(good, extra=True),
               dict(good, derivations={}), dict(good, derivations={DRV + "x": description}),
               dict(good, derivations={DRV: description, DRV + "x": description})]
        for field in ("outputs", "env"):
            changed = copy.deepcopy(good)
            if field == "outputs":
                changed["derivations"][DRV][field]["out"]["path"] = output + "x"
            else:
                changed["derivations"][DRV][field]["out"] = output + "x"
            bad.append(changed)
        for raw in bad:
            with self.assertRaises(ValueError):
                proof.exact_derivation(raw, DRV, output)

    def test_precise_input_output_selection_legacy_and_v4(self):
        expected = [DRV + "^dev", DRV + "^out"]
        self.assertEqual(proof.inputs({"inputDrvs": {DRV: ["dev", "out"]}}, set()), expected)
        self.assertEqual(proof.inputs({"version": 4, "inputs": {"drvs": {DRV.removeprefix('/nix/store/'): ["dev", "out"]}}}, set()), expected)
        self.assertEqual(proof.inputs({"version": 4, "inputs": {"drvs": {
            DRV.removeprefix('/nix/store/'): {"outputs": ["dev", "out"], "dynamicOutputs": {}}}}}, set()), expected)

    def test_roots_dynamic_and_unknown_inputs_rejected(self):
        for value, roots in [({"inputDrvs": {DRV: ["out"]}}, {DRV}),
                             ({"version": 5, "inputDrvs": {}}, set()),
                             ({"version": 4, "inputs": {"drvs": {DRV: {"dynamicOutputs": {}}}}}, set()),
                             ({"version": 4, "inputs": {"drvs": {DRV: {"outputs": ["out"], "dynamicOutputs": {"out": {}}}}}}, set()),
                             ({"inputDrvs": {DRV: ["out;echo"]}}, set())]:
            with self.assertRaises(ValueError):
                proof.inputs(value, roots)

    def test_existing_and_dangling_roots_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as name:
            file = Path(name) / "root"
            proof.absent([str(file)])
            file.symlink_to(Path(name) / "missing")
            with self.assertRaises(ValueError):
                proof.absent([str(file)])

    def receipt(self, leg):
        return {"schema": 1, "authorityClaim": False, "leg": leg,
                "revision": "a" * 40, "runId": "1", "runAttempt": "1", "nixVersion": "test",
                "bootId": ("a" if leg == "A" else "b") * 36, "serviceTest": leg == "A",
                "profiles": {p: {"drv": DRV, "output": DRV.removesuffix(".drv"),
                                 "narHash": "sha256-" + "a" * 43 + "=", "narSize": 10,
                                 "freshOfflineBuild": True, "installChecks": True} for p in proof.PROFILES}}

    def test_equal_independent_receipts(self):
        self.assertEqual(proof.compare(self.receipt("A"), self.receipt("B"))["status"], "matching-independent-builds")

    def test_same_host_attempt_input_hash_or_reuse_never_pass(self):
        original = self.receipt("B")
        for key, value in [("bootId", "a" * 36), ("runAttempt", "2"), ("revision", "b" * 40)]:
            second = copy.deepcopy(original)
            second[key] = value
            with self.assertRaises(ValueError):
                proof.compare(self.receipt("A"), second)
        for key, value in [("narHash", "sha256-" + "b" * 43 + "="), ("freshOfflineBuild", False)]:
            second = copy.deepcopy(original)
            second["profiles"]["latest"][key] = value
            with self.assertRaises(ValueError):
                proof.compare(self.receipt("A"), second)


if __name__ == "__main__":
    unittest.main()
