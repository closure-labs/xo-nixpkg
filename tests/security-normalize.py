# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location("normalize", Path(__file__).parents[1] / "nix/security-normalize.py")
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


def supply(directory, channel="latest"):
    directory = Path(directory)
    directory.mkdir(exist_ok=True)
    root = "/nix/store/" + "a" * 32 + "-xen-orchestra-ce-6.9.1"
    expected = {"root": root, "channel": channel, "sourceRev": "a" * 40, "version": "6.9.1"}
    package = {"name": "xen-orchestra-ce", "version": "6.9.1", "type": "application", "bom-ref": "nix:root",
               "purl": "pkg:nix/xen-orchestra-ce@6.9.1", "properties": [{"name": "nix:storePath", "value": root}]}
    components = [package, {"name": "openssl", "version": "1.0.1", "type": "library", "bom-ref": "nix:native",
                            "purl": "pkg:nix/openssl@1.0.1", "properties": [{"name": "nix:storePath", "value": "/nix/store/" + "b" * 32 + "-openssl-1.0.1"}]},
                  {"name": "lodash", "version": "4.17.15", "type": "library", "bom-ref": "npm:lodash",
                   "purl": "pkg:npm/lodash@4.17.15", "hashes": [{"alg": "SHA-256", "content": "c" * 64}],
                   "properties": [{"name": "xo-nixpkg:manifestPath", "value": root + "/libexec/xen-orchestra/node_modules/lodash/package.json"}]}]
    inventory = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": package},
                 "components": components, "dependencies": [{"ref": "nix:root", "dependsOn": ["nix:native", "npm:lodash"]}],
                 "properties": [{"name": "xo-nixpkg:inventoryVersion", "value": "2"},
                                {"name": "xo-nixpkg:channel", "value": channel},
                                {"name": "xo-nixpkg:sourceRevision", "value": expected["sourceRev"]}]}
    (directory / "closure.graph").write_text(root + "\n\n0\n")
    (directory / "xen-orchestra.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
    (directory / "xen-orchestra.cdx.json").write_text(json.dumps(inventory))
    documents = {name: {"path": name, "sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest()}
                 for name in ["closure.graph", "xen-orchestra.spdx.json", "xen-orchestra.cdx.json"]}
    (directory / "SHA256SUMS").write_text("".join(f"{record['sha256']}  {name}\n" for name, record in documents.items()))
    assertion = {"schemaVersion": 1, "predicateType": "https://github.com/closure-labs/xo-nixpkg/supply-protector/v1",
                 "subject": {"name": "xen-orchestra-ce", "channel": channel, "version": "6.9.1",
                             "sourceRevision": expected["sourceRev"], "storePath": root, "storeHash": "a" * 32},
                 "closure": {"graph": documents["closure.graph"]},
                 "documents": {"spdx": documents["xen-orchestra.spdx.json"], "cyclonedx": documents["xen-orchestra.cdx.json"]}}
    (directory / "assertion.json").write_text(json.dumps(assertion))
    return expected, inventory


def report(inventory):
    return {"matches": [{"artifact": {"id": component["bom-ref"], "name": component["name"],
                                      "version": component["version"], "purl": component["purl"]},
                         "vulnerability": {"id": "GHSA-fixture-" + component["name"], "severity": "Critical",
                                           "namespace": "fixture", "urls": ["https://example.invalid/advisory"]},
                         "matchDetails": [{"type": "exact-direct-match"}]}
                        for component in inventory["components"][1:]]}


def reject(call):
    try:
        call()
    except (ValueError, KeyError):
        return
    raise AssertionError("accepted invalid scanner or inventory evidence")


def main():
    with tempfile.TemporaryDirectory() as temporary:
        expected, inventory = supply(temporary)
        context = normalizer.verify_supply(temporary, expected)
        assert context["profiles"]["scope"] == "package"
        raw = report(inventory)
        findings = normalizer.normalize(raw, inventory, {"version": "fixture"}, context)
        assert len(findings) == 2
        native = next(f for f in findings if f["component"] == "openssl")
        assert native["binding"]["derivation"] is None and native["binding"]["source"] is None
        npm = next(f for f in findings if f["component"] == "lodash")
        assert npm["binding"]["manifest_path"].endswith("/lodash/package.json")
        assert native["severity"] == "critical" and npm["severity"] == "critical"
        assert all(f["identity"] == normalizer.digest(f["binding"]) for f in findings)
        fallback = deepcopy(raw)
        fallback["matches"][0]["artifact"]["id"] = "scanner-generated"
        assert normalizer.normalize(fallback, inventory, {}, context)
        ambiguous = deepcopy(inventory)
        ambiguous["components"].append({**inventory["components"][1], "bom-ref": "another-native"})
        reject(lambda: normalizer.normalize(fallback, ambiguous, {}, context))
        inconsistent = deepcopy(raw)
        inconsistent["matches"][0]["artifact"]["version"] = "wrong"
        reject(lambda: normalizer.normalize(inconsistent, inventory, {}, context))
        absent = deepcopy(raw)
        absent["matches"][0]["artifact"]["id"] = "absent"
        absent["matches"][0]["artifact"]["purl"] = "pkg:nix/unknown@1"
        reject(lambda: normalizer.normalize(absent, inventory, {}, context))
        reject(lambda: normalizer.normalize({"matches": None}, inventory, {}, context))
        changed = deepcopy(expected)
        changed["channel"] = "stable"
        reject(lambda: normalizer.verify_supply(temporary, changed))
        assertion_path = Path(temporary) / "assertion.json"
        assertion = normalizer.read(assertion_path)
        assertion["documents"]["cyclonedx"]["sha256"] = "0" * 64
        assertion_path.write_text(json.dumps(assertion))
        reject(lambda: normalizer.verify_supply(temporary, expected))
        supply(temporary)
        checksum = Path(temporary) / "SHA256SUMS"
        checksum.write_text(checksum.read_text() + "0" * 64 + "  ../../etc/passwd\n")
        reject(lambda: normalizer.verify_supply(temporary, expected))
        supply(temporary)
        (Path(temporary) / "xen-orchestra.cdx.json").write_text("tampered")
        reject(lambda: normalizer.verify_supply(temporary, expected))
        duplicate = Path(temporary) / "duplicate.json"
        duplicate.write_text('{"matches":[],"matches":[{}]}')
        reject(lambda: normalizer.read(duplicate))
    print("Security supply binding and normalization fixtures passed")


if __name__ == "__main__":
    main()
