# SPDX-License-Identifier: Apache-2.0
"""Source, advisory, context and filesystem drift must reopen critical findings."""
from copy import deepcopy
from datetime import date, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("applicability", Path(__file__).parents[1] / "nix/security-applicability.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
TODAY = date(2026, 10, 14)


def rejected(function):
    try:
        function()
    except (ValueError, TypeError):
        return
    raise AssertionError("accepted malformed or ambiguous evidence")


def refresh(finding):
    finding["identity"] = engine.digest(finding["binding"])


with tempfile.TemporaryDirectory() as temporary:
    store = Path(temporary) / "store"
    root = store / ("a" * 32 + "-xen-orchestra-ce")
    module = root / "libexec/xen-orchestra/node_modules/example"
    module.mkdir(parents=True)
    manifest = module / "package.json"
    manifest.write_text('{"name":"example","version":"1.0.0"}')
    code = module / "index.js"
    code.write_text("export const vulnerableFeature = false;\n")
    manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    context = {"schemaVersion": 2, "xoPackage": str(root), "runtime": {"xo": {"feature": False}}}
    component = {"bom-ref": "npm:example", "name": "example", "version": "1.0.0", "purl": "pkg:npm/example@1.0.0",
                 "hashes": [{"alg": "SHA-256", "content": manifest_hash}],
                 "properties": [{"name": "xo-nixpkg:manifestPath", "value": str(manifest)}]}
    xo = {"bom-ref": "nix:xo", "name": "xen-orchestra-ce", "version": "1.0.0", "purl": "pkg:nix/xen-orchestra-ce@1.0.0",
          "properties": [{"name": "nix:storePath", "value": str(root)}]}
    inventory = {"bomFormat": "CycloneDX", "metadata": {"component": xo}, "components": [xo, component],
                 "properties": [{"name": "maestro:inventoryVersion", "value": "2"},
                                {"name": "maestro:runtimeContext", "value": json.dumps(context)},
                                {"name": "maestro:runtimeContextDigest", "value": engine.digest(context)}]}
    binding = {"component_ref": "npm:example", "purl": component["purl"], "manifest_path": str(manifest),
               "hashes": component["hashes"], "output_path": None, "derivation": None, "derivation_digest": None,
               "source": None, "patches": None, "runtime_context": engine.digest(context), "advisory_digest": "b" * 64}
    finding = {"advisory": "CVE-2026-0001", "component": "example", "version": "1.0.0", "severity": "critical", "binding": binding}
    refresh(finding)
    rule = {"id": "example-disabled", **{key: finding[key] for key in ["advisory", "component", "version", "severity"]},
            "kind": "not_affected", "owner": "security", "reason": "Reviewed immutable code excludes the vulnerable feature.",
            "evidence": ["https://example.org/security/CVE-2026-0001"], "created": "2026-10-14", "expires": "2026-11-13",
            "binding": {key: binding[key] for key in engine.NPM_KEYS},
            "context": {"xoPackage": str(root), "runtime.xo.feature": False},
            "files": [{"path": str(code), "sha256": hashlib.sha256(code.read_bytes()).hexdigest()}]}
    rules = {"schema_version": 1, "rules": [rule]}

    def run(f=finding, i=inventory, r=rules, c=None, day=TODAY):
        return engine.assess([f], i, r, c, day, store_dir=store)

    result = run()
    assert result["results"][0]["classification"] == "not_affected"
    assert result["results"][0]["finding"] == finding and result["dispositions"][0]["identity"] == finding["identity"]
    assert not result["unresolved_critical"]
    assert result["inventory_digest"] == engine.digest(inventory)
    assert result["rules_digest"] == engine.digest(rules)
    assert result["evaluator_digest"] == hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest()
    # Maestro embeds the actual package under runtime.xoPackage. Resolving
    # this guard must preserve the exact signed context digest and identity.
    maestro_context = {"schemaVersion": 2, "runtime": {"xoPackage": str(root), "xo": {"feature": False}},
                       "profiles": {"scope": "appliance"}}
    maestro_inventory = deepcopy(inventory)
    maestro_inventory["properties"][1]["value"] = json.dumps(maestro_context)
    maestro_inventory["properties"][2]["value"] = engine.digest(maestro_context)
    maestro_finding = deepcopy(finding)
    maestro_finding["binding"]["runtime_context"] = engine.digest(maestro_context)
    refresh(maestro_finding)
    maestro_rules = deepcopy(rules)
    maestro_rules["rules"][0]["context"] = {"runtime.xoPackage": str(root), "runtime.xo.feature": False}
    maestro_result = run(f=maestro_finding, i=maestro_inventory, r=maestro_rules)
    assert maestro_result["results"][0]["classification"] == "not_affected"
    assert maestro_result["context_digest"] == engine.digest(maestro_context)
    mismatched_root = deepcopy(maestro_inventory)
    mismatched_root["components"][0]["properties"][0]["value"] = str(store / "wrong-root")
    rejected(lambda: run(f=maestro_finding, i=mismatched_root, r=maestro_rules))
    assert engine.STORE.fullmatch("/nix/store/" + "e" * 32 + "-invalid") is None
    assert engine.STORE.fullmatch("/nix/store/" + "g" * 32 + "-valid") is not None
    assert run(day=date(2026, 11, 13))["unresolved_critical"]
    assert run(day=date(2026, 10, 13))["unresolved_critical"]
    changed = deepcopy(finding)
    changed["binding"]["advisory_digest"] = "c" * 64
    refresh(changed)
    assert run(f=changed)["unresolved_critical"]
    changed["binding"]["manifest_path"] = str(root / "other/package.json")
    refresh(changed)
    rejected(lambda: run(f=changed))
    rejected(lambda: run(c={"schemaVersion": 2, "xoPackage": str(root), "runtime": {"xo": {"feature": True}}}))
    changed_inventory = deepcopy(inventory)
    new_context = {"schemaVersion": 2, "xoPackage": str(root), "runtime": {"xo": {"feature": True}}}
    changed_inventory["properties"][1]["value"] = json.dumps(new_context)
    changed_inventory["properties"][2]["value"] = engine.digest(new_context)
    changed = deepcopy(finding)
    changed["binding"]["runtime_context"] = engine.digest(new_context)
    refresh(changed)
    assert run(f=changed, i=changed_inventory)["unresolved_critical"]
    code.write_text("export const vulnerableFeature = true;\n")
    assert run()["unresolved_critical"]
    code.unlink()
    assert run()["unresolved_critical"]
    outside = Path(temporary) / "outside.js"
    outside.write_text("outside")
    code.symlink_to(outside)
    escape = deepcopy(rules)
    escape["rules"][0]["files"][0]["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    assert run(r=escape)["unresolved_critical"]
    code.unlink()
    code.write_text("export const vulnerableFeature = false;\n")
    escape["rules"][0]["files"][0]["path"] = str(root) + "/../outside.js"
    assert run(r=escape)["unresolved_critical"]
    manifest.write_text('{"name":"other","version":"1.0.0"}')
    assert run()["unresolved_critical"]
    # Even a self-consistent rewritten hash cannot certify the wrong package name.
    changed_inventory = deepcopy(inventory)
    changed_inventory["components"][1]["hashes"][0]["content"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    changed = deepcopy(finding)
    changed["binding"]["hashes"] = changed_inventory["components"][1]["hashes"]
    refresh(changed)
    changed_rules = deepcopy(rules)
    changed_rules["rules"][0]["binding"]["hashes"] = changed["binding"]["hashes"]
    assert run(f=changed, i=changed_inventory, r=changed_rules)["unresolved_critical"]
    manifest.write_text('{"name":"example","version":"1.0.0"}')
    rejected(lambda: engine.loads('{"a":1,"a":2}'))
    rejected(lambda: engine.loads('{}\n{}'))
    rejected(lambda: engine.loads('{"a":NaN}'))
    rejected(lambda: engine.assess([finding, finding], inventory, rules, today=TODAY, store_dir=store))
    duplicate = deepcopy(inventory)
    duplicate["components"].append(component)
    rejected(lambda: run(i=duplicate))
    duplicate = deepcopy(inventory)
    duplicate["components"][1]["properties"].append(component["properties"][0])
    rejected(lambda: run(i=duplicate))
    rejected(lambda: run(r={"schema_version": 1, "rules": [rule, rule]}))
    ambiguous = deepcopy(rule)
    ambiguous["id"] = "another-review"
    rejected(lambda: run(r={"schema_version": 1, "rules": [rule, ambiguous]}))
    incomplete = deepcopy(rules)
    del incomplete["rules"][0]["binding"]["advisory_digest"]
    rejected(lambda: run(r=incomplete))
    incomplete = deepcopy(rules)
    incomplete["rules"][0]["files"] = [{"path": str(manifest), "sha256": manifest_hash}]
    rejected(lambda: run(r=incomplete))
    too_long = deepcopy(rules)
    too_long["rules"][0]["expires"] = "2026-12-14"
    rejected(lambda: run(r=too_long))
    # Standalone supply inventory binds its root; it does not assert deployment facts.
    standalone = deepcopy(inventory)
    standalone["properties"] = []
    standalone_context = {"xoPackage": str(root)}
    changed = deepcopy(finding)
    changed["binding"]["runtime_context"] = engine.digest(standalone_context)
    refresh(changed)
    assert run(f=changed, i=standalone)["unresolved_critical"]
    # Self-consistent caller facts do not become verified deployment evidence.
    forged_context = {"xoPackage": str(root), "runtime": {"xo": {"feature": False}}}
    forged_finding = deepcopy(finding)
    forged_finding["binding"]["runtime_context"] = engine.digest(forged_context)
    refresh(forged_finding)
    forged_result = run(f=forged_finding, i=standalone, c=forged_context)
    assert forged_result["unresolved_critical"]
    assert "caller facts" in forged_result["results"][0]["reason"]
    conditional_fix = deepcopy(rules)
    conditional_fix["rules"][0]["kind"] = "fixed"
    assert run(f=forged_finding, i=standalone, r=conditional_fix, c=forged_context)["unresolved_critical"]
    arbitrary_claim = {"xoPackage": str(root), "pluginsImmutable": True}
    arbitrary_finding = deepcopy(finding)
    arbitrary_finding["binding"]["runtime_context"] = engine.digest(arbitrary_claim)
    refresh(arbitrary_finding)
    arbitrary_rule = deepcopy(conditional_fix)
    arbitrary_rule["rules"][0]["context"] = {"xoPackage": str(root), "pluginsImmutable": True}
    assert run(f=arbitrary_finding, i=standalone, r=arbitrary_rule, c=arbitrary_claim)["unresolved_critical"]
    identity_only = deepcopy(rules)
    identity_only["rules"][0]["context"] = {"xoPackage": str(root), "platform": "x86_64-linux"}
    rejected(lambda: run(r=identity_only))
    identity_only["rules"][0]["context"] = {"runtime.xoPackage": str(root), "runtime.platform": "x86_64-linux"}
    rejected(lambda: run(r=identity_only))
    rejected(lambda: run(f=changed, i=standalone, c={"xoPackage": str(store / "wrong-root")}))
    # Native fixes bind exact reviewed producer metadata and are independent of feature config.
    native = {"bom-ref": "nix:perl", "name": "perl", "version": "5.42.3", "purl": "pkg:nix/perl@5.42.3",
              "properties": [{"name": "nix:storePath", "value": "/nix/store/" + "d" * 32 + "-perl-5.42.3"},
                             {"name": "maestro:derivation", "value": "/nix/store/" + "g" * 32 + "-perl.drv"},
                             {"name": "maestro:derivationDigest", "value": "f" * 64},
                             {"name": "maestro:source", "value": '"/nix/store/source-perl"'},
                             {"name": "maestro:patches", "value": "[]"}]}
    native_inventory = deepcopy(inventory)
    native_inventory["components"].append(native)
    props = engine.properties(native)
    nb = {"component_ref": native["bom-ref"], "purl": native["purl"], "output_path": props["nix:storePath"],
          "derivation": props["maestro:derivation"], "derivation_digest": props["maestro:derivationDigest"],
          "source": props["maestro:source"], "patches": "[]", "hashes": [], "manifest_path": None,
          "runtime_context": engine.digest(context), "advisory_digest": "b" * 64}
    nf = {**finding, "component": "perl", "version": "5.42.3", "binding": nb}
    refresh(nf)
    nr = {**deepcopy(rule), "id": "native-fix", "component": "perl", "version": "5.42.3", "kind": "fixed",
          "binding": {key: nb[key] for key in engine.NATIVE_KEYS}, "context": {}, "files": []}
    native_rules = {"schema_version": 1, "rules": [nr]}
    assert run(f=nf, i=native_inventory, r=native_rules)["results"][0]["classification"] == "fixed"
    multioutput = deepcopy(native_inventory)
    multioutput["components"][-1]["properties"].extend([
        {"name": "nix:output_path", "value": props["nix:storePath"]},
        {"name": "nix:output_path", "value": "/nix/store/" + "h" * 32 + "-perl-man"},
        {"name": "nix:output_path", "value": "/nix/store/" + "i" * 32 + "-perl-devdoc"}])
    assert run(f=nf, i=multioutput, r=native_rules)["results"][0]["classification"] == "fixed"
    contradictory = deepcopy(multioutput)
    contradictory["components"][-1]["properties"].append(
        {"name": "maestro:derivationDigest", "value": "a" * 64})
    rejected(lambda: run(f=nf, i=contradictory, r=native_rules))
    changed_native = deepcopy(nf)
    changed_native["binding"]["source"] = '"changed"'
    refresh(changed_native)
    rejected(lambda: run(f=changed_native, i=native_inventory, r=native_rules))
    native_inventory["components"][-1]["properties"][3]["value"] = '"changed"'
    assert run(f=changed_native, i=native_inventory, r=native_rules)["unresolved_critical"]
    # A valid public-CLI inventory can report unresolved native findings without
    # reading the fictional immutable output. Enforce mode changes only exit status.
    cli_inventory = deepcopy(native_inventory)
    cli_root = "/nix/store/" + "a" * 32 + "-xen-orchestra-ce"
    cli_context = {**context, "xoPackage": cli_root}
    cli_inventory["metadata"]["component"]["properties"][0]["value"] = cli_root
    cli_inventory["components"][0]["properties"][0]["value"] = cli_root
    cli_inventory["properties"][1]["value"] = json.dumps(cli_context)
    cli_inventory["properties"][2]["value"] = engine.digest(cli_context)
    cli_finding = deepcopy(changed_native)
    cli_finding["binding"]["runtime_context"] = engine.digest(cli_context)
    refresh(cli_finding)
    for name, document in [("findings", [cli_finding]), ("inventory", cli_inventory), ("rules", {"schema_version": 1, "rules": []})]:
        (Path(temporary) / (name + ".json")).write_text(json.dumps(document))
    args = [sys.executable, str(Path(__file__).parents[1] / "nix/security-applicability.py")]
    for name in ["findings", "inventory", "rules"]:
        args += ["--" + name, str(Path(temporary) / (name + ".json"))]
    args += ["--output", str(Path(temporary) / "report.json")]
    assert subprocess.run(args, capture_output=True).returncode == 0
    cli_report = json.loads((Path(temporary) / "report.json").read_text())
    assert cli_report["unresolved_critical"] == [cli_finding]
    assert cli_report["mode"] == "report"
    assert subprocess.run(args + ["--mode", "enforce"], capture_output=True).returncode == 1
    cli_rule = deepcopy(nr)
    cli_rule["created"] = date.today().isoformat()
    cli_rule["expires"] = (date.today() + timedelta(days=30)).isoformat()
    cli_rule["binding"]["source"] = cli_finding["binding"]["source"]
    (Path(temporary) / "rules.json").write_text(json.dumps({"schema_version": 1, "rules": [cli_rule]}))
    assert subprocess.run(args + ["--mode", "enforce"], capture_output=True).returncode == 0
    # Invalid scanner data is an error even in report mode.
    (Path(temporary) / "findings.json").write_text('{}\n{}')
    assert subprocess.run(args + ["--mode", "report"], capture_output=True).returncode == 2
print("Security applicability fixtures passed")
