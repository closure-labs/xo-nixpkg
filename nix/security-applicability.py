#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revalidate narrowly reviewed security decisions against immutable inventory.

This evaluator does not infer absence of an attack surface from an operating
system name. A decision needs exact advisory, source, runtime and code guards.
Unknown or changed evidence remains visible in report mode.
"""
import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

HEX = re.compile(r"[0-9a-f]{64}\Z")
STORE = re.compile(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/]+\Z")
SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"}
IDENTITY = {"advisory", "component", "version", "severity", "identity"}
RULE_KEYS = {"id", "advisory", "component", "version", "severity", "kind", "owner",
             "reason", "evidence", "created", "expires", "binding", "context", "files"}
NATIVE_KEYS = {"advisory_digest", "purl", "derivation", "derivation_digest", "source",
               "patches", "output_path"}
NPM_KEYS = {"advisory_digest", "purl", "hashes", "manifest_path"}
# Package or platform identity establishes what was scanned, not which
# deployment feature is disabled. Not-affected decisions need a runtime fact.
STANDALONE_CONTEXT_GUARDS = {"xoPackage", "runtime.xoPackage", "channel", "sourceRevision"}
IDENTITY_CONTEXT = {"xoPackage", "platform", "system", "os", "architecture", "arch",
                    "scope", "channel", "sourceRevision", "source", "version", "purl",
                    "package", "packageRoot", "name", "schemaVersion"}


def runtime_guard(path):
    parts = path.split(".")
    return len(parts) > 1 and parts[0] == "runtime" and parts[1] not in IDENTITY_CONTEXT


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def loads(value):
    return json.loads(value, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")))


def shared_native(record):
    values = record.get("properties", [])
    if not isinstance(values, list):
        return False
    marker = [item for item in values if isinstance(item, dict)
              and item.get("name") == "xo-nixpkg:sharedNative"]
    return (isinstance(record.get("bom-ref"), str)
            and record["bom-ref"].startswith("shared-native:")
            and marker == [{"name": "xo-nixpkg:sharedNative", "value": "true"}])


def properties(record):
    result = {}
    values = record.get("properties", [])
    require(isinstance(values, list), "invalid inventory properties")
    multiple = {"xo-nixpkg:installedPath", "nix:derivation"} if shared_native(record) else set()
    for item in values:
        require(isinstance(item, dict) and isinstance(item.get("name"), str)
                and isinstance(item.get("value"), str), "invalid inventory property")
        # sbomnix emits one nix:output_path per output of a derivation.
        # Provenance and runtime properties remain single-valued.
        require(item["name"] not in result or item["name"] == "nix:output_path" or item["name"] in multiple,
                "duplicate inventory property")
        if item["name"] in multiple:
            entries = result.setdefault(item["name"], [])
            require(item["value"] not in entries, "duplicate native exposure value")
            entries.append(item["value"])
        else:
            result[item["name"]] = item["value"]
    for name in multiple & result.keys():
        result[name] = sorted(result[name])
    return result


def output_paths(component):
    properties(component)  # Validate duplicates and property structure first.
    return [item["value"] for item in component.get("properties", [])
            if item["name"] in {"nix:storePath", "nix:output_path"}]


def hashes(component):
    values = component.get("hashes", [])
    require(isinstance(values, list), "invalid component hashes")
    seen = set()
    for item in values:
        require(isinstance(item, dict) and set(item) == {"alg", "content"}
                and isinstance(item["alg"], str) and isinstance(item["content"], str), "invalid component hash")
        require(item["alg"] not in seen, "duplicate component hash algorithm")
        seen.add(item["alg"])
        if item["alg"] == "SHA-256":
            require(HEX.fullmatch(item["content"]) is not None, "invalid SHA-256")
    return values


def nested(value, key):
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def store_root(value, store_dir):
    if not isinstance(value, str):
        return False
    if store_dir == Path("/nix/store"):
        return STORE.fullmatch(value) is not None
    path = Path(value)
    return path.is_absolute() and path.parent == store_dir and ".." not in path.parts


def guarded_path(value, root):
    """Require lexical and resolved containment: symlinks cannot widen proof scope."""
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        return False
    try:
        path.relative_to(root)
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return path.is_file()
    except (OSError, ValueError):
        return False


def validate_rules(document):
    require(isinstance(document, dict) and set(document) == {"schema_version", "rules"}
            and type(document["schema_version"]) is int and document["schema_version"] == 1
            and isinstance(document["rules"], list), "invalid applicability rules schema")
    ids = set()
    for rule in document["rules"]:
        require(isinstance(rule, dict) and set(rule) == RULE_KEYS, "invalid applicability rule fields")
        require(all(isinstance(rule[key], str) and rule[key].strip() for key in
                    ["id", "advisory", "component", "version", "owner", "reason"]), "missing rule identity or review")
        require(rule["id"] not in ids, "duplicate applicability rule ID")
        ids.add(rule["id"])
        require(rule["severity"] == "critical" and rule["kind"] in {"fixed", "not_affected"}, "invalid rule severity/kind")
        require(isinstance(rule["evidence"], list) and rule["evidence"]
                and all(isinstance(url, str) and urlsplit(url).scheme == "https" and urlsplit(url).netloc
                        for url in rule["evidence"]), "missing HTTPS review evidence")
        created, expires = date.fromisoformat(rule["created"]), date.fromisoformat(rule["expires"])
        require(0 < (expires - created).days <= 30, "rule must expire within 30 days")
        binding = rule["binding"]
        require(isinstance(binding, dict) and isinstance(binding.get("purl"), str), "missing rule source binding")
        npm = binding["purl"].startswith("pkg:npm/")
        required = NPM_KEYS if npm else NATIVE_KEYS
        require(required <= set(binding), "incomplete exact source binding")
        require(HEX.fullmatch(str(binding.get("advisory_digest"))) is not None, "invalid advisory digest")
        if "runtime_context" in binding:
            require(HEX.fullmatch(str(binding["runtime_context"])) is not None, "invalid runtime context digest")
        if not npm:
            require(binding["purl"].startswith("pkg:nix/"), "unsupported applicability component ecosystem")
            require(HEX.fullmatch(str(binding.get("derivation_digest"))) is not None
                    and isinstance(binding.get("derivation"), str) and binding["derivation"].endswith(".drv")
                    and isinstance(binding.get("output_path"), str), "incomplete native derivation identity")
            require(STORE.fullmatch(binding["output_path"]) is not None
                    and STORE.fullmatch(binding["derivation"]) is not None, "invalid native immutable store identity")
            require(isinstance(binding["source"], str) and isinstance(binding["patches"], str), "invalid native source evidence")
            source, patches = loads(binding["source"]), loads(binding["patches"])
            require(source is None or isinstance(source, str), "invalid native source")
            require(isinstance(patches, list), "invalid native patches")
            for patch in patches:
                require(isinstance(patch, dict) and set(patch) == {"path", "sha256"}
                        and isinstance(patch["path"], str) and HEX.fullmatch(str(patch["sha256"])), "invalid patch evidence")
        else:
            require(isinstance(binding["manifest_path"], str) and binding["manifest_path"].endswith("/package.json"), "invalid manifest binding")
            require(any(item["alg"] == "SHA-256" for item in hashes({"hashes": binding["hashes"]})), "missing manifest SHA-256")
        require(isinstance(rule["context"], dict), "invalid runtime applicability guards")
        if rule["kind"] == "not_affected":
            require(any(isinstance(key, str) and runtime_guard(key) for key in rule["context"]),
                    "not-affected rules require runtime guards beyond package/platform identity")
        require(all(isinstance(key, str) and all(part for part in key.split(".")) for key in rule["context"]), "invalid runtime guard path")
        if npm:
            require("xoPackage" in rule["context"] or "runtime.xoPackage" in rule["context"],
                    "missing immutable XO root guard")
        require(isinstance(rule["files"], list) and (rule["files"] or not npm), "missing npm code guards")
        if npm:
            require(any(isinstance(item, dict) and item.get("path") != binding["manifest_path"]
                        for item in rule["files"]), "npm decisions require explicit code beyond package metadata")
        paths = set()
        for item in rule["files"]:
            require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                    and isinstance(item["path"], str) and HEX.fullmatch(str(item["sha256"])), "invalid code guard")
            require(item["path"] not in paths, "duplicate code guard")
            paths.add(item["path"])
    return document["rules"]


def inventory_context(inventory, context, store_dir):
    require(isinstance(inventory, dict) and inventory.get("bomFormat") == "CycloneDX"
            and isinstance(inventory.get("components"), list) and inventory["components"], "invalid or empty CycloneDX inventory")
    props = properties(inventory)
    components = {}
    for component in inventory["components"]:
        require(isinstance(component, dict) and isinstance(component.get("bom-ref"), str)
                and component["bom-ref"] and isinstance(component.get("name"), str), "invalid inventory component")
        require(component["bom-ref"] not in components, "duplicate inventory component identity")
        properties(component)
        require(all(store_root(output, store_dir) or STORE.fullmatch(output) is not None
                    for output in output_paths(component)), "invalid component immutable output")
        hashes(component)
        components[component["bom-ref"]] = component
    if "maestro:runtimeContext" in props:
        require(props.get("maestro:inventoryVersion") == "2", "unsupported runtime inventory version")
        actual = loads(props["maestro:runtimeContext"])
        require(isinstance(actual, dict) and type(actual.get("schemaVersion")) is int
                and actual["schemaVersion"] == 2
                and props.get("maestro:runtimeContextDigest") == digest(actual), "invalid embedded runtime context")
        require(context is None or context == actual, "caller context differs from embedded runtime context")
    else:
        actual = context or {}
        require(isinstance(actual, dict), "invalid caller context")
    root_component = inventory.get("metadata", {}).get("component")
    require(isinstance(root_component, dict) and root_component.get("bom-ref"), "missing inventory root")
    root_props = properties(root_component)
    root_path = root_props.get("nix:storePath", root_props.get("nix:output_path"))
    if "maestro:runtimeContext" not in props:
        # A supply inventory describes a package, not a deployed NixOS runtime.
        # Callers may add deployment facts, but cannot substitute its package root.
        if root_component.get("name") == "xen-orchestra-ce" and root_path:
            require("xoPackage" not in actual or actual["xoPackage"] == root_path, "caller XO root differs from inventory")
            actual = {**actual, "xoPackage": root_path}
        else:
            require("xoPackage" not in actual, "unbound caller XO root")
    runtime_root_known, runtime_root = nested(actual, "runtime.xoPackage")
    flat_root = actual.get("xoPackage")
    require(not runtime_root_known or flat_root is None or flat_root == runtime_root,
            "conflicting runtime XO roots")
    xo_root = runtime_root if runtime_root_known else flat_root
    if "maestro:runtimeContext" not in props:
        for key in ["channel", "sourceRevision"]:
            observed = props.get("xo-nixpkg:" + key)
            if key in actual:
                require(observed is not None and actual[key] == observed, "caller package identity differs from inventory")
    require(xo_root is None or store_root(xo_root, store_dir), "XO root is not an immutable store output")
    if xo_root is not None:
        require(any(component.get("name") == "xen-orchestra-ce"
                    and xo_root in output_paths(component)
                    for component in components.values()), "runtime XO root is absent from inventory")
    return components, actual, Path(xo_root) if xo_root else None


def verify_finding(record, components, context):
    require(isinstance(record, dict) and all(isinstance(record.get(key), str) and record[key] for key in IDENTITY), "invalid finding identity")
    require(record["severity"] in SEVERITIES and HEX.fullmatch(record["identity"]), "invalid finding severity/digest")
    binding = record.get("binding")
    require(isinstance(binding, dict) and digest(binding) == record["identity"], "finding identity does not bind its evidence")
    component = components.get(binding.get("component_ref"))
    require(component is not None, "finding component is absent from inventory")
    require(record["component"] == component["name"] and record["version"] == component.get("version")
            and binding.get("purl") == component.get("purl"), "finding package differs from inventory")
    props = properties(component)
    if shared_native(component):
        output = props.get("nix:storePath")
        installed = props.get("xo-nixpkg:installedPath", [])
        derivations = props.get("nix:derivation", [])
        require(isinstance(output, str) and STORE.fullmatch(output) and installed
                and all((path == output or path.startswith(output + "/"))
                        and str(Path(path)) == path and ".." not in Path(path).parts
                        for path in installed), "invalid shared native file exposure")
        require(derivations and all(STORE.fullmatch(path) and path.endswith(".drv")
                                   for path in derivations), "invalid shared native derivations")
        require(binding.get("normalizer") == "shared-native-v1"
                and binding.get("installed_paths") == installed
                and binding.get("native_derivations") == derivations,
                "finding shared native exposure differs from inventory")
    else:
        require(binding.get("normalizer") != "shared-native-v1"
                and "installed_paths" not in binding and "native_derivations" not in binding,
                "unexpected shared native exposure binding")
    expected = {
        "output_path": props.get("nix:storePath", props.get("nix:output_path")),
        "derivation": props.get("maestro:derivation", props.get("xo-nixpkg:derivation")),
        "derivation_digest": props.get("maestro:derivationDigest", props.get("xo-nixpkg:derivationDigest")),
        "source": props.get("maestro:source", props.get("xo-nixpkg:source")),
        "patches": props.get("maestro:patches", props.get("xo-nixpkg:patches")),
        "hashes": hashes(component),
        "manifest_path": props.get("xo-nixpkg:manifestPath"),
    }
    for key, value in expected.items():
        if key == "output_path" and output_paths(component):
            require(binding.get(key) in output_paths(component), "finding output_path differs from inventory")
        else:
            require(binding.get(key) == value, f"finding {key} differs from inventory")
    require(binding.get("runtime_context") == digest(context), "finding runtime context differs from inventory")
    require(HEX.fullmatch(str(binding.get("advisory_digest"))) is not None, "missing advisory identity")
    return component


def assess(findings, inventory, rules, context=None, today=None, *, store_dir=Path("/nix/store")):
    """Return original findings and exact dispositions; store_dir is a fixture seam."""
    today = today or date.today()
    reviewed = validate_rules(rules)
    components, actual_context, xo_root = inventory_context(inventory, context, Path(store_dir))
    embedded_runtime = "maestro:runtimeContext" in properties(inventory)
    require(isinstance(findings, list), "invalid findings list")
    results, dispositions, seen = [], [], set()
    for finding in findings:
        verify_finding(finding, components, actual_context)
        key = tuple(finding[field] for field in sorted(IDENTITY))
        require(key not in seen, "duplicate finding instance")
        seen.add(key)
        matching = [rule for rule in reviewed if all(rule[field] == finding[field]
                    for field in ["advisory", "component", "version", "severity"])
                    and all(field in finding["binding"] and finding["binding"][field] == value
                            for field, value in rule["binding"].items())]
        require(len(matching) <= 1, "ambiguous applicability rules for exact finding")
        result = {"finding": finding, "classification": "unresolved", "rule_id": None,
                  "reason": "No exact reviewed applicability rule matches this finding."}
        if matching:
            rule = matching[0]
            result["rule_id"] = rule["id"]
            problems = []
            if any(path not in STANDALONE_CONTEXT_GUARDS for path in rule["context"]) and not embedded_runtime:
                problems.append("Runtime applicability is not verified by an embedded deployment context; caller facts cannot establish applicability.")
            if not date.fromisoformat(rule["created"]) <= today < date.fromisoformat(rule["expires"]):
                problems.append("Review is expired or not yet valid.")
            for path, value in rule["context"].items():
                known, observed = nested(actual_context, path)
                if not known or observed != value:
                    problems.append(f"Runtime guard differs or is unknown: {path}.")
            guards = list(rule["files"])
            if finding["binding"]["purl"].startswith("pkg:npm/"):
                manifest = finding["binding"]["manifest_path"]
                sha = next(item["content"] for item in finding["binding"]["hashes"] if item["alg"] == "SHA-256")
                guards.append({"path": manifest, "sha256": sha})
            for guard in guards:
                path = Path(guard["path"])
                if xo_root is None or not guarded_path(guard["path"], xo_root):
                    problems.append(f"Code guard is absent or outside the immutable XO package: {path}.")
                    continue
                try:
                    if hashlib.sha256(path.read_bytes()).hexdigest() != guard["sha256"]:
                        problems.append(f"Code guard hash differs: {path}.")
                    if path.name == "package.json" and str(path) == finding["binding"].get("manifest_path"):
                        manifest = loads(path.read_text())
                        if manifest.get("name") != finding["component"] or manifest.get("version") != finding["version"]:
                            problems.append("Installed manifest package identity differs.")
                except (OSError, ValueError, AttributeError):
                    problems.append(f"Code guard could not be read: {path}.")
            if problems:
                result["reason"] = " ".join(problems)
            else:
                result["classification"] = rule["kind"]
                result["reason"] = rule["reason"]
                dispositions.append({**{field: finding[field] for field in IDENTITY},
                                     **{field: rule[field] for field in
                                        ["kind", "owner", "reason", "evidence", "created", "expires"]}})
        results.append(result)
    unresolved = [result["finding"] for result in results
                  if result["classification"] == "unresolved" and result["finding"]["severity"] == "critical"]
    return {"schema_version": 1, "date": today.isoformat(), "context_digest": digest(actual_context),
            "inventory_digest": digest(inventory), "rules_digest": digest(rules),
            "evaluator_digest": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "results": results, "dispositions": dispositions, "unresolved_critical": unresolved}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["findings", "inventory", "rules", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--mode", choices=["report", "enforce"], default="report")
    args = parser.parse_args()
    try:
        report = assess(loads(args.findings.read_text()), loads(args.inventory.read_text()),
                        loads(args.rules.read_text()), loads(args.context.read_text()) if args.context else None)
        report["mode"] = args.mode
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        return int(args.mode == "enforce" and bool(report["unresolved_critical"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid applicability evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
