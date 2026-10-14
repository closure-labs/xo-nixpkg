#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind raw scanner matches to the installed XO inventory without hiding matches."""
import argparse
import hashlib
import json
from pathlib import Path
import re

STORE = re.compile(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+\Z")
SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def properties(record):
    values = record.get("properties", [])
    require(isinstance(values, list), "invalid inventory properties")
    result = {}
    for item in values:
        require(isinstance(item, dict) and isinstance(item.get("name"), str)
                and isinstance(item.get("value"), str) and item["name"] not in result,
                "invalid or duplicate inventory property")
        result[item["name"]] = item["value"]
    return result


def verify_supply(directory, expected):
    directory = Path(directory).resolve()
    require(isinstance(expected, dict) and set(expected) == {"root", "channel", "sourceRev", "version"}, "invalid expected package identity")
    require(expected["channel"] in {"latest", "stable", "rolling"} and
            isinstance(expected["root"], str) and STORE.fullmatch(expected["root"]) and
            re.fullmatch(r"[0-9a-f]{40}", expected["sourceRev"]) is not None and
            isinstance(expected["version"], str) and expected["version"], "invalid package identity")
    names = {"closure.graph", "xen-orchestra.spdx.json", "xen-orchestra.cdx.json"}
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None and match[2] in names and match[2] not in checksums, "invalid supply checksum inventory")
        checksums[match[2]] = match[1]
    require(set(checksums) == names, "incomplete supply checksum inventory")
    for name, checksum in checksums.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                "invalid supply document path")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == checksum, "supply checksum mismatch")
    assertion = read(directory / "assertion.json")
    subject = assertion["subject"]
    require(assertion["schemaVersion"] == 1 and
            assertion["predicateType"] == "https://github.com/closure-labs/xo-nixpkg/supply-protector/v1" and
            subject["name"] == "xen-orchestra-ce" and subject["channel"] == expected["channel"] and
            subject["version"] == expected["version"] and subject["sourceRevision"] == expected["sourceRev"] and
            subject["storePath"] == expected["root"] and
            subject["storeHash"] == Path(expected["root"]).name[:32], "supply assertion package identity mismatch")
    documents = {"closure.graph": assertion["closure"]["graph"],
                 "xen-orchestra.spdx.json": assertion["documents"]["spdx"],
                 "xen-orchestra.cdx.json": assertion["documents"]["cyclonedx"]}
    require(all(document["path"] == name and document["sha256"] == checksums[name]
                for name, document in documents.items()), "assertion document binding mismatch")
    sbom = read(directory / "xen-orchestra.cdx.json")
    require(sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5", "invalid CycloneDX inventory")
    root = sbom["metadata"]["component"]
    require(root["name"] == "xen-orchestra-ce" and root["version"] == expected["version"] and
            properties(root).get("nix:storePath") == expected["root"], "inventory root differs from asserted package")
    props = properties(sbom)
    require(props.get("xo-nixpkg:inventoryVersion") == "2" and
            props.get("xo-nixpkg:channel") == expected["channel"] and
            props.get("xo-nixpkg:sourceRevision") == expected["sourceRev"], "inventory source/channel binding mismatch")
    require(any(component == root for component in sbom["components"]), "inventory root component is missing or inconsistent")
    return {"platform": "x86_64-linux", "profiles": {"scope": "package"},
            "xoPackage": expected["root"], "channel": expected["channel"],
            "sourceRevision": expected["sourceRev"]}


def normalize(report, sbom, scanner_version, context):
    require(isinstance(report, dict) and isinstance(report.get("matches"), list), "invalid scanner report")
    require(isinstance(context, dict) and STORE.fullmatch(str(context.get("xoPackage", ""))), "missing immutable XO context")
    require(properties(sbom).get("xo-nixpkg:inventoryVersion") == "2", "incomplete installed inventory")
    components = {}
    for component in sbom["components"]:
        ref = component["bom-ref"]
        require(isinstance(ref, str) and ref and ref not in components, "invalid or duplicate inventory identity")
        components[ref] = component
    findings = {}
    for match in report["matches"]:
        artifact, vulnerability = match["artifact"], match["vulnerability"]
        component = components.get(artifact["id"])
        if component is None:
            candidates = [c for c in components.values() if artifact.get("purl") and
                          c.get("purl") == artifact["purl"] and c["name"] == artifact["name"] and
                          c.get("version") == artifact["version"]]
            require(len(candidates) == 1, "scanner match has ambiguous or absent immutable component identity")
            component = candidates[0]
        require(component["name"] == artifact["name"] and component.get("version") == artifact["version"] and
                (not artifact.get("purl") or component["purl"] == artifact["purl"]), "scanner artifact differs from inventory")
        props = properties(component)
        binding = {
            "component_ref": component["bom-ref"], "purl": component["purl"],
            "manifest_path": props.get("xo-nixpkg:manifestPath"),
            "output_path": props.get("nix:storePath", props.get("nix:output_path")),
            "derivation": props.get("maestro:derivation", props.get("xo-nixpkg:derivation")),
            "derivation_digest": props.get("maestro:derivationDigest", props.get("xo-nixpkg:derivationDigest")),
            "source": props.get("maestro:source", props.get("xo-nixpkg:source")),
            "patches": props.get("maestro:patches", props.get("xo-nixpkg:patches")),
            "hashes": component.get("hashes", []), "runtime_context": digest(context),
            "scanner": scanner_version, "normalizer": "1",
            "namespace": vulnerability["namespace"], "advisory_digest": digest(vulnerability),
            "match_digest": digest(match["matchDetails"]),
            "match_types": sorted({detail["type"] for detail in match["matchDetails"]}),
        }
        severity = vulnerability["severity"].lower()
        require(severity in SEVERITIES, "unsupported scanner severity")
        finding = {"advisory": vulnerability["id"], "component": component["name"],
                   "version": component["version"], "severity": severity, "scanner": "grype",
                   "identity": digest(binding), "binding": binding,
                   "evidence": {"parents": sorted(d["ref"] for d in sbom.get("dependencies", [])
                                                   if component["bom-ref"] in d.get("dependsOn", [])),
                                "urls": vulnerability.get("urls", [])}}
        findings[(finding["advisory"], finding["identity"], severity)] = finding
    return [findings[key] for key in sorted(findings)]


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("directory")
    verify.add_argument("expected")
    verify.add_argument("context")
    scan = commands.add_parser("normalize")
    for argument in ["report", "inventory", "scanner", "context", "output"]:
        scan.add_argument(argument)
    args = parser.parse_args()
    if args.command == "verify":
        result = verify_supply(args.directory, read(args.expected))
        output = args.context
    else:
        result = normalize(read(args.report), read(args.inventory), read(args.scanner), read(args.context))
        output = args.output
    Path(output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
