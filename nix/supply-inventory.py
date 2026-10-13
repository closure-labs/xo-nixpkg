#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory immutable Nix outputs and the complete installed JavaScript tree."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote


def identity(path):
    name = Path(path).name[33:]
    match = re.match(r"^(.+?)-([0-9].*)$", name)
    if not match:
        return name, None
    name, version = match.groups()
    version = re.sub(r"-(bin|dev|doc|info|man|lib|out|npm|corepack)$", "", version)
    # The slim output is the same Node interpreter, not a separate product.
    if name == "nodejs-slim":
        name = "nodejs"
    return name, version


def collect(root, source_rev):
    root = Path(root).resolve()
    root_manifest = json.loads((root / "package.json").read_text())
    workspaces = root_manifest.get("workspaces", [])
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages", [])
    workspace_dirs = {p.resolve() for pattern in workspaces for p in root.glob(pattern) if p.is_dir()}
    workspace_dirs.add(root)
    pending, seen, manifests, native = [root], set(), {}, []
    while pending:
        directory = pending.pop().resolve()
        stat = directory.stat()
        key = (stat.st_dev, stat.st_ino)
        if key in seen:
            continue
        seen.add(key)
        for entry in sorted(directory.iterdir()):
            if entry.name in {".git", ".cache"}:
                continue
            if entry.is_dir():
                pending.append(entry)
            elif entry.name == "package.json":
                parent = entry.parent
                module = parent.parent.name == "node_modules" or (
                    parent.parent.name.startswith("@") and parent.parent.parent.name == "node_modules")
                if not module and parent.resolve() not in workspace_dirs:
                    continue
                data = json.loads(entry.read_text())
                if not isinstance(data, dict):
                    raise ValueError(f"invalid package manifest: {entry}")
                name, version = data.get("name"), data.get("version")
                if not name:
                    raise ValueError(f"installed package lacks a name: {entry}")
                ref = "npm:" + hashlib.sha256(str(entry).encode()).hexdigest()
                workspace = entry.parent.resolve() in workspace_dirs
                if not version and not workspace:
                    raise ValueError(f"installed package lacks a version: {entry}")
                purl = ("pkg:npm/" + quote(name, safe="/") + "@" + quote(str(version), safe="")
                        if version else "pkg:github/vatesfr/xen-orchestra@" + source_rev
                        + "#" + quote(str(entry.parent.relative_to(root)), safe="/"))
                component = {
                    "type": "library", "name": name, "bom-ref": ref, "purl": purl,
                    "properties": [{"name": "xo-nixpkg:manifestPath", "value": str(entry)},
                                   {"name": "xo-nixpkg:sourceRevision", "value": source_rev}],
                    "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(entry.read_bytes()).hexdigest()}],
                }
                if version:
                    component["version"] = str(version)
                manifests[str(entry.parent.resolve())] = (component, data)
            elif entry.suffix == ".node" or ".so" in entry.name:
                native.append({"path": str(entry), "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()})
    components = [item[0] for item in manifests.values()]
    if not any(c["purl"].startswith("pkg:npm/") for c in components):
        raise ValueError("installed npm inventory is empty")
    dependencies = []
    for directory, (component, data) in manifests.items():
        refs = set()
        for name in set(data.get("dependencies", {})) | set(data.get("optionalDependencies", {})) | set(data.get("peerDependencies", {})):
            current = Path(directory)
            while True:
                target = (current / "node_modules" / name).resolve()
                if str(target) in manifests:
                    refs.add(manifests[str(target)][0]["bom-ref"])
                    break
                if current == root or current == current.parent:
                    break
                current = current.parent
        dependencies.append({"ref": component["bom-ref"], "dependsOn": sorted(refs)})
    return {"components": sorted(components, key=lambda c: c["bom-ref"]),
            "dependencies": sorted(dependencies, key=lambda c: c["ref"]),
            "nativeBinaries": sorted(native, key=lambda c: c["path"])}


def main():
    nodes_path, package, revision, output = sys.argv[1:]
    nodes = json.loads(Path(nodes_path).read_text())
    for node in nodes:
        name, version = identity(node["path"])
        if node["isRoot"]:
            name, version = "xen-orchestra-ce", os.environ["VERSION"]
        node.update(name=name, version=version,
                    purl="pkg:nix/" + quote(name, safe="") + ("@" + quote(version, safe="") if version else ""))
    Path(nodes_path).write_text(json.dumps(nodes, sort_keys=True))
    Path(output).write_text(json.dumps(collect(Path(package) / "libexec/xen-orchestra", revision), sort_keys=True))


if __name__ == "__main__":
    main()
