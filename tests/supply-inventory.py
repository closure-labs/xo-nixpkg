# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).parents[1] / "nix/supply-inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
assert inventory.identity("/nix/store/" + "a" * 32 + "-openssl-3.6.5-dev") == ("openssl", "3.6.5")
assert inventory.identity("/nix/store/" + "a" * 32 + "-nodejs-slim-22.23.2-npm") == ("nodejs", "22.23.2")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    for directory, data in {
        ".": {"name": "xo", "private": True, "workspaces": ["packages/*"]},
        "packages/xo-server": {"name": "xo-server", "dependencies": {"@scope/dep": "1.0.0"}},
        "node_modules/@scope/dep": {"name": "@scope/dep", "version": "1.0.0"},
        "node_modules/@scope/dep/test/example": {"name": "ignored-example"},
        "node_modules/nested": {"name": "nested", "version": "1.0.0"},
        "node_modules/nested/node_modules/@scope/dep": {"name": "@scope/dep", "version": "2.0.0"},
    }.items():
        target = root / directory
        target.mkdir(parents=True, exist_ok=True)
        (target / "package.json").write_text(json.dumps(data))
    (root / "node_modules/@scope/dep/addon.node").write_bytes(b"native fixture")
    (root / "node_modules/xo-server").symlink_to(root / "packages/xo-server")
    (root / "packages/xo-server/cycle").symlink_to(root)
    data = inventory.collect(root, "a" * 40)
    assert len(data["components"]) == 5
    assert len(data["nativeBinaries"]) == 1
    assert any(c["purl"] == "pkg:npm/%40scope/dep@2.0.0" for c in data["components"])
    server = next(c for c in data["components"] if c["name"] == "xo-server")
    assert next(d for d in data["dependencies"] if d["ref"] == server["bom-ref"])["dependsOn"]
    (root / "node_modules/nested/package.json").write_text('{"name":"nested"}')
    try:
        inventory.collect(root, "a" * 40)
        raise AssertionError("accepted unscannable installed package")
    except ValueError:
        pass
print("Supply inventory fixtures passed")
