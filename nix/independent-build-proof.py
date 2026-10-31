"""Read-only hosted reproducibility experiment; never release-authority evidence."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

PROFILES = ("latest", "stable", "rolling")
STORE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+")
OLD = {
    "/nix/store/7vqm49jj6y11r8axlhr6rf3ms7hqlvn4-xen-orchestra-ce-6.10.0",
    "/nix/store/kqf8wj1xwjkqvjwpaipcx393hil2c2fv-xen-orchestra-ce-6.9.1",
    "/nix/store/zh2pvbiwadzsxz5i3h7wp5x1wl44y5w0-xen-orchestra-ce-unstable-2026-10-29",
}
OPTIONS = ["--option", "accept-flake-config", "false", "--option", "access-tokens", "",
           "--option", "substituters", "https://cache.nixos.org", "--option", "extra-substituters", "",
           "--option", "builders", "", "--option", "max-jobs", "1", "--option", "cores", "2"]


def require(value):
    if not value:
        raise ValueError("experiment-guard-failed")


def store_path(value):
    require(isinstance(value, str))
    value = value if value.startswith("/nix/store/") else "/nix/store/" + value
    require(STORE.fullmatch(value))
    return value


def inputs(derivation, roots):
    """Support documented legacy and v4 formats; reject dynamic/unknown inputs."""
    if derivation.get("version") == 4:
        data = derivation["inputs"]["drvs"]
    else:
        require(derivation.get("version", 1) in (1, 2, 3))
        data = derivation["inputDrvs"]
    require(isinstance(data, dict) and 0 < len(data) <= 512)
    result = []
    for path, outputs in sorted(data.items()):
        path = store_path(path)
        require(path.endswith(".drv") and path not in roots)
        if isinstance(outputs, dict):
            require(derivation.get("version") == 4 and set(outputs) == {"outputs", "dynamicOutputs"})
            require(outputs["dynamicOutputs"] == {})
            outputs = outputs["outputs"]
        require(isinstance(outputs, list) and 0 < len(outputs) <= 32)
        for output in outputs:
            require(isinstance(output, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", output))
            result.append(path + "^" + output)
    return result


def exact_derivation(raw, drv, output):
    """The current CLI wraps its path map in a versioned envelope."""
    require(isinstance(raw, dict))
    if "derivations" in raw or "version" in raw:
        require(set(raw) == {"version", "derivations"} and type(raw["version"]) is int and raw["version"] == 4)
        raw = raw["derivations"]
    require(isinstance(raw, dict) and len(raw) == 1)
    key = next(iter(raw))
    require(store_path(key) == drv)
    description = raw[key]
    require(isinstance(description, dict))
    require(isinstance(description.get("outputs"), dict) and set(description["outputs"]) == {"out"})
    require(store_path(description["outputs"]["out"]["path"]) == output)
    require(description["env"].get("out") == output and description["env"].get("doInstallCheck") == "1")
    return description


def absent(paths):
    for path in paths:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise ValueError("root-output-already-present")


def command(args, deadline, seconds=300, capture=True):
    remaining = min(seconds, deadline - time.monotonic())
    require(remaining > 0)
    result = subprocess.run(args, check=True, timeout=remaining,
                            stdout=subprocess.PIPE if capture else None)
    if capture:
        require(len(result.stdout) <= 8 * 1024 * 1024)
        return result.stdout.decode().strip()


def nar_hash(path, deadline):
    """Hash actual bytes, not Nix's cached path-info hash. No NAR file retained."""
    end = min(deadline, time.monotonic() + 180)
    process = subprocess.Popen(["nix-store", "--dump", path], stdout=subprocess.PIPE)
    digest, size = hashlib.sha256(), 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = end - time.monotonic()
                require(remaining > 0)
                require(selector.select(remaining))
                block = os.read(process.stdout.fileno(), 1024 * 1024)
                if not block:
                    break
                size += len(block)
                require(size <= 3 * 1024**3)
                digest.update(block)
        require(process.wait(timeout=max(0.1, end - time.monotonic())) == 0)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    return "sha256-" + base64.b64encode(digest.digest()).decode(), size


def build(leg, destination):
    require(leg in ("A", "B"))
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
    group = next(line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::"))
    controls = Path("/sys/fs/cgroup") / group.lstrip("/")
    require((controls / "memory.max").read_text().strip() == "2147483648")
    require((controls / "memory.swap.max").read_text().strip() == "0")
    require((controls / "cpu.max").read_text().strip() == "100000 100000")
    revision = os.environ["PROOF_REVISION"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision))
    deadline = time.monotonic() + 225 * 60
    require(command(["git", "rev-parse", "HEAD"], deadline) == revision)
    nix = ["nix", *OPTIONS]
    nix_version = command(["nix", "--version"], deadline)
    print("engine: " + nix_version, flush=True)
    plan = {}
    print("stage: immutable-plan", flush=True)
    for profile in PROFILES:
        attr = ".#packages.x86_64-linux." + profile
        drv = store_path(command(nix + ["eval", "--raw", "--no-write-lock-file", attr + ".drvPath"], deadline))
        output = store_path(command(nix + ["eval", "--raw", "--no-write-lock-file", attr + ".outPath"], deadline))
        require(drv.endswith(".drv") and output not in OLD)
        raw = json.loads(command(nix + ["derivation", "show", drv], deadline))
        description = exact_derivation(raw, drv, output)
        plan[profile] = {"drv": drv, "output": output, "description": description}
    root_drvs = {item["drv"] for item in plan.values()}
    root_outputs = [item["output"] for item in plan.values()]
    require(len(root_drvs) == len(root_outputs) == 3 and len(set(root_outputs)) == 3)
    absent(root_outputs)
    print("stage: dependencies-only", flush=True)
    dependencies = sorted({item for root in plan.values() for item in inputs(root["description"], root_drvs)})
    command(nix + ["build", "--no-link", "--no-write-lock-file", *dependencies], deadline, 75 * 60, False)
    absent(root_outputs)
    results = {}
    for profile in PROFILES:
        print("stage: fresh-offline-root-" + profile, flush=True)
        item = plan[profile]
        absent([item["output"]])
        command(nix + ["build", "--offline", "--option", "substitute", "false", "--no-link", item["drv"] + "^out"],
                deadline, 50 * 60, False)
        require(command(["nix-store", "--query", "--deriver", item["output"]], deadline) == item["drv"])
        actual_hash, size = nar_hash(item["output"], deadline)
        info = json.loads(command(nix + ["path-info", "--json", "--json-format", "1", item["output"]], deadline))
        require(isinstance(info, dict) and set(info) == {item["output"]})
        entry = info[item["output"]]
        require(entry["narHash"] == actual_hash and entry["narSize"] == size)
        results[profile] = {"drv": item["drv"], "output": item["output"], "narHash": actual_hash,
                            "narSize": size, "freshOfflineBuild": True, "installChecks": True}
    if leg == "A":
        print("stage: nixos-service-test", flush=True)
        command(nix + ["build", "--no-link", "--no-write-lock-file", ".#checks.x86_64-linux.xo-server-service"],
                deadline, 30 * 60, False)
    receipt = {"schema": 1, "authorityClaim": False, "leg": leg, "revision": revision,
               "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
               "nixVersion": nix_version,
               "serviceTest": leg == "A", "profiles": results}
    Path(destination).write_text(json.dumps(receipt, sort_keys=True) + "\n")


def compare(first, second):
    for receipt, leg in ((first, "A"), (second, "B")):
        require(receipt["schema"] == 1 and receipt["authorityClaim"] is False and receipt["leg"] == leg)
        require(set(receipt["profiles"]) == set(PROFILES))
        require(re.fullmatch(r"[0-9a-f-]{36}", receipt["bootId"]))
        for item in receipt["profiles"].values():
            require(item["freshOfflineBuild"] is True and item["installChecks"] is True)
            require(store_path(item["output"]) not in OLD and store_path(item["drv"]).endswith(".drv"))
            require(re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", item["narHash"]))
            require(type(item["narSize"]) is int and 0 < item["narSize"] <= 3 * 1024**3)
    require(first["bootId"] != second["bootId"] and first["serviceTest"] is True)
    for key in ("revision", "runId", "runAttempt", "nixVersion", "profiles"):
        require(first[key] == second[key])
    return {"status": "matching-independent-builds", "authorityClaim": False,
            "revision": first["revision"], "profiles": first["profiles"]}


if __name__ == "__main__":
    if sys.argv[1] == "build":
        build(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "compare":
        receipts = []
        for name in sys.argv[2:]:
            path = Path(name)
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2)
            receipts.append(json.loads(path.read_text()))
        require(len(receipts) == 2)
        print(json.dumps(compare(*receipts), sort_keys=True))
    else:
        raise ValueError("unknown-mode")
