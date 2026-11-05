#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One fixed, nonpublishing retained-packet restore on a disposable capped runner."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time

SOURCE = '9c001f4c6a3588f0c654436a337136ad038e34e2'
RESTORE_SHA256 = '0ae91720174225dab89f47c06ab4744b526e9f68487c8f78e66a208f5fe21f48'
REPOSITORY = 'closure-labs/xo-nixpkg'
REVISION = '0ea838c5accd84855d6a890d47ed39e50d02c77a'
RUN, ATTEMPT = 41955054111, 1
REFERENCE = 'ghcr.io/closure-labs/xo-nixpkg-decisions@sha256:a86f41ea7dcbb7718bc150d78ef34bfba213c5558aa5dd67674ca8f387cef4e6'
PACKET = 'd83ec9bcbd5cee92d431e95316b4b9557996b3f3ba992fe33f652f334e2a8afb'
DECISION = 'de4c8faf32f415c767ee92815d5a144950ac504e2cd360f1680d418d169c8fcf'
PRODUCT = '16f2a292627931c06ad1241c6d7f274efa1eb423b6752637c01ec363ae1745b7'
GiB = 1024 ** 3
RESERVE, LOW_FREE, MAX_PAYLOAD = 2 * GiB, 512 * 1024 ** 2, 4 * GiB
STAGES = {'initial', 'bootstrap', 'metadata', 'materialize', 'authenticate', 'unpack', 'import', 'verify', 'done'}
DEADLINE = 0.0


class Blocked(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Blocked(code)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def validate_caps(memory, swap, cpu):
    require(memory.strip().isdigit() and 0 < int(memory) <= 4 * GiB, 'memory-cap')
    require(swap.strip() == '0', 'swap-cap')
    values = cpu.split()
    require(len(values) == 2 and all(x.isdigit() for x in values)
            and 0 < int(values[0]) <= 2 * int(values[1]), 'cpu-cap')


def caps():
    line = next((x for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')), '')
    require(line.startswith('0::/') and 'restore-capacity-' in line, 'cgroup-origin')
    root = Path('/sys/fs/cgroup') / line.split('::', 1)[1].lstrip('/')
    validate_caps((root / 'memory.max').read_text(), (root / 'memory.swap.max').read_text(), (root / 'cpu.max').read_text())
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                name = (process / 'comm').read_text().strip()
            except OSError:
                continue
            require(not name.startswith(('nix-daemon', 'determinate-nix')), 'daemon-outside-cap')
    require(os.geteuid() == 0 and os.environ.get('NIX_REMOTE') == 'local', 'local-store-required')


def command(args, timeout=300, data=None):
    remaining = min(timeout, DEADLINE - time.monotonic())
    require(remaining > 0, 'wall-budget')
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                 stdout=out, stderr=err, start_new_session=True)
        try:
            if data is not None:
                child.stdin.write(data); child.stdin.close()
            end = time.monotonic() + remaining
            while child.poll() is None:
                require(time.monotonic() < end, 'command-timeout')
                require(os.fstat(out.fileno()).st_size <= 16 * 1024 ** 2
                        and os.fstat(err.fileno()).st_size <= 16 * 1024 ** 2, 'command-output-cap')
                time.sleep(.1)
            require(os.fstat(out.fileno()).st_size <= 16 * 1024 ** 2 and os.fstat(err.fileno()).st_size <= 16 * 1024 ** 2, 'command-output-cap')
            require(child.returncode == 0, 'command-failed')
            out.seek(0)
            return out.read(16 * 1024 ** 2 + 1).decode('utf-8')
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL); child.wait()


def packet_bounds(members):
    require(isinstance(members, dict) and 0 < len(members) <= 512, 'packet-member-count')
    total = 0
    for name, record in members.items():
        require(isinstance(record, dict) and type(record.get('size')) is int and record['size'] > 0, 'packet-member-size')
        limit = 1_800_000_000 if re.fullmatch(r'distribution-cache\.tar\.part-[0-9]{3}', name) else (128 if name == 'scans.json' else 64) * 1024 ** 2
        require(record['size'] <= limit, 'packet-member-limit')
        total += record['size']
    require(total <= MAX_PAYLOAD, 'packet-total-limit')
    return total


def narinfo(raw, cache, transport):
    require(len(raw) <= 65536, 'narinfo-size')
    fields = {}
    for line in raw.decode('utf-8').splitlines():
        key, sep, value = line.partition(': ')
        require(sep and (key not in fields or key == 'Sig'), 'narinfo-schema')
        fields[key] = value
    require(transport.STORE.fullmatch(fields.get('StorePath', '')) is not None, 'narinfo-path')
    size = fields.get('NarSize', '')
    require(re.fullmatch(r'[1-9][0-9]{0,11}', size) is not None and int(size) <= 24 * GiB, 'narinfo-narsize')
    name = transport.safe_name(fields.get('URL', ''))
    path = cache / name
    require(not path.is_symlink() and path.is_file(), 'narinfo-local-payload')
    return fields['StorePath'], int(size)


class Metrics:
    def __init__(self, work, output):
        self.work, self.output = work, output
        self.phase, self.started = 'initial', time.monotonic()
        self.values = {'schema': 1, 'capacityOnly': True, 'authorityClaim': False,
                       'status': 'blocked', 'source': SOURCE, 'qualificationRun': RUN,
                       'qualificationAttempt': ATTEMPT, 'productHash': PRODUCT,
                       'publicWriteInvocations': 0, 'packageExecutions': 0,
                       'reserveBytes': RESERVE, 'samples': []}
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.reserve = work / 'physical-reserve'

    def write(self):
        with self.lock:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            pending = self.output.with_suffix('.pending')
            pending.write_text(json.dumps(self.values, sort_keys=True, indent=2) + '\n')
            pending.chmod(0o644); os.replace(pending, self.output)

    def sample(self):
        stat = os.statvfs(self.work)
        return {'stage': self.phase, 'elapsedMilliseconds': int((time.monotonic() - self.started) * 1000),
                'availableBytesExcludingHeldReserve': stat.f_bavail * stat.f_frsize,
                'freeInodes': stat.f_favail}

    def stage(self, phase):
        require(phase in STAGES, 'stage-name')
        self.phase = phase
        sample = self.sample()
        self.values['samples'].append(sample)
        if 'minimumAvailableExcludingHeldReserveBytes' in self.values:
            self.values['minimumAvailableExcludingHeldReserveBytes'] = min(self.values['minimumAvailableExcludingHeldReserveBytes'], sample['availableBytesExcludingHeldReserve'])
        self.write()

    def begin(self):
        devices = {os.stat(x).st_dev for x in (self.work, Path('/nix/store'), Path('/tmp'))}
        require(len(devices) == 1, 'different-filesystems')
        stat = os.statvfs(self.work)
        self.values.update(filesystemBytes=stat.f_blocks * stat.f_frsize,
                           availableBeforeReserveBytes=stat.f_bavail * stat.f_frsize)
        require(stat.f_bavail * stat.f_frsize >= RESERVE + LOW_FREE, 'initial-free-space')
        fd = os.open(self.reserve, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try: os.posix_fallocate(fd, 0, RESERVE)
        finally: os.close(fd)
        require(self.reserve.stat().st_blocks * 512 >= RESERVE, 'reserve-not-allocated')
        self.values['minimumAvailableExcludingHeldReserveBytes'] = stat.f_bavail * stat.f_frsize - RESERVE
        def watch():
            while not self.stop.wait(1):
                try:
                    current = self.sample()
                    intact = self.reserve.stat().st_blocks * 512 >= RESERVE
                except OSError:
                    self.values.update(status='blocked', code='space-observation-failed', failedStage=self.phase)
                    self.write(); os._exit(2)
                self.values['minimumAvailableExcludingHeldReserveBytes'] = min(
                    self.values['minimumAvailableExcludingHeldReserveBytes'], current['availableBytesExcludingHeldReserve'])
                if current['availableBytesExcludingHeldReserve'] < LOW_FREE or not intact:
                    self.values.update(status='blocked', code='free-space-reserve', failedStage=self.phase)
                    self.values['samples'].append(current); self.write()
                    os._exit(2)  # systemd KillMode=control-group terminates remaining local-store work.
        self.thread = threading.Thread(target=watch, daemon=True); self.thread.start()
        self.stage('initial')

    def finish(self):
        self.stop.set()
        if hasattr(self, 'thread'): self.thread.join(timeout=2)
        self.write()


def bootstrap(source, metrics):
    metrics.stage('bootstrap')
    os.environ.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0=str(source))
    require(command(['/usr/bin/git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD']).strip() == SOURCE, 'source-revision')
    require(digest(source / 'ci/distribution-cache.py') == RESTORE_SHA256, 'restore-source')
    uri = 'git+file://' + str(source) + '?rev=' + SOURCE
    expression = '''let f=builtins.getFlake %s; p=f.inputs.nixpkgs.legacyPackages.x86_64-linux; in {
      contexts=(builtins.getContext f.apps.x86_64-linux.publication-controller.program)
        // (builtins.getContext f.apps.x86_64-linux.fetch-evidence.program)
        // (builtins.getContext f.packages.x86_64-linux.devenv.outPath);
      tools={gh="${p.gh}/bin/gh"; oras="${p.oras}/bin/oras"; nix="${p.nix}/bin/nix";}; }''' % json.dumps(uri)
    values = json.loads(command(['nix', 'eval', '--json', '--expr', expression], timeout=600))
    contexts = values.get('contexts', {})
    require(isinstance(contexts, dict) and 0 < len(contexts) <= 8, 'tool-context')
    for drv, record in contexts.items():
        require(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/]+\.drv', drv) is not None
                and record == {'outputs': ['out']}, 'tool-derivation')
        command(['nix-store', '--realise', drv], timeout=600)
    tools = values['tools']
    require(set(tools) == {'gh', 'oras', 'nix'} and all(Path(x).is_file() for x in tools.values()), 'tool-paths')
    # Direct local-store writes use the installer engine, matching the publisher's daemon.
    # Keep the pinned client closure present for the same bootstrap footprint.
    os.environ['PATH'] = ':'.join(str(Path(tools[x]).parent) for x in ('gh', 'oras')) + ':' + os.environ['PATH']
    version = command(['nix', '--version']).strip().split()[-1]
    require(re.fullmatch(r'[0-9][0-9A-Za-z.+-]{0,40}', version) is not None, 'nix-version')
    metrics.values['nixVersion'] = version
    stat = os.statvfs(metrics.work)
    metrics.values['afterToolchainAvailableBytesExcludingHeldReserve'] = stat.f_bavail * stat.f_frsize
    metrics.stage('metadata')


def execute(source, work, metrics):
    os.environ['NIX_CONFIG'] = 'post-build-hook =\nbuilders =\n'
    bootstrap(source, metrics)
    caps()
    sys_path = str(source / 'ci/decisions')
    import sys
    sys.path.insert(0, sys_path)
    import common
    import decision_packets as packets
    import operations
    cfg = common.config(source / 'ci/decision-policy.json')
    require(cfg['repository'] == REPOSITORY, 'repository-policy')
    original = json.loads((source / 'automation/decisions/releases' / (DECISION + '.json')).read_text())
    require(canonical(original) == DECISION and canonical(original['payload']['product']) == PRODUCT, 'approved-product')
    packets.REGISTRY = 'ghcr.io/closure-labs/xo-nixpkg-decisions'
    packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
    expected_producer = dict(repository=REPOSITORY, revision=REVISION, sourceRevision=REVISION,
                             workflow='.github/workflows/qualification.yml', runId=RUN, runAttempt=ATTEMPT)
    token = os.environ.get('GH_TOKEN'); require(bool(token), 'read-token-missing')
    private = work / 'registry'; private.mkdir(mode=0o700)
    os.environ['DOCKER_CONFIG'] = str(private)
    command(['oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'], '--password-stdin'], data=token.encode())
    try:
        _, members = packets.inspect(REFERENCE)
        metrics.values['packetPayloadBytes'] = packet_bounds(members)
        evidence = work / 'evidence'; evidence.mkdir(mode=0o700)
        with operations.budget(900):
            descriptor_path = packets.fetch_member('decision-packet.json', evidence, members)
            descriptor = packets.packet_descriptor(descriptor_path, members, PACKET)
            require(descriptor['producer'] == expected_producer, 'packet-producer')
            descriptor_path.unlink()
            metrics.stage('materialize')
            with tempfile.TemporaryDirectory(dir=work) as temporary:
                downloaded = Path(temporary) / 'packet'
                packets.fetch(REFERENCE, downloaded, PACKET)
                cached = packets.job_cache(REFERENCE, PACKET)
                sample_name = next(iter(descriptor['files']))
                metrics.values['temporaryUsesPacketCacheHardlink'] = (
                    (downloaded / sample_name).stat().st_ino == (cached / 'data' / sample_name).stat().st_ino)
                for name in descriptor['files']:
                    packets.install_member(downloaded / name, evidence / name, evidence)
        metrics.stage('authenticate')
        native = common.scans(evidence / 'scans.json', cfg, allow_expired=True)
        product = common.product(evidence / 'product.json', cfg, native)
        require(canonical(product) == PRODUCT and product == original['payload']['product'], 'product-binding')
        require(native['revision'] == REVISION and native['producer']['runId'] == RUN
                and native['producer']['runAttempt'] == ATTEMPT, 'scan-producer')
        for name, expected in product['assets'].items():
            require(digest(evidence / name) == expected, 'asset-digest')
        current = common.authority.github_api(f'repos/{REPOSITORY}/actions/runs/{RUN}')
        require(current['run_attempt'] == ATTEMPT and current['conclusion'] == 'success'
                and current['head_sha'] == REVISION and current['path'] == '.github/workflows/qualification.yml', 'producer-changed')
    finally:
        command(['oras', 'logout', 'ghcr.io'])
        shutil.rmtree(private)
        for name in list(os.environ):
            if 'TOKEN' in name or name in ('DOCKER_CONFIG', 'DECIDER_KEY', 'CACHIX_AUTH_TOKEN'):
                os.environ.pop(name, None)
    os.environ['NIX_CONFIG'] += 'substituters =\nsubstitute = false\n'
    caps()
    roots = [*product['products'].values(), *product['roots'].values()]
    require(len(roots) == 8 and all(not os.path.lexists(r['storePath']) for r in roots), 'target-root-already-present')
    spec = importlib.util.spec_from_file_location('capacity_distribution', source / 'ci/distribution-cache.py')
    transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
    transport.validate_manifest(evidence, native['transport'])
    metrics.values['transportArchiveBytes'] = native['transport']['archiveSize']
    require(0 < native['transport']['archiveSize'] <= MAX_PAYLOAD, 'transport-size')
    saved_command, saved_unpack = transport.command, transport.unpack
    def unpack(archive, cache):
        metrics.stage('unpack'); saved_unpack(archive, cache)
        infos = {}; total = 0
        for path in cache.glob('*.narinfo'):
            key, size = narinfo(path.read_bytes(), cache, transport)
            require(key not in infos and len(infos) < 10000, 'narinfo-duplicates')
            infos[key] = size; total += size
        require(set(r['storePath'] for r in roots) <= set(infos) and total <= 24 * GiB, 'closure-size-bound')
        missing = [p for p in infos if not os.path.lexists(p)]
        metrics.values.update(narinfoPaths=len(infos), missingPaths=len(missing),
                              missingLogicalNarBytes=sum(infos[p] for p in missing))
    def measured(args):
        caps()
        if args[:2] == ['nix', 'copy']:
            require(args[2] == '--from' and args[3].startswith('file:///') and args[4] == '--no-check-sigs'
                    and set(args[5:]) == {r['storePath'] for r in roots}, 'import-argv')
            cache = Path(args[3][7:]); require(not (cache.parent / 'distribution-cache.tar').exists(), 'archive-not-released')
            metrics.stage('import')
        elif args[:3] in (['nix', 'path-info', '--json'], ['nix', 'store', 'verify']):
            metrics.stage('verify')
        else: raise Blocked('unexpected-nix-command')
        return saved_command(args)
    transport.unpack, transport.command = unpack, measured
    transport.restore(evidence, native['transport'], roots)
    transport.validate_manifest(evidence, native['transport'])
    require(metrics.reserve.stat().st_blocks * 512 >= RESERVE, 'reserve-lost')
    metrics.stage('done')
    metrics.values.update(status='passed', code='exact-restore-verified', rootCount=8,
                          originalPartsReverified=True, capacityProven=True,
                          localStoreMode=True, cacheWriteHooksDisabled=True, physicalReserveIntact=metrics.reserve.stat().st_blocks * 512 >= RESERVE)


def safe_error(error):
    if isinstance(error, Blocked):
        return str(error)
    text = str(error)
    match = re.search(r'HTTP(?: error)?[ :]+(401|403|404|429)\b', text, re.IGNORECASE)
    return 'read-http-' + match[1] if match else 'diagnostic-failed'


def main():
    global DEADLINE
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--source', type=Path, required=True); cli.add_argument('--work', type=Path, required=True)
    cli.add_argument('--output', type=Path, required=True); args = cli.parse_args()
    DEADLINE = time.monotonic() + 2000
    os.environ['CI_OPERATION_DEADLINE'] = str(DEADLINE)
    os.umask(0o077); args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    metrics = Metrics(args.work, args.output)
    try:
        caps(); metrics.begin(); execute(args.source.resolve(), args.work, metrics)
        return 0
    except BaseException as error:
        code = safe_error(error)
        diagnostic = getattr(error, 'diagnostic', None)
        if isinstance(diagnostic, dict) and diagnostic.get('code') == 'distribution-command-failed':
            allowed = {'disk-full','unsupported-option','permission-denied','unclassified','io-error','timeout','network'}
            metrics.values['restoreFailure'] = {'operation': diagnostic.get('operation') if diagnostic.get('operation') in ('restore-copy','store-verify','root-path-info') else 'unknown',
                'indicators': sorted(x for x in diagnostic.get('indicators', []) if x in allowed)}
        metrics.values.update(status='blocked', code=code, failedStage=metrics.phase,
                              exceptionCategory=type(error).__name__ if type(error).__name__ in
                              ('ValueError', 'OSError', 'CalledProcessError', 'TimeoutExpired', 'Blocked') else 'other')
        return 2
    finally:
        metrics.finish()


if __name__ == '__main__':
    raise SystemExit(main())
