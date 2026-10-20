"""Content addressed OCI decision evidence. Tags are discovery, never authority."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import subprocess
import tempfile
from urllib.parse import quote

from security_decisions import canonical_hash, load_json

REGISTRY = 'ghcr.io/closure-labs/maestro-decisions'
REFERENCE = re.compile(re.escape(REGISTRY) + r'@sha256:[0-9a-f]{64}')
TYPE = 'application/vnd.closure-labs.decision-packet.v1+json'
MAX_FILES = 512
MAX_BYTES = 32 * 1024**3


def safe_name(name):
    if (not isinstance(name, str) or not name or len(name) > 400
            or not re.fullmatch(r'[A-Za-z0-9_./+-]+', name)
            or name.startswith(('/', '-')) or any(p in ('', '.', '..') for p in name.split('/'))
            or str(PurePosixPath(name)) != name):
        raise ValueError('Unsafe packet member name')
    return name


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(args, max_file_bytes=None, **kwargs):
    # Bound registry-controlled output before loading it in memory and bound
    # oras-created blobs before checking their declared size and digest.
    limit = max(2 * 1024**2, max_file_bytes or 0)
    def restrict_files():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    with tempfile.TemporaryFile() as capture:
        subprocess.run(args, stdout=capture, stderr=subprocess.DEVNULL, timeout=1800,
                       check=True, preexec_fn=restrict_files, **kwargs)
        if capture.tell() > 2 * 1024**2:
            raise ValueError('Registry command output exceeds bound')
        capture.seek(0)
        return capture.read()


def decode_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate OCI manifest key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite OCI number')))



def inventory(directory):
    directory = Path(directory)
    files = {}
    total = 0
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('Packet links are forbidden')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('Packet member is not a regular file')
        name = safe_name(path.relative_to(directory).as_posix())
        if name == 'decision-packet.json':
            raise ValueError('Reserved packet manifest name')
        size = path.stat().st_size
        total += size
        if size <= 0 or total > MAX_BYTES or len(files) >= MAX_FILES:
            raise ValueError('Empty or oversized packet')
        files[name] = {'sha256': file_hash(path), 'size': size}
    if not files:
        raise ValueError('Packet is empty')
    return files


def private_review_registry(allow_missing=False):
    """Candidate closures must never be uploaded to a public review package.

    GitHub documents first-publish Container registry visibility as private.
    Only an authenticated HTTP 404 may use that bootstrap default; API errors
    never imply a missing package. A post-push lookup must positively confirm
    private visibility before returning an evidence reference.
    """
    match = re.fullmatch(r'ghcr\.io/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+-decisions)', REGISTRY)
    if not REGISTRY.endswith('-decisions'):
        return  # The separately admitted -products publisher is intentionally public.
    if not match:
        raise ValueError('Review packet registry must be a dedicated organization package')
    token = os.environ.get('REGISTRY_TOKEN')
    if not token:
        raise ValueError('Scoped REGISTRY_TOKEN is required to authenticate review package privacy')
    owner, package = match.groups()
    environment = dict(os.environ, GH_TOKEN=token)
    result = subprocess.run(['gh', 'api', '--method', 'GET', '--include',
                             f'orgs/{owner}/packages/container/{quote(package, safe="")}'],
                            env=environment, capture_output=True, text=True, timeout=60, check=False)
    if len(result.stdout) > 2 * 1024**2:
        raise ValueError('Package privacy API response exceeds bound')
    headers, separator, body = result.stdout.replace('\r\n', '\n').partition('\n\n')
    first = headers.split('\n', 1)[0]
    status = re.fullmatch(r'HTTP/[0-9.]+ ([0-9]{3})(?: .*)?', first)
    if not separator or not status:
        raise ValueError('Cannot authenticate package visibility HTTP status')
    if status[1] == '404' and allow_missing and result.returncode == 1:
        return
    if status[1] != '200' or result.returncode != 0:
        raise ValueError('Review package visibility API failed')
    value = decode_json(body)
    if (not isinstance(value, dict) or value.get('name') != package
            or value.get('package_type') != 'container'
            or not isinstance(value.get('owner'), dict)
            or value['owner'].get('login', '').lower() != owner.lower()
            or value.get('visibility') != 'private'):
        raise ValueError('Candidate review package must have verified private visibility')


def push(directory, producer):
    """Caller authenticates producer before persistence; return an immutable ref."""
    directory = Path(directory).resolve()
    packet = {'schema': 1, 'producer': producer, 'files': inventory(directory)}
    private_review_registry(allow_missing=True)
    path = directory / 'decision-packet.json'
    path.write_text(json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n')
    try:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'manifest.json'
            tag = REGISTRY + ':packet-' + canonical_hash(packet)
            command(['oras', 'push', '--artifact-type', TYPE, '--export-manifest', str(manifest),
                     tag, 'decision-packet.json:application/json',
                     *[name + ':application/octet-stream' for name in packet['files']]], cwd=directory)
            private_review_registry()
            digest = file_hash(manifest)
            return {'reference': REGISTRY + '@sha256:' + digest,
                    'sha256': canonical_hash(packet), 'producer': producer}
    finally:
        path.unlink(missing_ok=True)


def fetch(reference, output, expected=None):
    """Inspect the manifest before fetching fixed regular members, never oras pull."""
    if not isinstance(reference, str) or not REFERENCE.fullmatch(reference):
        raise ValueError('Packet requires a digest in the dedicated evidence repository')
    raw = command(['oras', 'manifest', 'fetch', reference])
    if len(raw) > 2 * 1024**2 or hashlib.sha256(raw).hexdigest() != reference.split(':')[-1]:
        raise ValueError('Packet OCI manifest digest mismatch')
    manifest = decode_json(raw)
    if not isinstance(manifest, dict) or manifest.get('schemaVersion') != 2:
        raise ValueError('Invalid OCI manifest schema')
    layers = manifest.get('layers')
    if manifest.get('artifactType') != TYPE or not isinstance(layers, list) or not 1 < len(layers) <= MAX_FILES + 1:
        raise ValueError('Invalid packet OCI manifest')
    members = {}
    total = 0
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get('annotations'), dict):
            raise ValueError('Invalid OCI layer descriptor')
        name = safe_name(layer['annotations'].get('org.opencontainers.image.title'))
        size, digest = layer.get('size'), layer.get('digest')
        if (name in members or type(size) is not int or size <= 0
                or not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)):
            raise ValueError('Duplicate or invalid OCI packet member')
        total += size
        members[name] = {'sha256': digest[7:], 'size': size}
    if total > MAX_BYTES or 'decision-packet.json' not in members or members['decision-packet.json']['size'] > 2 * 1024**2:
        raise ValueError('Packet exceeds bounds or lacks manifest')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for name in ['decision-packet.json', *sorted(set(members) - {'decision-packet.json'})]:
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        command(['oras', 'blob', 'fetch', REGISTRY + '@sha256:' + members[name]['sha256'], '--output', str(path)], max_file_bytes=members[name]['size'])
        if path.is_symlink() or not path.is_file() or path.stat().st_size != members[name]['size'] or file_hash(path) != members[name]['sha256']:
            raise ValueError('Packet member integrity failure')
        if name == 'decision-packet.json':
            packet = load_json(path)
            if (not isinstance(packet, dict) or set(packet) != {'schema', 'producer', 'files'}
                    or type(packet['schema']) is not int or packet['schema'] != 1
                    or not isinstance(packet['producer'], dict)
                    or packet['files'] != {k: v for k, v in members.items() if k != name}
                    or (expected is not None and canonical_hash(packet) != expected)):
                raise ValueError('Packet contents differ from approved manifest')
    return packet
