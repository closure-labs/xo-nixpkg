"""Publisher-owned attestation material; every use still runs the verifier."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

VARIABLE = 'XO_NIXPKG_ATTESTATION_SESSION'
MATERIAL_LIMIT = 2 * 1024**2
ENTRY_LIMIT = 8 * 1024**2
SUBJECT_LIMIT = 128 * 1024**2
ISSUER = 'https://token.actions.githubusercontent.com'
PREDICATE = 'https://slsa.dev/provenance/v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@contextmanager
def publisher_session():
    # Never inherit another publisher's material or keep it after this process.
    previous = os.environ.pop(VARIABLE, None)
    try:
        with tempfile.TemporaryDirectory(prefix='xo-attestation-session-') as name:
            os.chmod(name, 0o700)
            os.environ[VARIABLE] = name
            yield
    finally:
        os.environ.pop(VARIABLE, None)
        if previous is not None:
            os.environ[VARIABLE] = previous


def checked_directory(name):
    path = Path(name)
    value = path.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700):
        raise ValueError('Invalid private attestation session directory')
    return path


def file_identity(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('Invalid bounded attestation input')
        digest = hashlib.sha256()
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            for block in iter(lambda: stream.read(1024**2), b''):
                digest.update(block)
        after = os.fstat(descriptor)
        identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError('Attestation input changed while hashing')
        return digest.hexdigest(), identity(after)
    finally:
        os.close(descriptor)


def repository_identity(api, repository):
    value = api('repos/' + repository)
    owner = value.get('owner', {})
    if (value.get('full_name', '').lower() != repository.lower()
            or owner.get('login', '').lower() != repository.split('/')[0].lower()
            or type(value.get('id')) is not int or value['id'] <= 0
            or type(owner.get('id')) is not int or owner['id'] <= 0):
        raise ValueError('Invalid live attestation repository identity')
    return {'repositoryId': value['id'], 'ownerId': owner['id']}


def material(result, context):
    """Retain only verified bundles bound to this exact producer and subject."""
    if not isinstance(result, list) or not 0 < len(result) <= 30:
        return None
    invocation = ('https://github.com/' + context['repository'] + '/actions/runs/'
                  + str(context['producer']['runId']) + '/attempts/'
                  + str(context['producer']['runAttempt']))
    bundles = []
    for row in result:
        if not isinstance(row, dict):
            return None
        verified = row.get('verificationResult', {})
        if not isinstance(verified, dict) or not isinstance(verified.get('statement'), dict):
            return None
        statement = verified['statement']
        predicate = statement.get('predicate', {})
        details = predicate.get('runDetails', {}) if isinstance(predicate, dict) else {}
        metadata = details.get('metadata', {}) if isinstance(details, dict) else {}
        actual = metadata.get('invocationId') if isinstance(metadata, dict) else None
        subjects = statement.get('subject', [])
        if actual != invocation or not isinstance(subjects, list):
            continue
        if not any(isinstance(s, dict) and isinstance(s.get('digest'), dict)
                   and s['digest'].get('sha256') == context['subjectSha256']
                   for s in subjects):
            continue
        attestation = row.get('attestation', {})
        bundle = attestation.get('bundle') if isinstance(attestation, dict) else None
        if not isinstance(bundle, dict) or not isinstance(bundle.get('mediaType'), str):
            return None
        bundles.append(canonical(bundle))
    raw = b'\n'.join(bundles) + b'\n'
    return raw if bundles and len(raw) <= MATERIAL_LIMIT else None


def verified_subject(result, digest):
    if not isinstance(result, list) or not 0 < len(result) <= 30:
        return False
    for row in result:
        verification = row.get('verificationResult') if isinstance(row, dict) else None
        statement = verification.get('statement') if isinstance(verification, dict) else None
        subjects = statement.get('subject') if isinstance(statement, dict) else None
        if not isinstance(subjects, list) or not any(
                isinstance(s, dict) and isinstance(s.get('digest'), dict)
                and s['digest'].get('sha256') == digest for s in subjects):
            return False
    return True


def read_entry(path, context):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= ENTRY_LIMIT):
            raise ValueError('Invalid private attestation material entry')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            value = json.loads(stream.read(ENTRY_LIMIT + 1))
    finally:
        os.close(descriptor)
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('context') != context:
        raise ValueError('Attestation material context mismatch')
    raw = base64.b64decode(value.get('material', ''), validate=True)
    if not 0 < len(raw) <= MATERIAL_LIMIT or hashlib.sha256(raw).hexdigest() != value.get('materialSha256'):
        raise ValueError('Attestation material digest mismatch')
    return raw


def verify(path, cfg, revision, workflow, producer, arguments, command, api):
    name = os.environ.get(VARIABLE)
    if not name or producer is None:
        return command(arguments)
    if (type(producer.get('runId')) is not int or producer['runId'] <= 0
            or type(producer.get('runAttempt')) is not int or producer['runAttempt'] <= 0):
        raise ValueError('Exact attestation producer run and attempt required')
    root = checked_directory(name)
    path = Path(path)
    subject = file_identity(path, SUBJECT_LIMIT)
    verifier = shutil.which(arguments[0])
    if not verifier:
        raise ValueError('Attestation verifier unavailable')
    verifier = str(Path(verifier).resolve(strict=True))
    executable = file_identity(verifier, 256 * 1024**2)
    arguments = [verifier, *arguments[1:]]
    live = repository_identity(api, cfg['repository'])
    context = {'schema': 1, 'subjectSha256': subject[0], 'subjectName': path.name,
               'subjectBytes': subject[1][2], 'policySha256': hashlib.sha256(canonical(cfg)).hexdigest(),
               'repository': cfg['repository'], 'liveIdentity': live, 'source': revision,
               'workflow': workflow, 'producer': producer,
               'trust': {'issuer': ISSUER, 'predicate': PREDICATE, 'root': 'gh-default-current',
                         'host': 'github.com', 'denySelfHosted': True},
               'verifier': {'path': verifier, 'sha256': executable[0]},
               'arguments': arguments[4:]}
    entry = root / (hashlib.sha256(canonical(context)).hexdigest() + '.json')
    raw = None
    try:
        raw = read_entry(entry, context)
    except FileNotFoundError:
        pass
    try:
        if raw is None:
            result = command(arguments)
        else:
            with tempfile.TemporaryDirectory(prefix='verify-', dir=root) as temporary:
                bundle = Path(temporary) / 'bundle.jsonl'
                bundle.write_bytes(raw)
                bundle.chmod(0o600)
                # Re-run all cryptographic, issuer, source, workflow, subject,
                # hosted-runner and current default trust-root checks locally.
                result = command([*arguments, '--bundle', str(bundle)])
        if not verified_subject(result, subject[0]):
            raise ValueError('Verified attestation subject differs from input digest')
        if (file_identity(path, SUBJECT_LIMIT) != subject
                or file_identity(verifier, 256 * 1024**2) != executable
                or repository_identity(api, cfg['repository']) != live):
            raise ValueError('Attestation subject, verifier or repository changed during verification')
    except BaseException:
        entry.unlink(missing_ok=True)
        raise
    if raw is None:
        raw = material(result, context)
        if raw is not None and len(list(root.glob('*.json'))) < 16:
            value = {'schema': 1, 'context': context, 'materialSha256': hashlib.sha256(raw).hexdigest(),
                     'material': base64.b64encode(raw).decode()}
            encoded = canonical(value)
            if len(encoded) > ENTRY_LIMIT:
                raise ValueError('Attestation material entry exceeds bound')
            descriptor, temporary = tempfile.mkstemp(prefix='material-', dir=root)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(encoded)
                os.replace(temporary, entry)
            finally:
                Path(temporary).unlink(missing_ok=True)
    return result
