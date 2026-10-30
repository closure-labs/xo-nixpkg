# SPDX-License-Identifier: Apache-2.0
"""Classify official dependency PRs from immutable metadata; never grant review authority."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import re
from urllib.parse import quote

from decision_authority import SHA

REPOSITORY = 'closure-labs/xo-nixpkg'
REPOSITORY_ID = 1198726032
BOT = {'login': 'dependabot[bot]', 'id': 49699333, 'type': 'Bot'}
WORKFLOW = re.compile(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml')
ACTION = re.compile(r'\.github/actions/(?:[A-Za-z0-9_.-]+/)+action\.ya?ml')
PIN = re.compile(r'([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)@([0-9a-f]{40})')
VERSION = re.compile(r'v[0-9]+(?:\.[0-9]+){0,2}')
MAX_FILES = 64
MAX_BYTES = 1024 * 1024


class UnsupportedFamily(ValueError):
    """A well-formed inventory belongs to a family not admitted automatically."""


def tree(api, repository, sha):
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError('Tree lookup requires immutable commit SHA')
    value = api(f'repos/{repository}/git/trees/{sha}?recursive=1')
    if not isinstance(value, dict) or value.get('truncated') is not False or not isinstance(value.get('tree'), list):
        raise ValueError('Cannot prove complete dependency tree identity')
    entries = {}
    for item in value['tree']:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            raise ValueError('Invalid tree response')
        if (not item['path'] or item['path'].startswith('/') or any(part in ('', '.', '..') for part in item['path'].split('/'))
                or (item.get('type'), item.get('mode')) not in {('tree', '040000'), ('blob', '100644'),
                    ('blob', '100755'), ('blob', '120000'), ('commit', '160000')}
                or not isinstance(item.get('sha'), str) or not SHA.fullmatch(item['sha'])):
            raise ValueError('Invalid tree entry identity')
        if item['path'] in entries:
            raise ValueError('Duplicate dependency tree path')
        entries[item['path']] = (item.get('type'), item.get('mode'), item.get('sha'))
    return entries


def changed_paths(files, count):
    if type(count) is not int or not isinstance(files, list) or len(files) != count or not files:
        raise ValueError('Incomplete PR file inventory')
    paths = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get('filename'), str):
            raise ValueError('Invalid changed-file inventory')
        paths.add(item['filename'])
        if item.get('previous_filename'):
            if not isinstance(item['previous_filename'], str):
                raise ValueError('Invalid renamed path')
            paths.add(item['previous_filename'])
    return paths


def official(pull):
    user = pull.get('user')
    return (isinstance(user, dict) and type(user.get('id')) is int
            and all(user.get(key) == value for key, value in BOT.items()))


def identity(repository, pull):
    if repository != REPOSITORY or not official(pull):
        raise ValueError('Dependency exception requires the official Dependabot identity')
    if (type(pull.get('number')) is not int or pull['number'] < 1 or pull.get('state') != 'open'
            or pull.get('base', {}).get('ref') != 'main'):
        raise ValueError('Dependency update must be an open main-targeting PR')
    for side in ('base', 'head'):
        value = pull.get(side, {})
        repo = value.get('repo', {})
        if (repo.get('full_name') != REPOSITORY or type(repo.get('id')) is not int
                or repo['id'] != REPOSITORY_ID or not isinstance(value.get('sha'), str)
                or not SHA.fullmatch(value['sha'])):
            raise ValueError('Dependency update must retain the same native repository and immutable heads')
    return (pull['number'], pull['base']['sha'], pull['head']['sha'])


def files_at(api, repository, number):
    result = api(f'repos/{repository}/pulls/{number}/files?per_page=100&page=1')
    if not isinstance(result, list) or not 1 <= len(result) <= MAX_FILES:
        raise ValueError('Dependency file inventory exceeds the bounded supported scope')
    return result


def blob(api, repository, sha):
    value = api(f'repos/{repository}/git/blobs/{sha}')
    if (not isinstance(value, dict) or value.get('sha') != sha or value.get('encoding') != 'base64'
            or type(value.get('size')) is not int or not 0 < value['size'] <= MAX_BYTES
            or not isinstance(value.get('content'), str)):
        raise ValueError('Dependency content is not a bounded immutable Git blob')
    try:
        encoded = value['content'].replace('\n', '')
        if len(encoded) != 4 * ((value['size'] + 2) // 3):
            raise ValueError('Encoded dependency blob differs from declared size')
        raw = base64.b64decode(encoded, validate=True)
        if (len(raw) != value['size'] or
                hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != sha):
            raise ValueError('Dependency blob size or Git identity mismatch')
        return raw.decode('utf-8')
    except (UnicodeError, ValueError) as error:
        raise ValueError('Invalid authenticated dependency blob') from error


def inspect(api, repository, pull, files=None):
    """Stdlib shape/byte validation; never execute or import candidate code.

    This alone does not classify YAML semantics or authenticate human approval.
    The trusted-main admission worker must additionally call classify().
    """
    number, base, head = identity(repository, pull)
    files = files_at(api, repository, number) if files is None else files
    paths = changed_paths(files, pull.get('changed_files'))
    if (not 1 <= len(paths) <= MAX_FILES or len(paths) != len(files)
            or any(item.get('status') != 'modified' or item.get('previous_filename') for item in files)):
        raise ValueError('Dependency exception supports only existing dependency files')
    family = 'nixpkgs-paired-lock' if paths <= {'flake.lock', 'devenv.lock'} and 'flake.lock' in paths else 'github-actions-pins'
    if family == 'github-actions-pins' and any(not (WORKFLOW.fullmatch(path) or ACTION.fullmatch(path)) for path in paths):
        raise UnsupportedFamily('Only complete Actions pins or paired nixpkgs locks are supported')
    branch = pull.get('head', {}).get('ref', '')
    if family == 'nixpkgs-paired-lock' and (not re.fullmatch(r'dependabot/nix/[A-Za-z0-9][A-Za-z0-9._/-]*', branch)
                                           or '..' in branch):
        raise ValueError('Unexpected native Dependabot branch')
    comparison = api(f'repos/{repository}/compare/{base}...{head}')
    merge_base = comparison.get('merge_base_commit', {}).get('sha')
    if (comparison.get('base_commit', {}).get('sha') != base
            or not isinstance(merge_base, str) or not SHA.fullmatch(merge_base)):
        raise ValueError('Dependency comparison lacks an authenticated immutable merge base')
    old = {path: value for path, value in tree(api, repository, merge_base).items() if value[0] != 'tree'}
    new = {path: value for path, value in tree(api, repository, head).items() if value[0] != 'tree'}
    actual = {path for path in old.keys() | new.keys() if old.get(path) != new.get(path)}
    if actual != paths:
        raise ValueError('Complete dependency trees differ from the native PR file inventory')
    documents, size = {}, 0
    for path in sorted(paths):
        if old.get(path, ())[:2] != ('blob', '100644') or new.get(path, ())[:2] != ('blob', '100644'):
            raise ValueError('Dependency exception refuses additions, deletions, modes and symbolic links')
        before, after = blob(api, repository, old[path][2]), blob(api, repository, new[path][2])
        size += len(before.encode()) + len(after.encode())
        if size > 8 * MAX_BYTES:
            raise ValueError('Dependency content exceeds the total byte budget')
        documents[path] = (before, after)
    return {'number': number, 'base': base, 'head': head, 'mergeBase': merge_base, 'documents': documents, 'family': family, 'oldTree': old, 'headTree': new}


def revalidate(api, repository, context):
    latest = api(f'repos/{repository}/pulls/{context["number"]}')
    if identity(repository, latest) != (context['number'], context['base'], context['head']):
        raise ValueError('Dependency PR changed during validation; review the current head')
    return latest


def action_spans(source, path):
    # The admission executable and its pinned Python/PyYAML runtime are built
    # from protected main before any App credentials are present.
    import yaml
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode
    try:
        for index, event in enumerate(yaml.parse(source, Loader=yaml.SafeLoader)):
            if index > 40000:
                raise ValueError('Dependency YAML exceeds parser event bounds')
            if isinstance(event, yaml.AliasEvent) or getattr(event, 'anchor', None) or getattr(event, 'tag', None):
                raise ValueError('Dependency YAML refuses aliases, anchors and explicit tags')
        root = yaml.compose(source, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError('Dependency YAML is not an unambiguous single document') from error
    count = 0
    def validate(node, depth=0):
        nonlocal count
        count += 1
        if depth > 64 or count > 20000:
            raise ValueError('Dependency YAML exceeds structural bounds')
        if isinstance(node, MappingNode):
            keys = set()
            for key, value in node.value:
                if (not isinstance(key, ScalarNode) or key.value in keys or key.value == '<<'
                        or key.tag != 'tag:yaml.org,2002:str'
                        and not (key.value == 'on' and key.tag == 'tag:yaml.org,2002:bool')):
                    raise ValueError('Dependency YAML has duplicate, complex or merged mapping keys')
                keys.add(key.value)
                validate(value, depth + 1)
        elif isinstance(node, SequenceNode):
            for value in node.value:
                validate(value, depth + 1)
        elif not isinstance(node, ScalarNode):
            raise ValueError('Dependency YAML has an unsupported node')
    validate(root)
    def member(node, name):
        if isinstance(node, MappingNode):
            return next((value for key, value in node.value if key.value == name), None)
        return None
    spans = []
    def uses(node):
        value = member(node, 'uses')
        if not isinstance(value, ScalarNode):
            return
        match = PIN.fullmatch(value.value)
        if not match:
            return
        if any(part in ('.', '..') for part in match[1].split('/')):
            raise ValueError('Dependency action path is not canonical')
        start, end = value.start_mark.index, value.end_mark.index
        if value.style is not None or value.start_mark.line != value.end_mark.line or source[start:end] != value.value:
            raise ValueError('Dependency action pin must be a plain single-line scalar')
        line_end = source.find('\n', end)
        line_end = len(source) if line_end < 0 else line_end
        comment = re.fullmatch(r'[ \t]+# (v[0-9]+(?:\.[0-9]+){0,2})[ \t]*', source[end:line_end])
        # Unsupported unchanged pins remain literal bytes, never exceptions.
        if comment:
            spans.append((start, line_end, match[1], match[2], comment[1]))
    def steps(node):
        values = member(node, 'steps')
        if isinstance(values, SequenceNode):
            for step in values.value:
                uses(step)
    if WORKFLOW.fullmatch(path):
        jobs = member(root, 'jobs')
        if not isinstance(jobs, MappingNode):
            raise ValueError('Dependency workflow lacks a jobs mapping')
        for _, job in jobs.value:
            # Existing reusable-workflow pins have the same exact identity rules.
            uses(job)
            steps(job)
    else:
        runs = member(root, 'runs')
        using = member(runs, 'using')
        if not isinstance(using, ScalarNode) or using.value != 'composite':
            raise ValueError('Dependency action is not a composite action')
        steps(runs)
    return spans


def published_tag(api, action, version, sha):
    repository = '/'.join(action.split('/')[:2])
    if not VERSION.fullmatch(version):
        raise ValueError('Unsupported dependency version comment')
    value = api(f'repos/{repository}/git/ref/tags/{quote(version, safe="")}')
    if value.get('ref') != 'refs/tags/' + version:
        raise ValueError('Dependency tag differs from the exact upstream ref')
    target, seen = value.get('object', {}), set()
    for _ in range(8):
        current = target.get('sha')
        if not isinstance(current, str) or not SHA.fullmatch(current) or current in seen:
            raise ValueError('Invalid or cyclic dependency tag identity')
        seen.add(current)
        if target.get('type') == 'commit':
            if current != sha:
                raise ValueError('Dependency pin differs from its upstream published version')
            return
        if target.get('type') != 'tag':
            raise ValueError('Dependency tag does not identify a commit')
        value = api(f'repos/{repository}/git/tags/{current}')
        if value.get('sha') != current:
            raise ValueError('Dependency annotated tag identity mismatch')
        target = value.get('object', {})
    raise ValueError('Dependency tag indirection exceeds bound')


def classify(api, context):
    if context.get('family') == 'nixpkgs-paired-lock':
        return paired_lock(api, context)
    changes = []
    for path, (before, after) in context['documents'].items():
        old, new = action_spans(before, path), action_spans(after, path)
        if len(old) != len(new):
            raise ValueError('Dependency update adds or removes supported Actions pins')
        old_edits, new_edits = [], []
        for previous, current in zip(old, new):
            if previous[2] != current[2]:
                raise ValueError('Dependency update changes action owner, repository or subpath')
            if previous[3:] == current[3:]:
                continue
            if previous[3] == current[3]:
                raise ValueError('Dependency exception requires a changed immutable pin, not just a comment')
            published_tag(api, current[2], current[4], current[3])
            marker = current[2] + '@<reviewed-pin>'
            old_edits.append((previous[0], previous[1], marker))
            new_edits.append((current[0], current[1], marker))
            changes.append({'path': path, 'action': current[2], 'old': previous[3], 'new': current[3], 'version': current[4]})
        def normalized(source, edits):
            for start, end, replacement in reversed(edits):
                source = source[:start] + replacement + source[end:]
            return source
        if not old_edits or normalized(before, old_edits) != normalized(after, new_edits):
            raise ValueError('Dependency update contains changes outside immutable Actions pins/version comments')
    if not changes:
        raise ValueError('Dependency update has no supported pin changes')
    return changes


def immutable_text(api, context, path, *, old=False):
    entries = context['oldTree' if old else 'headTree']
    entry = entries.get(path)
    if not entry or entry[:2] != ('blob', '100644'):
        raise ValueError('Admission requires a regular immutable controller file')
    return blob(api, REPOSITORY, entry[2])


def paired_lock(api, context):
    """Reuse the protected JSON-only synchronizer; never load candidate Python/Nix."""
    source = Path(os.environ.get('XO_NIXPKG_LOCK_SYNC', Path(__file__).resolve().parents[1] / 'sync-dependabot-lock.py'))
    spec = importlib.util.spec_from_file_location('admission_lock_sync', source)
    sync = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync)
    args = [immutable_text(api, context, path, old=old).encode()
            for path, old in [('flake.lock', True), ('flake.lock', False),
                              ('devenv.lock', True), ('devenv.lock', False)]]
    if sync.synchronize(*args) is not None:
        raise UnsupportedFamily('Awaiting trusted JSON-only paired-lock synchronization')
    return [{'family': 'nixpkgs-paired-lock'}]


# Only this exact protected predicate is interpreted. Unknown conditions never
# justify skipping a privileged job during admission of a PR/review event.
NON_PR = "github.event_name != 'pull_request' && github.event_name != 'pull_request_review'"


def read_only_run(api, context, run):
    """Prove the admitted immutable workflow cannot execute privileged jobs.

    This is an execution boundary, not a human merge-approval exception.
    Pin-only deltas retain the reviewed graph; Nix deltas retain all workflows.
    """
    import yaml
    path = run['path']
    source = immutable_text(api, context, path)
    action_spans(source, path)  # bounded parse, rejects aliases/duplicate keys/tags
    document = yaml.load(source, Loader=yaml.BaseLoader)
    def permissions(value):
        if not isinstance(value, dict) or any(v not in ('read', 'none') for v in value.values()):
            raise ValueError('Dependabot execution requires explicit read-only permissions')
    permissions(document.get('permissions'))
    if re.search(r'\bsecrets\b', str({k: v for k, v in document.items() if k != 'jobs'})):
        raise ValueError('Dependabot execution cannot reference secrets')
    seen = set()
    local_count = 0
    def steps(values):
        nonlocal local_count
        if not isinstance(values, list):
            raise ValueError('Admission requires explicit non-reusable steps')
        for step in values:
            uses = step.get('uses', '')
            if not isinstance(uses, str):
                raise ValueError('Invalid immutable action identity')
            if uses.startswith('./'):
                local = uses[2:]
                protected = local.startswith('controller/')
                if protected:
                    local = local[len('controller/'):]
                if not re.fullmatch(r'\.github/actions/[A-Za-z0-9_/-]+', local):
                    raise ValueError('Unsupported local action path')
                if local in seen:
                    raise ValueError('Recursive local action graph')
                local_count += 1
                if local_count > 64 or len(seen) >= 16:
                    raise ValueError('Local action graph exceeds admission bounds')
                seen.add(local)
                action_path = local + '/action.yml'
                if protected:
                    if 'controllerTree' not in context:
                        context['controllerTree'] = tree(api, REPOSITORY, context['base'])
                    trusted = dict(context, headTree=context['controllerTree'])
                    raw = immutable_text(api, trusted, action_path)
                else:
                    raw = immutable_text(api, context, action_path)
                action_spans(raw, action_path)
                if re.search(r'\bsecrets\b', raw):
                    raise ValueError('Local action cannot reference secrets')
                action = yaml.load(raw, Loader=yaml.BaseLoader)
                if action.get('runs', {}).get('using') != 'composite':
                    raise ValueError('Local action must be a bounded composite')
                steps(action['runs'].get('steps'))
                seen.remove(local)
            elif uses and (not PIN.fullmatch(uses) or uses.startswith(('actions/attest', 'actions/cache'))):
                raise ValueError('No reusable, dynamic, attestation or cache-publishing action in admitted jobs')
    for job in document['jobs'].values():
        condition = job.get('if', '')
        if condition in (NON_PR, NON_PR + " && needs.validate.outputs.cache_eligible == 'true'"):
            continue  # always false for both permitted native PR event types
        permissions(job.get('permissions', document['permissions']))
        if re.search(r'\bsecrets\b', str(job)) or 'uses' in job or job.get('runs-on') not in ('ubuntu-24.04', 'ubuntu-slim'):
            raise ValueError('Admitted jobs require isolated hosted runners and no secrets/reusable workflows')
        steps(job.get('steps'))
    return True
