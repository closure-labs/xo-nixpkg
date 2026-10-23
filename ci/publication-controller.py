#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish admitted immutable products with a compare-and-swap Git ref journal."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import sys
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import publication_receipts
import destinations
import operations
from contextlib import contextmanager


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def api(repository, endpoint, body=None, method=None, missing=False, timeout=None):
    args = ['gh', 'api', f'repos/{repository}/{endpoint}']
    if body is not None:
        args += ['--method', method or 'POST', '--input', '-']
    result = operations.run(args, input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, check=False, timeout=timeout or 30)
    if result.returncode:
        if missing and 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError('GitHub journal API failed: ' + endpoint)
    return json.loads(result.stdout)


def commit_sha(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('publication journal returned invalid commit identity')
    return value


def reference_sha(value, branch):
    if (not isinstance(value, dict) or value.get('ref') != 'refs/heads/' + branch
            or not isinstance(value.get('object'), dict) or value['object'].get('type') != 'commit'):
        raise ValueError('publication journal returned invalid reference identity')
    try:
        return commit_sha(value['object'].get('sha'))
    except ValueError:
        raise ValueError('publication journal returned invalid reference commit identity') from None


def readback_error(reason, expected, observed, prior, attempts):
    # Only validated immutable identities and a bounded attempt count are safe
    # diagnostics. A stale observation alone does not establish another writer.
    return ValueError('publication journal ' + reason + ': expected=' + expected
                      + ' observed=' + (observed or 'none') + ' knownPrior=' + (prior or 'none')
                      + ' attempts=' + str(attempts))


class Journal:
    def __init__(self, repository, product, authorize=None):
        self.authorize = authorize or (lambda: None)
        self.save_attempts = 0
        self.repository = repository
        self.digest = hashlib.sha256(canonical(product)).hexdigest()
        self.branch = 'automation/publication-' + self.digest
        ref = api(repository, 'git/ref/heads/' + self.branch, missing=True)
        self.commit = reference_sha(ref, self.branch) if ref is not None else None
        if self.commit:
            commit = api(repository, 'git/commits/' + self.commit)
            tree = api(repository, 'git/trees/' + commit['tree']['sha'])
            if len(tree['tree']) != 1 or tree['tree'][0]['path'] != 'journal.json':
                raise ValueError('unexpected publication journal tree')
            blob = api(repository, 'git/blobs/' + tree['tree'][0]['sha'])
            import base64
            self.value = json.loads(base64.b64decode(blob['content']))
            receipts = publication_receipts.read(self.value, self.digest)
            complete = {step['name'] for step in self.value.get('steps', []) if step.get('state') == 'complete'}
            if not set(receipts) <= complete:
                raise ValueError('Receipt without completed destination')
        else:
            self.value = {'schema': 1, 'productHash': self.digest, 'steps': []}
            self.save()

    def save(self):
        self.save_attempts += 1
        self.authorize()
        tree = api(self.repository, 'git/trees', {'tree': [{'path': 'journal.json', 'mode': '100644',
            'type': 'blob', 'content': json.dumps(self.value, sort_keys=True, indent=2) + '\n'}]})
        body = {'message': 'Record immutable publication ' + self.digest, 'tree': tree['sha'],
                'parents': [self.commit] if self.commit else []}
        commit = api(self.repository, 'git/commits', body)
        expected = commit_sha(commit.get('sha'))
        prior = self.commit
        if prior:
            # A concurrent writer produces a sibling commit; force=false refuses
            # its non-fast-forward update instead of losing either checkpoint.
            acknowledged = api(self.repository, 'git/refs/heads/' + self.branch,
                               {'sha': expected, 'force': False}, method='PATCH')
        else:
            acknowledged = api(self.repository, 'git/refs',
                               {'ref': 'refs/heads/' + self.branch, 'sha': expected})
        try:
            observed = reference_sha(acknowledged, self.branch)
        except ValueError:
            raise readback_error('write acknowledgement has invalid reference', expected, None, prior, 0) from None
        if observed != expected:
            raise readback_error('write acknowledgement differs', expected, observed, prior, 0)
        deadline = time.monotonic() + 4
        observed = prior
        for attempt in range(1, 6):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise readback_error('readback deadline exceeded', expected, observed or 'none', prior, attempt - 1)
            try:
                live = api(self.repository, 'git/ref/heads/' + self.branch, missing=True, timeout=remaining)
            except subprocess.TimeoutExpired:
                raise readback_error('readback deadline exceeded', expected, observed or 'none', prior, attempt) from None
            except (RuntimeError, ValueError):
                raise readback_error('readback API failed', expected, observed or 'none', prior, attempt) from None
            try:
                observed = reference_sha(live, self.branch) if live is not None else None
            except ValueError:
                raise readback_error('readback returned invalid reference', expected, None, prior, attempt) from None
            if observed == expected:
                self.commit = expected
                return
            if observed != prior:
                raise readback_error('unexpected readback head', expected, observed, prior, attempt)
            remaining = deadline - time.monotonic()
            if attempt == 5 or remaining <= 0:
                raise readback_error('readback remained at known prior head', expected, observed, prior, attempt)
            # Retry only the exact previous head (or confirmed prior absence),
            # never another writer's head or a general API failure.
            time.sleep(min(.5, remaining))

    def complete(self, name, identity, proof=None):
        if proof is not None:
            publication_receipts.validate(proof, self.digest, name)
            prior = self.value.get('receipts', {}).get(name)
            if prior and all(canonical(prior[k]) == canonical(proof[k]) for k in ('expected', 'observed', 'verifier')):
                self.authorize()
                return
            self.value.update(schema=2, receipts={**self.value.get('receipts', {}), name: proof})
        existing = next((step for step in self.value['steps'] if step['name'] == name), None)
        if existing:
            if existing['identity'] != identity and name != 'handoff':
                raise ValueError('conflicting immutable publication step')
            existing.update(state='complete', identity=identity)
        else:
            self.value['steps'].append({'name': name, 'state': 'complete', 'identity': identity})
        self.save()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def publish_handoff(directory, scans, repository, source_revision):
    """Keep registry credentials scoped while preserving current scan provenance."""
    import decision_packets as packets
    packets.REGISTRY = 'ghcr.io/' + repository.lower() + '-products'
    packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
    registry_token = os.environ['REGISTRY_TOKEN']
    previous_config = os.environ.get('DOCKER_CONFIG')
    try:
        with tempfile.TemporaryDirectory(prefix='xo-publication-registry-') as registry_config:
            os.environ['DOCKER_CONFIG'] = registry_config
            run('oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'],
                '--password-stdin', input=registry_token, text=True)
            try:
                run('xo-nixpkg-publication-gate')
                producer = dict(scans['producer'], repository=repository,
                                revision=scans['producer'].get('revision', source_revision),
                                sourceRevision=source_revision)
                return packets.push(directory, producer)
            finally:
                run('oras', 'logout', 'ghcr.io')
    finally:
        if previous_config is None:
            os.environ.pop('DOCKER_CONFIG', None)
        else:
            os.environ['DOCKER_CONFIG'] = previous_config


@contextmanager
def registry():
    previous = os.environ.get('DOCKER_CONFIG')
    try:
        with tempfile.TemporaryDirectory(prefix='xo-publication-registry-') as directory:
            os.environ['DOCKER_CONFIG'] = directory
            run('oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'],
                '--password-stdin', input=os.environ['REGISTRY_TOKEN'], text=True)
            try:
                yield
            finally:
                run('oras', 'logout', 'ghcr.io')
    finally:
        if previous is None: os.environ.pop('DOCKER_CONFIG', None)
        else: os.environ['DOCKER_CONFIG'] = previous


def source_descriptor(source):
    import decision_packets as packets
    packets.REGISTRY='ghcr.io/closure-labs/xo-nixpkg-decisions'
    packets.REFERENCE=re.compile(re.escape(packets.REGISTRY)+r'@sha256:[0-9a-f]{64}')
    with registry(), operations.budget(90), tempfile.TemporaryDirectory() as temp:
        _, members = packets.inspect(source['reference'])
        descriptor = packets.packet_descriptor(packets.fetch_member('decision-packet.json', Path(temp), members),
                                                members, source['sha256'])
        if descriptor['producer'] != source['producer']:
            raise ValueError('Source packet producer differs')
        return descriptor


def remote_handoff(source, descriptor, observations=None):
    """Copy admitted immutable OCI content once; retries inspect manifest and descriptor only."""
    import decision_packets as packets
    destination = 'ghcr.io/' + os.environ['GITHUB_REPOSITORY'].lower() + '-products'
    expected_reference = destination + '@' + source['reference'].split('@')[1]
    with registry():
        # Only an authenticated OCI MANIFEST_UNKNOWN / NAME_UNKNOWN means missing.
        probe = packets.command(['oras', 'manifest', 'fetch', expected_reference], allow_missing=True)
        if probe is None:
            tag=destination+':packet-'+source['sha256']
            tagged=packets.command(['oras','manifest','fetch',tag], allow_missing=True)
            if tagged is not None:
                if hashlib.sha256(tagged).hexdigest()!=source['reference'].split(':')[-1]:
                    raise ValueError('Public OCI tag conflicts with approved packet')
                raise ValueError('Public OCI digest readback unavailable')
            run('xo-nixpkg-publication-gate')
            with operations.budget(900):
                if observations is not None:
                    observations['handoffCopyAttempts'] += 1
                packets.command(['oras','copy',source['reference'],destination+':packet-'+source['sha256']])
        old_registry,old_reference=packets.REGISTRY,packets.REFERENCE
        try:
            packets.REGISTRY=destination
            packets.REFERENCE=re.compile(re.escape(destination)+r'@sha256:[0-9a-f]{64}')
            with operations.budget(90), tempfile.TemporaryDirectory() as temp:
                _, members=packets.inspect(expected_reference)
                actual=packets.packet_descriptor(packets.fetch_member('decision-packet.json',Path(temp),members),members,source['sha256'])
                if canonical(actual)!=canonical(descriptor):
                    raise ValueError('Public handoff conflicts with approved packet')
        finally:
            packets.REGISTRY,packets.REFERENCE=old_registry,old_reference
    return dict(source,reference=expected_reference)


def verify_tag(repository, tag, revision):
    value=api(repository,'git/ref/tags/'+tag,missing=True)
    if value is None: return False
    if value.get('ref')!='refs/tags/'+tag:raise ValueError('Remote tag reference differs')
    obj=value.get('object',{})
    for _ in range(8):
        if obj.get('type')=='commit':
            if commit_sha(obj.get('sha'))!=revision: raise ValueError('Remote tag conflicts with approved revision')
            return True
        if obj.get('type')!='tag': break
        obj=api(repository,'git/tags/'+commit_sha(obj.get('sha'))).get('object',{})
    raise ValueError('Remote tag has invalid identity')


def main():
    # Diagnostics never supply authority or select a publication operation.
    result_path = Path(os.environ['RUNNER_TEMP']) / 'publication-result.json' if os.environ.get('RUNNER_TEMP') else None
    if result_path is not None:
        result_path.unlink(missing_ok=True)
    observations = dict(closurePacketFetches=0, cachePublishInvocations=0,
                        handoffCopyAttempts=0, handoffPushInvocations=0, xoTagLeafInvocations=0,
                        projectTagInvocations=0, releasePublishInvocations=0,
                        xoTagRequired=False)
    directory=Path(os.environ['XO_NIXPKG_EVIDENCE']).resolve()
    product=json.loads((directory/'product.json').read_text())
    scans=json.loads((directory/'scans.json').read_text())
    repository,revision=product['repository'],product['revision']
    os.environ['GATED_SHA']=revision
    os.environ['XO_NIXPKG_PUBLICATION_PURPOSE']=os.environ.get('XO_NIXPKG_PUBLICATION_PURPOSE','release')
    run('xo-nixpkg-publication-gate')
    controller_revision = commit_sha(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip())
    os.environ['BASE_SHA']=subprocess.check_output(['git','rev-parse',revision+'^'],text=True).strip()
    source_path=directory.with_suffix('.source.json')
    source=json.loads(source_path.read_text()) if source_path.exists() else None
    descriptor=source_descriptor(source) if source else None
    if descriptor:
        for name in ('product.json','scans.json'):
            path=directory/name; record=descriptor['files'].get(name,{})
            if path.is_symlink() or not path.is_file() or path.stat().st_size!=record.get('size') or hashlib.sha256(path.read_bytes()).hexdigest()!=record.get('sha256'):
                raise ValueError('Source packet differs from gated metadata bytes')
        producer=dict(scans['producer'],repository=repository,
                      revision=scans['producer'].get('revision',revision),sourceRevision=revision)
        if canonical(descriptor['producer'])!=canonical(producer):
            raise ValueError('Source packet differs from gated producer')
    for name,expected in product['assets'].items():
        if descriptor:
            if descriptor['files'].get(name,{}).get('sha256')!=expected:
                raise ValueError('Publication asset differs from approved immutable bytes')
        else:
            path=directory/name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                raise ValueError('Publication asset differs from approved immutable bytes')
    journal=Journal(repository,product,authorize=lambda: run('xo-nixpkg-publication-gate'))
    state=destinations.cache(product,os.environ['XO_NIXPKG_CACHIX_CACHE_URL'])
    if state['status'] in ('conflict','unavailable'):
        raise ValueError('Public cache '+state['status'])
    if state['status']!='verified':
        if source:
            import decision_packets as packets
            with registry(), tempfile.TemporaryDirectory() as temp:
                target=Path(temp)/'evidence'
                observations['closurePacketFetches'] += 1
                packets.fetch(source['reference'],target,source['sha256'])
                (target/'decision-packet.json').unlink()
                for path in target.rglob('*'):
                    if path.is_file():
                        relative=path.relative_to(target); output=directory/relative
                        packets.install_member(path, output, directory)
        observations['cachePublishInvocations'] += 1
        run('xo-nixpkg-publish')
        state=destinations.cache(product,os.environ['XO_NIXPKG_CACHIX_CACHE_URL'])
    proof=destinations.receipt(state,product)
    journal.complete('cache', {'products':product['products'],'roots':product.get('roots',{})},proof)
    if source:
        packet=remote_handoff(source,descriptor,observations)
    else:
        observations['handoffPushInvocations'] += 1
        packet=publish_handoff(directory,scans,repository,revision)
    if not source:
        # Historical artifact recovery must also read the immutable public manifest.
        import decision_packets as packets
        old_registry,old_reference=packets.REGISTRY,packets.REFERENCE
        try:
            packets.REGISTRY=packet['reference'].split('@')[0]
            packets.REFERENCE=re.compile(re.escape(packets.REGISTRY)+r'@sha256:[0-9a-f]{64}')
            packets.metadata(packet['reference'],packet['sha256'],'product.json',producer=packet['producer'])
        finally: packets.REGISTRY,packets.REFERENCE=old_registry,old_reference
    journal.complete('handoff',packet,destinations.receipt(destinations.result('handoff',packet,packet),product))
    if os.environ['XO_NIXPKG_PUBLICATION_PURPOSE']=='release':
        observations['xoTagLeafInvocations'] += 1
        run('xo-nixpkg-tag-xo-release')
        before=json.loads(subprocess.check_output(['git','show',os.environ['BASE_SHA']+':nix/sources/xen-orchestra.json']))['channels']['latest']
        after=json.loads(subprocess.check_output(['git','show',revision+':nix/sources/xen-orchestra.json']))['channels']['latest']
        xo_identity={'revision':revision,'required':(before['version'],before['rev'])!=(after['version'],after['rev'])}
        observations['xoTagRequired'] = xo_identity['required']
        if xo_identity['required']:
            version=after['version']; tag='v'+version+('.0' if version.count('.')==1 else '')
            if not verify_tag(repository,tag,revision):raise ValueError('XO tag readback missing')
            xo_identity['tag']=tag
        journal.complete('xo-tag',{'revision':revision},destinations.receipt(destinations.result('xo-tag',xo_identity,xo_identity),product))
        version=subprocess.check_output(['git','show',revision+':VERSION'],text=True).strip();tag='v'+version
        existing=subprocess.run(['git','rev-parse','--verify',tag+'^{commit}'],capture_output=True,text=True)
        if existing.returncode==0 and existing.stdout.strip()!=revision:
            # Preserve independent historical project version policy; no new checkpoint.
            print('Project version already released; package publication is complete.')
        else:
            if not verify_tag(repository,tag,revision):
                observations['projectTagInvocations'] += 1
                run('xo-nixpkg-tag-release')
            if not verify_tag(repository,tag,revision):raise ValueError('Project tag readback missing')
            identity={'tag':tag,'revision':revision}
            journal.complete('project-tag',identity,destinations.receipt(destinations.result('project-tag',identity,identity),product))
            observations['releasePublishInvocations'] += 1
            run('xo-nixpkg-publish-release')
            release=api(repository,'releases/tags/'+tag)
            if release.get('tag_name')!=tag or release.get('draft') is not False or not verify_tag(repository,tag,revision):
                raise ValueError('GitHub release readback differs')
            journal.complete('github-release',identity,destinations.receipt(destinations.result('github-release',identity,identity),product))
    observations['journalSaveAttempts'] = journal.save_attempts
    result = {'schema':1, 'status':'verified', 'productHash':journal.digest,
              'journalRef':journal.branch, 'sourceRevision':revision,
              'controllerRevision':controller_revision,
              'producer':scans['producer'], 'metadataSourceAvailable':source is not None,
              'operations':observations}
    if result_path is not None:
        # Replace the final name atomically; never follow an existing symlink.
        with tempfile.NamedTemporaryFile(mode='w', dir=result_path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                json.dump(result, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.replace(temporary, result_path)
            finally:
                temporary.unlink(missing_ok=True)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
