"""One gate's immutable Git facts; never mutable GitHub authority surfaces."""
import json
import re

import decision_authority as authority


class GateReads:
    MAX_ENTRIES = 256
    MAX_BYTES = 8 * 1024**2

    def __init__(self, repository, api):
        self.api = api
        self.entries = {}
        self.bytes = 0
        self.hits = 0
        self.pattern = None
        if isinstance(repository, str) and authority.REPOSITORY.fullmatch(repository):
            prefix = re.escape('repos/' + repository)
            self.pattern = re.compile(
                prefix + r'/(?:contents/automation/decisions/(?:security|releases)/[a-f0-9]{64}'
                r'\.json\?ref=[a-f0-9]{40}|compare/[a-f0-9]{40}\.\.\.[a-f0-9]{40})')

    @staticmethod
    def fact(endpoint, value):
        if not isinstance(value, dict):
            return None
        if '/compare/' in endpoint:
            # A failed ancestry result is not reused, even though SHA ancestry
            # itself is immutable. Callers retain all existing failure checks.
            return {'status': value['status']} if value.get('status') in ('ahead', 'identical') else None
        if (value.get('type') != 'file' or value.get('encoding') not in ('base64', 'none')
                or type(value.get('size')) is not int
                or not 0 < value['size'] <= authority.MAX_PROPOSAL_BYTES
                or not isinstance(value.get('sha'), str) or not authority.SHA.fullmatch(value['sha'])
                or value.get('target') is not None or value.get('submodule_git_url') is not None):
            return None
        if value['encoding'] == 'base64':
            # Validate inline bytes before retaining metadata. Large Git blobs
            # are still fetched/hashed/reparsed by document_blob on each use.
            try:
                authority.decode_blob(value, value['sha'], value['size'])
            except (ValueError, TypeError):
                return None
        return {key: value[key] for key in ('type', 'encoding', 'size', 'sha')} | {
            'content': value.get('content', '') if value['encoding'] == 'base64' else ''}

    def __call__(self, endpoint):
        eligible = bool(self.pattern and isinstance(endpoint, str) and self.pattern.fullmatch(endpoint))
        if eligible and endpoint in self.entries:
            self.hits += 1
            return dict(self.entries[endpoint])
        value = self.api(endpoint)  # Exceptions, errors and unknown endpoints stay live.
        fact = self.fact(endpoint, value) if eligible else None
        if fact is not None:
            size = len(endpoint.encode()) + len(json.dumps(fact, separators=(',', ':')).encode())
            if len(self.entries) < self.MAX_ENTRIES and self.bytes + size <= self.MAX_BYTES:
                self.entries[endpoint] = fact
                self.bytes += size
        return value
