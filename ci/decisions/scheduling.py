# SPDX-License-Identifier: Apache-2.0
"""Versioned scheduling data; it never grants authority or contains commands."""
import re

ACTIONS = {'inspect', 'materialize', 'refresh', 'publish', 'wait', 'none'}
REASONS = {'producer-active', 'publication-active', 'publication-observed', 'observations-expired',
           'evidence-required', 'no-candidate', 'not-admitted', 'destinations-verified'}


def result(repository, source, controller, run_id, attempt, action, reason, product_hash=None, packet=None):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or any(not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{40}', value)
                   for value in (source, controller))
            or type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt <= 0
            or action not in ACTIONS or reason not in REASONS
            or product_hash is not None and not re.fullmatch(r'[a-f0-9]{64}', product_hash)
            or packet is not None and (not isinstance(packet, dict) or set(packet) != {'reference', 'sha256'}
                or not re.fullmatch(r'ghcr.io/[A-Za-z0-9_./-]+@sha256:[a-f0-9]{64}', packet['reference'])
                or not re.fullmatch(r'[a-f0-9]{64}', packet['sha256']))):
        raise ValueError('Invalid scheduling identity or outcome')
    return {'schema': 1, 'repository': repository, 'sourceRevision': source,
            'controllerRevision': controller, 'producer': {'runId': run_id, 'runAttempt': attempt},
            'productHash': product_hash, 'packet': packet, 'action': action, 'reason': reason,
            'authorityClaim': False}

def observation_expiry(native, cfg):
    """Scheduling freshness mirrors evidence/database clocks without granting admission."""
    import datetime as dt
    def timestamp(value):
        if not isinstance(value, str):
            raise ValueError('Observation timestamp required')
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('Observation timestamp requires timezone')
        return result
    now = dt.datetime.now(dt.timezone.utc)
    scanned, expires = timestamp(native.get('scannedAt')), timestamp(native.get('expiresAt'))
    evidence_hours, database_hours = cfg.get('maxEvidenceAgeHours', 24), cfg.get('maxDatabaseAgeHours', 48)
    if (type(evidence_hours) is not int or not 0 < evidence_hours <= 48
            or type(database_hours) is not int or not 0 < database_hours <= 168
            or not scanned <= now or not scanned < expires
            or expires - scanned > dt.timedelta(hours=evidence_hours)):
        raise ValueError('Invalid observation envelope')
    profiles = native.get('profiles')
    if not isinstance(profiles, dict) or not profiles or set(profiles) != set(cfg['profiles']):
        raise ValueError('Incomplete observation profile coverage')
    deadlines = [expires]
    for profile in profiles.values():
        if profile.get('status') != 'complete' or profile.get('scannerHealth') != 'healthy':
            raise ValueError('Unhealthy observation metadata')
        observed = timestamp(profile.get('scannedAt'))
        database = profile.get('database', {})
        built = timestamp(database.get('built'))
        if (database.get('valid') is not True or not built <= observed <= now or observed < scanned
                or observed - built > dt.timedelta(hours=database_hours)):
            raise ValueError('Invalid observation database metadata')
        deadlines.append(built + dt.timedelta(hours=database_hours))
    return min(deadlines)
