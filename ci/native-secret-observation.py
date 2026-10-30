#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Proposed pure evidence contract. No API calls, credentials, or gate wiring.

Only a future trusted current-main collector may supply these observations.
This module cannot authenticate observations and never grants gate authority.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

POLICY_ID = 'github-native-secret-observation-v1'
REPOSITORY = 'closure-labs/xo-nixpkg'
SHA = re.compile(r'[a-f0-9]{40}')
OPTIONAL_SETTINGS = ('secret_scanning_non_provider_patterns', 'secret_scanning_validity_checks')
POLICY = {
    'schema': 1, 'policyId': POLICY_ID, 'activation': 'protected-main',
    'repository': REPOSITORY,
    'requiredSettings': {'secret_scanning': 'enabled', 'secret_scanning_push_protection': 'enabled'},
    'maxObservationAgeSeconds': 300, 'maxCollectionSeconds': 120,
    'maxAlertPagesPerPass': 20, 'alertsPerPage': 100, 'matchingPasses': 2,
    'maxOpenAlerts': 0, 'assurance': 'posture-and-alert-observation-only',
}


class Blocked(ValueError):
    """Fixed safe categories only; never include API payloads in exceptions."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def stamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
            'timestamp-schema')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise Blocked('timestamp-schema') from None


def posture(raw):
    require(isinstance(raw, dict), 'posture-schema')
    analysis = raw.get('security_and_analysis')
    require(isinstance(analysis, dict), 'posture-inaccessible')
    result = {}
    for name in POLICY['requiredSettings']:
        item = analysis.get(name)
        require(isinstance(item, dict) and item.get('status') == 'enabled', 'posture-not-enabled')
        result[name] = 'enabled'
    for name in OPTIONAL_SETTINGS:
        value = analysis.get(name)
        if value is None:
            result[name] = 'unavailable'
        else:
            require(isinstance(value, dict) and value.get('status') in ('enabled', 'disabled'),
                    'posture-schema')
            result[name] = value['status']
    return result


def inventory(pages):
    require(isinstance(pages, list) and 1 <= len(pages) <= POLICY['maxAlertPagesPerPass'],
            'pagination-bound')
    seen = {}
    for number, page in enumerate(pages, start=1):
        require(isinstance(page, dict), 'page-schema')
        expected_path = (f'/repos/{REPOSITORY}/secret-scanning/alerts?'
                         f'state=open&hide_secret=true&per_page=100&page={number}')
        require(page.get('origin') == 'https://api.github.com'
                and page.get('requestPath') == expected_path, 'request-scope')
        require(type(page.get('httpStatus')) is int and page['httpStatus'] == 200, 'api-error')
        require(page.get('hideSecret') is True, 'hidden-secret-required')
        require(type(page.get('hasNext')) is bool
                and page['hasNext'] == (number < len(pages)), 'pagination-incomplete')
        rows = page.get('alerts')
        require(isinstance(rows, list) and len(rows) <= POLICY['alertsPerPage'], 'page-schema')
        for row in rows:
            require(isinstance(row, dict), 'alert-schema')
            # Reject an unsupported hide_secret response; never retry without it.
            require(row.get('secret') in (None, ''), 'secret-not-hidden')
            identity = row.get('number')
            require(type(identity) is int and 0 < identity <= 2**53 - 1, 'alert-id-schema')
            require(identity not in seen, 'duplicate-alert-id')
            require(row.get('state') == 'open', 'alert-state-race')
            created, updated = stamp(row.get('created_at')), stamp(row.get('updated_at'))
            require(updated >= created, 'alert-time-order')
            # Explicit projection: ignore paths, content, URLs, comments and type labels.
            seen[identity] = {'number': identity, 'state': 'open',
                              'createdAt': row['created_at'], 'updatedAt': row['updated_at']}
    return [seen[number] for number in sorted(seen)]


def propose_receipt(*, policy, repository, candidate_before, candidate_after,
                    main_before, main_after, posture_before, posture_after,
                    passes, started_at, completed_at, now):
    require(isinstance(policy, dict) and canonical(policy) == canonical(POLICY), 'policy-schema-or-version')
    require(repository == REPOSITORY, 'repository-scope')
    for identity in (candidate_before, candidate_after, main_before, main_after):
        require(isinstance(identity, str) and SHA.fullmatch(identity), 'head-schema')
    require(candidate_before == candidate_after and main_before == main_after, 'head-race')
    start, end = stamp(started_at), stamp(completed_at)
    require(isinstance(now, datetime) and now.tzinfo is not None, 'clock-schema')
    now = now.astimezone(timezone.utc)
    require(start <= end <= now + timedelta(seconds=5), 'clock-order')
    require((end - start).total_seconds() <= POLICY['maxCollectionSeconds'], 'collection-expired')
    require(end <= now and timedelta(0) <= now - start <= timedelta(seconds=POLICY['maxObservationAgeSeconds']),
            'observation-expired')
    before, after = posture(posture_before), posture(posture_after)
    require(before == after, 'posture-race')
    require(isinstance(passes, list) and len(passes) == POLICY['matchingPasses'], 'pass-count')
    first, second = [inventory(pages) for pages in passes]
    require(first == second, 'alert-inventory-race')
    require(len(first) <= POLICY['maxOpenAlerts'], 'open-alerts')
    return {
        'schema': 1, 'policyId': POLICY_ID,
        'policySha256': hashlib.sha256(canonical(POLICY)).hexdigest(),
        'repository': REPOSITORY, 'candidateSha': candidate_before,
        'protectedMainSha': main_before, 'observedAt': completed_at,
        'expiresAt': (start + timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'settings': after, 'openAlertCount': 0, 'alertIds': [],
        'passes': 2, 'pagesPerPass': [len(x) for x in passes],
        'paginationComplete': True, 'status': 'observed',
        'assurance': 'posture-and-alert-observation-only',
        'fullHistoryCompletionClaim': False, 'exactCommitScanCompletionClaim': False,
        'authorityClaim': False, 'reuseEligible': False, 'activation': 'protected-main',
    }
