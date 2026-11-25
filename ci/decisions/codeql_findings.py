# SPDX-License-Identifier: Apache-2.0
"""Evaluate authenticated queue SARIF against the exact protected-base analysis."""
import decimal
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode

import common
import native_approvals as native

LANGUAGES = ('actions', 'javascript-typescript', 'python')
WORKFLOW = '.github/workflows/codeql.yml'
PREFIX = 'repos/' + native.REPOSITORY


def validate_analysis(value, revision, ref, language, upload=None):
    common.require(isinstance(value, dict) and type(value.get('id')) is int and value['id'] > 0
                   and value.get('commit_sha') == revision and value.get('ref') == ref
                   and value.get('category') == '/language:' + language
                   and value.get('analysis_key') == WORKFLOW + ':analyze-protected'
                   and value.get('tool', {}).get('name') == 'CodeQL'
                   and value.get('error') == '' and value.get('warning', '') == ''
                   and type(value.get('rules_count')) is int and value['rules_count'] > 0
                   and type(value.get('results_count')) is int and value['results_count'] >= 0
                   and (upload is None or value.get('sarif_id') == upload),
                   'CodeQL analysis identity, coverage or health differs')
    return value


def select_analysis(api, revision, ref, language, upload=None):
    query = {'ref': ref, 'tool_name': 'CodeQL', 'per_page': 100}
    if upload is not None:
        query['sarif_id'] = upload
    # Newest matching analysis is authoritative; an unhealthy retry cannot fall
    # back to an older success. Stop at the exact base rather than reading history.
    for page in range(1, 11):
        values = api(PREFIX + '/code-scanning/analyses?' + urlencode(dict(query, page=page)))
        common.require(isinstance(values, list) and len(values) <= 100, 'Incomplete CodeQL analysis inventory')
        matching = [v for v in values if isinstance(v, dict) and v.get('commit_sha') == revision
                    and v.get('category') == '/language:' + language]
        if matching:
            common.require(upload is None or len(matching) == 1, 'Ambiguous CodeQL upload')
            return validate_analysis(matching[0], revision, ref, language, upload)
        if len(values) < 100:
            break
    raise ValueError('Exact CodeQL analysis unavailable; rerun analysis for the protected base')


def blocking_findings(document, analysis):
    common.require(isinstance(document, dict) and document.get('version') == '2.1.0'
                   and isinstance(document.get('runs'), list) and len(document['runs']) == 1,
                   'Incomplete CodeQL SARIF')
    run = document['runs'][0]
    common.require(run.get('tool', {}).get('driver', {}).get('name') == 'CodeQL'
                   and run.get('automationDetails', {}).get('id', '').rstrip('/') == analysis['category']
                   and isinstance(run.get('results'), list)
                   and len(run['results']) == analysis['results_count'], 'CodeQL SARIF coverage differs')
    provenance = run.get('versionControlProvenance', [])
    common.require(len(provenance) == 1 and provenance[0].get('revisionId') == analysis['commit_sha']
                   and provenance[0].get('branch') == analysis['ref']
                   and provenance[0].get('repositoryUri') == 'https://github.com/' + native.REPOSITORY,
                   'CodeQL SARIF source differs')
    rules = {}
    for component in [run['tool']['driver'], *run['tool'].get('extensions', [])]:
        for rule in component.get('rules', []):
            rule_id = rule.get('id')
            common.require(isinstance(rule_id, str) and rule_id and rule_id not in rules,
                           'Ambiguous CodeQL rule metadata')
            rules[rule_id] = rule
    blocked = set()
    for result in run['results']:
        rule_id = result.get('ruleId')
        common.require(rule_id in rules, 'CodeQL result lacks rule metadata')
        rule = rules[rule_id]
        level = result.get('level', rule.get('defaultConfiguration', {}).get('level', 'warning'))
        common.require(level in ('none', 'note', 'warning', 'error'), 'Unknown CodeQL result level')
        properties = rule.get('properties', {})
        score = properties.get('security-severity')
        common.require(score is not None or 'security' not in properties.get('tags', []),
                       'Security rule lacks severity metadata')
        if score is not None:
            try:
                score = decimal.Decimal(str(score))
            except decimal.InvalidOperation:
                raise ValueError('Invalid CodeQL security severity') from None
            common.require(score.is_finite() and 0 <= score <= 10, 'Invalid CodeQL security severity')
            score = score.normalize()
        if level == 'error' or score is not None and score >= 7:
            # GitHub's authenticated SARIF supplies stable alert identities even
            # when source lines move. Counts alone cannot establish a baseline.
            number = result.get('properties', {}).get('github/alertNumber')
            common.require(type(number) is int and number > 0, 'Blocking CodeQL result lacks alert identity')
            blocked.add((number, rule_id, level, str(score)))
    return blocked


def read_sarif(analysis):
    raw = common.command(['gh', 'api', '--method', 'GET', '-H', 'Accept: application/sarif+json',
                          PREFIX + '/code-scanning/analyses/' + str(analysis['id'])], timeout=30)
    common.require(len(raw.encode()) <= 50 * 1024 * 1024, 'CodeQL SARIF exceeds bounded size')
    return json.loads(raw)


def verify(language, upload, event, run_id, attempt, api=None, sarif=None):
    api, sarif = api or common.authority.github_api, sarif or read_sarif
    common.require(language in LANGUAGES and isinstance(upload, str)
                   and re.fullmatch(r'[0-9a-fA-F-]{36}', upload), 'Invalid CodeQL upload selection')
    group = event.get('merge_group', {})
    revision, base, ref = group.get('head_sha'), group.get('base_sha'), group.get('head_ref')
    common.require(all(isinstance(v, str) and common.SHA.fullmatch(v) for v in (revision, base))
                   and group.get('base_ref') == 'refs/heads/main' and isinstance(ref, str)
                   and ref.startswith('refs/heads/gh-readonly-queue/main/') and ref.endswith('-' + base)
                   and type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
                   'Invalid CodeQL merge-group identity')
    run = api(PREFIX + f'/actions/runs/{run_id}/attempts/{attempt}')
    common.require(run.get('id') == run_id and run.get('run_attempt') == attempt
                   and run.get('event') == 'merge_group' and run.get('path') == WORKFLOW
                   and run.get('head_sha') == revision and run.get('head_branch') == ref.removeprefix('refs/heads/')
                   and run.get('repository', {}).get('full_name') == native.REPOSITORY
                   and run.get('head_repository', {}).get('full_name') == native.REPOSITORY,
                   'CodeQL run or attempt differs from the merge candidate')
    current = common.main_revision({'repository': native.REPOSITORY}, api)
    common.require(api(PREFIX + f'/compare/{base}...{current}').get('status') in ('ahead', 'identical'),
                   'CodeQL baseline is not protected main ancestry')
    candidate = select_analysis(api, revision, ref, language, upload)
    baseline = select_analysis(api, base, 'refs/heads/main', language)
    new = blocking_findings(sarif(candidate), candidate) - blocking_findings(sarif(baseline), baseline)
    common.require(not new, 'New blocking CodeQL findings on the merge candidate: '
                   + ', '.join(str(item[0]) for item in sorted(new)))
    return {'schema': 1, 'status': 'verified', 'language': language, 'revision': revision,
            'baseRevision': base, 'runId': run_id, 'runAttempt': attempt,
            'analysisId': candidate['id'], 'baselineAnalysisId': baseline['id'], 'newBlockingFindings': 0}


def main():
    common.require(os.environ.get('GITHUB_REPOSITORY') == native.REPOSITORY
                   and os.environ.get('GITHUB_EVENT_NAME') == 'merge_group', 'Queue CodeQL validation requires its native event')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    common.require(event.get('merge_group', {}).get('head_sha') == os.environ.get('GITHUB_SHA'), 'CodeQL checkout differs')
    common.emit(verify(os.environ['CODEQL_LANGUAGE'], os.environ['CODEQL_UPLOAD'], event,
                       int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])))
