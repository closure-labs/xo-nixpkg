#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normalize raw scanner evidence without reducing severity or hiding observations."""
import datetime
import json
import math
import os
from pathlib import Path
import sys


def advisory_risk(match):
    related = match.get('relatedVulnerabilities', [])
    if not isinstance(related, list):
        raise ValueError('invalid related advisory records')
    advisories = [match['vulnerability'], *related]
    levels = ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']
    severities, aliases, cvss = [], set(), []
    exploited = False
    for advisory in advisories:
        if (not isinstance(advisory, dict) or not isinstance(advisory.get('id'), str)
                or not advisory['id']):
            raise ValueError('invalid scanner advisory identity')
        aliases.add(advisory['id'])
        related_aliases = advisory.get('aliases', [])
        if (not isinstance(related_aliases, list)
                or any(not isinstance(alias, str) or not alias for alias in related_aliases)):
            raise ValueError('invalid scanner advisory aliases')
        aliases.update(related_aliases)
        severity = advisory.get('severity', 'Unknown')
        if severity not in levels:
            raise ValueError('unsupported scanner severity')
        severities.append(severity)
        records = advisory.get('cvss', [])
        if not isinstance(records, list):
            raise ValueError('invalid scanner CVSS records')
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get('metrics'), dict):
                raise ValueError('invalid scanner CVSS record')
            score = record['metrics'].get('baseScore')
            if (type(score) not in (int, float) or not math.isfinite(score)
                    or not 0 <= score <= 10):
                raise ValueError('invalid scanner CVSS base score')
        cvss.extend(records)
        known = advisory.get('knownExploited', [])
        if (type(known) is not bool and (not isinstance(known, list)
                or any(not isinstance(record, dict) for record in known))):
            raise ValueError('invalid scanner exploitation metadata')
        exploited = exploited or bool(known)
    return {'aliases': sorted(aliases), 'severity': severities[0],
            'admissionSeverity': max(severities, key=levels.index),
            'cvss': cvss, 'knownExploited': exploited}


def normalize(sbom, report):
    components = {}
    for component in sbom['components']:
        purl = component['purl']
        components.setdefault(purl, []).append(component)
    observations = []
    for match in report['matches']:
        artifact, vulnerability = match['artifact'], match['vulnerability']
        purl = artifact.get('purl')
        if purl not in components:
            raise ValueError('scanner matched an identity outside the complete inventory')
        locations = sorted({p['value'] for component in components[purl]
                            for p in component['properties'] if p['name'] == 'xo-nixpkg:installedPath'})
        if not locations or any(not path.startswith('/') for path in locations):
            raise ValueError('finding has no bound shipped-file exposure')
        risk = advisory_risk(match)
        exposure_bindings = []
        for component in components[purl]:
            props = {p['name']: p['value'] for p in component['properties']
                     if p['name'] != 'xo-nixpkg:installedPath'}
            for prop in component['properties']:
                if prop['name'] == 'xo-nixpkg:installedPath':
                    location = prop['value']
                    relative = str(Path(location).relative_to(props['nix:storePath']))
                    exposure_bindings.append({'location': location,
                        'outputName': props['xo-nixpkg:outputName'], 'relativePath': relative})
        observations.append({'component': purl, 'advisory': vulnerability['id'], **risk,
                             'locations': locations, 'locationCoverage': 'complete',
                             'exposureBindings': exposure_bindings,
                             'fixVersions': vulnerability.get('fix', {}).get('versions', [])})
    return {'status': 'complete', 'scannerHealth': 'healthy', 'observations': observations,
            'scannedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def main():
    inventory, output = map(Path, sys.argv[1:])
    result = normalize(json.loads((inventory / 'runtime.cdx.json').read_text()),
                       json.loads((output / 'runtime.grype.json').read_text()))
    result['database'] = json.loads((output / 'database.json').read_text())
    if result['database'].get('valid') is not True:
        raise ValueError('scanner database did not pass native health validation')
    (output / 'scan.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    sys.path.insert(0,os.environ.get('XO_FINGERPRINTS_CORE',str(Path(__file__).with_name('decisions'))))
    import fingerprints
    keys=fingerprints.bindings({'inventory':fingerprints.file_identity(inventory/'runtime.cdx.json')},
        {'normalizer':fingerprints.file_identity(Path(__file__))},{'inventory':fingerprints.digest(json.loads((inventory/'runtime.cdx.json').read_text()).get('properties',[]))},
        {'report':fingerprints.file_identity(output/'runtime.grype.json'),'database':fingerprints.file_identity(output/'database.json')},
        {'payload':fingerprints.file_identity(output/'scan.json'),'producer':{k:os.environ.get(k) for k in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_WORKFLOW_REF')}})
    (output/'observation-fingerprints.json').write_text(json.dumps(keys,sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
