#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normalize raw scanner evidence without reducing severity or hiding observations."""
import datetime
import json
from pathlib import Path
import sys


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
        aliases = sorted({v['id'] for v in [vulnerability, *match.get('relatedVulnerabilities', [])]})
        severity = vulnerability.get('severity', 'Unknown')
        if severity not in {'Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical'}:
            raise ValueError('unsupported scanner severity')
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
        cvss = vulnerability.get('cvss', [])
        observations.append({'component': purl, 'advisory': vulnerability['id'], 'aliases': aliases,
                             'severity': severity,
                             'knownExploited': bool(vulnerability.get('knownExploited', [])),
                             'locations': locations, 'locationCoverage': 'complete',
                             'exposureBindings': exposure_bindings, 'cvss': cvss, 'fixVersions': vulnerability.get('fix', {}).get('versions', [])})
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


if __name__ == '__main__':
    main()
