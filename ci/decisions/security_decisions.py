#!/usr/bin/env python3
"""Compare complete scan observations with independently authenticated human decisions.

This module does not authenticate acceptance. Callers MUST obtain accepted findings
from decision-authority.py; a JSON document or a passing scanner is not authority.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
import ipaddress
from urllib.parse import unquote

SEVERITIES = ('Negligible', 'Low', 'Medium', 'High', 'Critical')
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}', re.I)
ADVISORY = re.compile(r'(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9-]+|GO-[0-9]{4}-[0-9]+|[A-Za-z][A-Za-z0-9_.:+-]{1,199})')


class TechnicalError(ValueError):
    """Evidence is incomplete, ambiguous or invalid; human risk acceptance cannot fix it."""


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TechnicalError('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(TechnicalError('Nonfinite JSON number')))


def component_identity(value):
    if not isinstance(value, str) or not value.startswith('pkg:') or len(value) > 4096:
        raise TechnicalError('Stable package URL is required for component identity')
    # Keep namespace, qualifiers and subpath; remove only the package version.
    base, marker, tail = value.partition('?')
    if not marker:
        base, marker, tail = value.partition('#')
    if '@' not in base or not base.rsplit('@', 1)[1]:
        raise TechnicalError('Versioned package URL is required')
    identity, version = base.rsplit('@', 1)
    if not re.fullmatch(r'pkg:[a-z][a-z0-9.+-]*/[^\s?#@]+', identity):
        raise TechnicalError('Malformed package URL')
    if any(part in ('.', '..') for part in unquote(identity[4:]).split('/')):
        raise TechnicalError('Ambiguous package URL path')
    return identity + marker + tail, version


def exposure_paths(value):
    if not isinstance(value, list) or not value or len(value) > 10000:
        raise TechnicalError('Complete nonempty exposure locations are required')
    for path in value:
        if (not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or '\\' in path
                or '\x00' in path or any(p in ('.', '..') for p in path.split('/'))
                or str(PurePosixPath(path)) != path):
            raise TechnicalError('Ambiguous exposure path')
    return sorted(set(value))


def cvss_score(finding):
    value = finding.get('cvss')
    if value is None:
        return None
    if isinstance(value, list):
        scores = []
        for entry in value:
            if not isinstance(entry, dict) or not isinstance(entry.get('metrics'), dict):
                raise TechnicalError('Invalid CVSS record')
            scores.append(entry['metrics'].get('baseScore'))
        value = max((validate_score(v) for v in scores), default=None)
    return validate_score(value) if value is not None else None


def validate_score(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 10:
        raise TechnicalError('Invalid CVSS base score')
    return value


def validate_context(context):
    fields = {'schema', 'tcpPorts', 'udpPorts', 'managementCIDRs', 'ssh', 'execution',
              'capabilities', 'ambientCapabilities', 'helpers', 'sudo', 'mountsDir'}
    if isinstance(context, dict) and context.get('schema') == 2:
        fields.add('installer')
    if not isinstance(context, dict) or set(context) != fields or type(context['schema']) is not int or context['schema'] not in (1, 2):
        raise TechnicalError('Invalid native security context')
    if context['schema'] == 2:
        installer = context['installer']
        if (not isinstance(installer, dict) or set(installer) != {'ssh', 'firewall', 'sudo', 'operator', 'systemdInitrd', 'bootModes', 'bootPolicy'}
                or not isinstance(installer['ssh'], dict) or not isinstance(installer['firewall'], dict)
                or set(installer['firewall']) != {'allowedTCPPorts', 'allowedUDPPorts', 'extraCommands'}
                or not isinstance(installer['sudo'], dict) or set(installer['sudo']) != {'enable', 'wheelNeedsPassword', 'extraRules'}
                or not isinstance(installer['operator'], dict) or set(installer['operator']) != {'extraGroups', 'passwordState', 'rootPasswordState', 'mutableUsers'}
                or any(installer['operator'][field] not in ('absent', 'locked', 'empty', 'configured') for field in ('passwordState', 'rootPasswordState'))
                or not isinstance(installer['bootModes'], dict) or set(installer['bootModes']) != {'bios', 'efi', 'memtest'}
                or any(type(value) is not bool for value in installer['bootModes'].values())
                or not isinstance(installer['bootPolicy'], dict) or set(installer['bootPolicy']) != {'kernelParams', 'emergencyMode', 'initrdEmergencyAccess'}
                or not isinstance(installer['bootPolicy']['kernelParams'], list)
                or any(not isinstance(value, str) for value in installer['bootPolicy']['kernelParams'])
                or type(installer['bootPolicy']['emergencyMode']) is not bool
                or installer['bootPolicy']['initrdEmergencyAccess'] not in ('disabled', 'unauthenticated', 'locked', 'configured')
                or type(installer['systemdInitrd']) is not bool):
            raise TechnicalError('Invalid installer security policy')
        for field in ('allowedTCPPorts', 'allowedUDPPorts'):
            values = installer['firewall'][field]
            if not isinstance(values, list) or any(type(v) is not int or not 1 <= v <= 65535 for v in values):
                raise TechnicalError('Invalid installer firewall ports')
        if (not isinstance(installer['firewall']['extraCommands'], str)
                or not isinstance(installer['operator']['extraGroups'], list)
                or any(not isinstance(v, str) for v in installer['operator']['extraGroups'])
                or type(installer['operator']['mutableUsers']) is not bool
                or any(type(installer['sudo'][field]) is not bool for field in ('enable', 'wheelNeedsPassword'))
                or not isinstance(installer['sudo']['extraRules'], list)):
            raise TechnicalError('Invalid installer privilege policy')
    for field in ('tcpPorts', 'udpPorts'):
        values = context[field]
        if not isinstance(values, list) or any(type(v) is not int or not 1 <= v <= 65535 for v in values) or values != sorted(set(values)):
            raise TechnicalError('Invalid security context ports')
    for field in ('capabilities', 'ambientCapabilities'):
        values = context[field]
        if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values) or values != sorted(set(values)):
            raise TechnicalError('Invalid security context capabilities')
    ranges = context['managementCIDRs']
    if (not isinstance(ranges, list) or not ranges or any(not isinstance(v, str) for v in ranges)
            or ranges != sorted({str(ipaddress.ip_network(v, strict=True)) for v in ranges})):
        raise TechnicalError('Invalid security context management ranges')
    helpers = context['helpers']
    if (not isinstance(helpers, dict) or set(helpers) != {'enableNFS', 'enableCIFS', 'enableVHD', 'fileRestore'}
            or any(type(v) is not bool for v in helpers.values())):
        raise TechnicalError('Invalid security context helper policy')
    if (not isinstance(context['ssh'], dict) or not isinstance(context['sudo'], list)
            or not isinstance(context['execution'], dict) or set(context['execution']) != {'xoUser', 'User', 'Group'}
            or any(not isinstance(v, str) or not v for v in context['execution'].values())
            or not isinstance(context['mountsDir'], str) or not context['mountsDir'].startswith('/')):
        raise TechnicalError('Invalid security context privilege policy')
    canonical_hash(context)
    return context


def compare_context(current, previous):
    if previous is not None and current is None:
        raise TechnicalError('Previously known runtime security context disappeared')
    if current == previous:
        return False, False
    if previous is None:
        return True, False
    if 'installer' in previous and 'installer' not in current:
        raise TechnicalError('Previously known installer security context disappeared')
    expanded, reduced = False, False
    for field in ('tcpPorts', 'udpPorts', 'capabilities', 'ambientCapabilities'):
        old, new = set(previous[field]), set(current[field])
        # Complement capability syntax has different ordering semantics. Never
        # interpret a changed denylist as an ordinary reduced capability set.
        positive = field in ('tcpPorts', 'udpPorts') or all(re.fullmatch(r'CAP_[A-Z0-9_]+', value) for value in old | new)
        expanded |= not new <= old or (not positive and new != old)
        reduced |= positive and new < old
    old_ranges = [ipaddress.ip_network(value) for value in previous['managementCIDRs']]
    new_ranges = [ipaddress.ip_network(value) for value in current['managementCIDRs']]
    def covered(network, ranges):
        return any(network.version == parent.version and network.subnet_of(parent) for parent in ranges)
    expanded |= any(not covered(network, old_ranges) for network in new_ranges)
    reduced |= any(not covered(network, new_ranges) for network in old_ranges)
    for name, value in current['helpers'].items():
        expanded |= value and not previous['helpers'][name]
        reduced |= previous['helpers'][name] and not value
    # Sudo rule ordering, authentication changes and user/group privilege
    # relationships have no safe general partial order. Ask for review.
    expanded |= any(current[field] != previous[field] for field in ('ssh', 'sudo', 'execution', 'mountsDir'))
    # Installer boot/authentication/sudo policy has no safe general ordering.
    # An unchanged policy survives package/ISO rebuilds; every change is reviewed.
    expanded |= current.get('installer') != previous.get('installer')
    return bool(expanded), bool(reduced)


def normalize_findings(scan_result, profile):
    if not isinstance(profile, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', profile):
        raise TechnicalError('Invalid profile')
    if not isinstance(scan_result, dict) or scan_result.get('status') not in ('pass', 'blocked', 'review-required', 'covered', 'complete'):
        raise TechnicalError('A successfully completed native scan is required')
    if scan_result.get('status') == 'complete' and scan_result.get('scannerHealth') != 'healthy':
        raise TechnicalError('Completed scan lacks healthy scanner evidence')
    observations = scan_result.get('observations')
    if not isinstance(observations, list):
        raise TechnicalError('Complete scan observations are required')
    merged = {}
    context = validate_context(scan_result['securityContext']) if 'securityContext' in scan_result else None
    for finding in observations:
        if not isinstance(finding, dict) or finding.get('locationCoverage') != 'complete':
            raise TechnicalError('Incomplete finding location coverage')
        raw_component = finding.get('component')
        if isinstance(raw_component, str) and raw_component.startswith('pkg:'):
            component, version = component_identity(raw_component)
        else:
            image = scan_result.get('image', '')
            digest = re.search(r'@sha256:([0-9a-f]{64})$', image) if isinstance(image, str) else None
            if not isinstance(raw_component, str) or not raw_component.strip() or len(raw_component) > 4096 or not digest:
                raise TechnicalError('Opaque component requires exact immutable image identity')
            component = 'artifact:sha256:' + digest[1] + ':' + hashlib.sha256(raw_component.encode()).hexdigest()
            version = raw_component
        severity = finding.get('admissionSeverity', finding.get('severity'))
        if severity not in (*SEVERITIES, 'Unknown') or type(finding.get('knownExploited')) is not bool:
            raise TechnicalError('Invalid severity or exploitation indicator')
        aliases = finding.get('aliases', [])
        if not isinstance(aliases, list) or not isinstance(finding.get('advisory'), str):
            raise TechnicalError('Invalid advisory identities')
        aliases = sorted(set([finding['advisory'], *aliases])) if all(isinstance(v, str) for v in aliases) else []
        if not aliases or any(not ADVISORY.fullmatch(alias) for alias in aliases):
            raise TechnicalError('Invalid advisory aliases')
        aliases = sorted({a.upper() if CVE.fullmatch(a) else a for a in aliases})
        advisories = sorted({a.upper() for a in aliases if CVE.fullmatch(a)}) or [finding['advisory']]
        paths = exposure_paths(finding.get('locations'))
        # Only the authenticated native producer can establish the derivation
        # output mapping. Keep actual locations in native evidence; compare the
        # stable output name and relative shipped path across rebuilt store roots.
        if 'exposureBindings' in finding:
            bindings = finding['exposureBindings']
            if not isinstance(bindings, list) or len(bindings) != len(paths):
                raise TechnicalError('Incomplete stable exposure mapping')
            mapped, stable = set(), []
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != {'location', 'outputName', 'relativePath'}:
                    raise TechnicalError('Invalid stable exposure mapping')
                location, output, relative = binding['location'], binding['outputName'], binding['relativePath']
                if (not isinstance(location, str) or location not in paths or location in mapped
                        or not isinstance(output, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', output)
                        or not isinstance(relative, str) or not relative or relative.startswith('/')
                        or any(p in ('', '.', '..') for p in relative.split('/'))
                        or '\\' in relative or '\x00' in relative
                        or not re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/]+/' + re.escape(relative), location)):
                    raise TechnicalError('Unbound stable exposure mapping')
                mapped.add(location)
                stable.append('/nix-output/' + output + '/' + relative)
            paths = exposure_paths(stable)
        score = cvss_score(finding)
        fixes = finding.get('fixVersions', [])
        if not isinstance(fixes, list) or any(not isinstance(v, str) for v in fixes):
            raise TechnicalError('Invalid fix versions')
        for advisory in advisories:
            identity = (profile, component, advisory)
            current = {'profile': profile, 'component': component, 'advisory': advisory,
                       'exposure': paths, 'severity': severity, 'cvss': score,
                       'knownExploited': finding['knownExploited'], 'versions': [version],
                       'aliases': aliases, 'fixVersions': sorted(set(fixes))}
            if context is not None:
                current['securityContext'] = context
            if identity in merged:
                old = merged[identity]
                # Conflicting Unknown and a scored severity is ambiguous rather than a downgrade.
                if (old['severity'] == 'Unknown') != (severity == 'Unknown'):
                    raise TechnicalError('Conflicting advisory severity evidence')
                current['severity'] = max((old['severity'], severity), key=lambda s: -1 if s == 'Unknown' else SEVERITIES.index(s))
                current['cvss'] = max((v for v in (old['cvss'], score) if v is not None), default=None)
                current['knownExploited'] |= old['knownExploited']
                for field in ('exposure', 'versions', 'aliases', 'fixVersions'):
                    current[field] = sorted(set(current[field]) | set(old[field]))
            merged[identity] = current
    for finding in merged.values():
        fields = ('profile', 'component', 'advisory', 'exposure', 'securityContext') if 'securityContext' in finding else ('profile', 'component', 'advisory', 'exposure')
        finding['key'] = canonical_hash({k: finding[k] for k in fields})
    return sorted(merged.values(), key=lambda f: f['key'])


def validate_normalized(findings):
    if not isinstance(findings, list):
        raise TechnicalError('Accepted findings must be a list')
    identities = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise TechnicalError('Invalid accepted finding')
        required = {'key', 'profile', 'component', 'advisory', 'exposure', 'severity', 'cvss',
                    'knownExploited', 'versions', 'aliases', 'fixVersions'}
        if 'securityContext' in finding:
            required.add('securityContext')
        if set(finding) != required:
            raise TechnicalError('Unsupported normalized finding fields')
        # Round-trip through native normalization to validate the complete contract.
        if not isinstance(finding['versions'], list) or not finding['versions'] or any(not isinstance(v, str) or not v for v in finding['versions']):
            raise TechnicalError('Missing accepted package versions')
        component = finding['component']
        if not isinstance(component, str):
            raise TechnicalError('Invalid accepted component')
        base, separator, tail = component.partition('?')
        if not separator:
            base, separator, tail = component.partition('#')
        opaque = re.fullmatch(r'artifact:sha256:([0-9a-f]{64}):[0-9a-f]{64}', component)
        source = {'component': finding['versions'][0] if opaque else base + '@' + finding['versions'][0] + separator + tail,
                  'advisory': finding['advisory'], 'aliases': finding['aliases'],
                  'locations': finding['exposure'], 'locationCoverage': 'complete',
                  'severity': finding['severity'], 'cvss': finding['cvss'],
                  'knownExploited': finding['knownExploited'], 'fixVersions': finding['fixVersions']}
        native = {'status': 'pass', 'observations': [source]}
        if 'securityContext' in finding:
            native['securityContext'] = validate_context(finding['securityContext'])
        if opaque:
            native['image'] = 'image@sha256:' + opaque[1]
        normalized = normalize_findings(native, finding['profile'])
        normalized = [item for item in normalized if item['advisory'] == finding['advisory']]
        if len(normalized) != 1 or any(normalized[0][k] != finding[k] for k in required - {'versions'}):
            raise TechnicalError('Noncanonical accepted finding')
        identity = tuple(finding[k] for k in ('profile', 'component', 'advisory'))
        if identity in identities:
            raise TechnicalError('Ambiguous duplicate accepted finding')
        identities.add(identity)
    return findings


def compare_findings(current, accepted):
    validate_normalized(current)
    validate_normalized(accepted)
    identity = lambda f: tuple(f[k] for k in ('profile', 'component', 'advisory'))
    old = {identity(f): f for f in accepted}
    new, worsened, unchanged, improved = [], [], [], []
    for finding in current:
        previous = old.get(identity(finding))
        if previous is None:
            new.append(finding)
            continue
        reasons = []
        severity, prior_severity = finding['severity'], previous['severity']
        if (severity == 'Unknown') != (prior_severity == 'Unknown'):
            reasons.append('severity-evidence-changed')
        elif severity != 'Unknown' and SEVERITIES.index(severity) > SEVERITIES.index(prior_severity):
            reasons.append('severity-increased')
        if previous['cvss'] is not None and finding['cvss'] is None:
            raise TechnicalError('Previously known CVSS evidence disappeared')
        if finding['cvss'] is not None and (previous['cvss'] is None or finding['cvss'] > previous['cvss']):
            reasons.append('cvss-increased-or-new')
        if finding['knownExploited'] and not previous['knownExploited']:
            reasons.append('known-exploitation-added')
        if not set(finding['exposure']).issubset(previous['exposure']):
            reasons.append('exposure-expanded')
        runtime_expanded, runtime_reduced = compare_context(finding.get('securityContext'), previous.get('securityContext'))
        if runtime_expanded:
            reasons.append('runtime-security-policy-expanded-or-changed')
        if reasons:
            worsened.append({'finding': finding, 'reasons': reasons})
        elif runtime_reduced or any(finding[k] != previous[k] for k in ('severity', 'cvss', 'knownExploited', 'exposure')):
            improved.append(finding)
        else:
            unchanged.append(finding)
    present = {identity(f) for f in current}
    return {'new': new, 'worsened': worsened, 'unchanged': unchanged, 'improved': improved,
            'resolved': [f for f in accepted if identity(f) not in present]}


def evaluate(scan_result, profile, accepted=None, revoked=False):
    findings = normalize_findings(scan_result, profile)
    # None is deliberately different from an authenticated empty baseline.
    comparison = compare_findings(findings, accepted if accepted is not None else [])
    status = 'revoked' if revoked else ('review-required' if accepted is None or comparison['new'] or comparison['worsened'] else 'covered')
    return {'schema': 1, 'status': status, 'profile': profile, 'findings': findings,
            'proposalHash': canonical_hash(findings), **comparison}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--accepted', type=Path, help='Authenticated normalized finding list; never untrusted PR JSON')
    parser.add_argument('--revoked', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(load_json(args.scan), args.profile,
                          load_json(args.accepted) if args.accepted else None, args.revoked)
        code = 0 if result['status'] == 'covered' else 3
    except (ValueError, TypeError, KeyError, OSError) as error:
        result, code = {'schema': 1, 'status': 'scanner-error', 'error': str(error)}, 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps(result, allow_nan=False))
    return code


if __name__ == '__main__':
    sys.exit(main())
