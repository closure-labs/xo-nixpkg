# SPDX-License-Identifier: Apache-2.0
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'ci'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class ScanEfficiency(unittest.TestCase):
    def test_differential_union_preserves_every_original_component_and_graph(self):
        union=load('advisory-union').union
        old={'bomFormat':'CycloneDX','components':[{'bom-ref':'a','purl':'pkg:npm/a@1','name':'a','version':'1','properties':[{'name':'path','value':'original'}]}],
             'dependencies':[{'ref':'a','dependsOn':[]}],'properties':[{'name':'coverage','value':'legacy'}]}
        extra={'components':[{'bom-ref':'a','purl':'pkg:npm/a@1','name':'a','version':'1'},
                             {'bom-ref':'b','purl':'pkg:npm/b@2','name':'b','version':'2'}]}
        prior=copy.deepcopy(old);actual=union(old,extra)
        self.assertEqual(old,prior)
        self.assertEqual(actual['components'][0],prior['components'][0])
        self.assertEqual(actual['dependencies'],prior['dependencies']);self.assertEqual(actual['properties'],prior['properties'])
        self.assertEqual(len(actual['components']),3)
        self.assertEqual({c['purl'] for c in actual['components']},{'pkg:npm/a@1','pkg:npm/b@2'})

    def test_real_normalizer_preserves_distinct_native_instances_and_all_file_exposures(self):
        fixture_spec=importlib.util.spec_from_file_location('advisory_fixture',ROOT/'tests/security-normalize.py')
        fixture=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(fixture)
        normalizer=fixture.normalizer
        with tempfile.TemporaryDirectory() as tmp:
            expected,old=fixture.supply(tmp)
            context=normalizer.verify_supply(tmp,expected);raw=fixture.report(old)
            before=normalizer.normalize(raw,old,{'version':'fixture'},context)
            additions=[]
            for index in ('c','d'):
                output='/nix/store/'+index*32+'-openssl-1.0.1'
                paths=[output+'/lib/libssl.so',output+'/lib/libcrypto.so']
                additions.append({'type':'library','bom-ref':'native-'+index,'name':'openssl','version':'1.0.1',
                    'purl':'pkg:nix/openssl@1.0.1','properties':[{'name':'nix:storePath','value':output},
                        *[{'name':'xo-nixpkg:installedPath','value':path} for path in paths],
                        *[{'name':'nix:derivation','value':'/nix/store/'+letter*32+'-openssl.drv'} for letter in ('g','h')]]})
            combined=load('advisory-union').union(old,{'components':additions})
            after=normalizer.normalize(raw,combined,{'version':'fixture'},context)
            self.assertTrue({f['identity'] for f in before}<={f['identity'] for f in after})
            shared=[f for f in after if f['binding']['normalizer']=='shared-native-v1']
            self.assertEqual(len(shared),2)
            self.assertEqual(len({path for f in shared for path in f['binding']['installed_paths']}),4)
            self.assertTrue(all(f['severity']=='critical' and len(f['binding']['native_derivations'])==2 for f in shared))
            spec=importlib.util.spec_from_file_location('shared_applicability',ROOT/'nix/security-applicability.py')
            applicability=importlib.util.module_from_spec(spec);spec.loader.exec_module(applicability)
            assessment=applicability.assess(after,combined,{'schema_version':1,'rules':[]},context)
            self.assertEqual(len(assessment['unresolved_critical']),len(after))
            self.assertEqual(assessment['dispositions'],[])
            for key in ('installed_paths','native_derivations','normalizer'):
                tampered=copy.deepcopy(after)
                finding=next(f for f in tampered if f['binding']['normalizer']=='shared-native-v1')
                finding['binding'][key]=finding['binding'][key][:-1]
                finding['identity']=applicability.digest(finding['binding'])
                with self.assertRaises(ValueError):
                    applicability.assess(tampered,combined,{'schema_version':1,'rules':[]},context)
            malformed=copy.deepcopy(combined)
            malformed['components'][-1]['properties'].append({'name':'nix:storePath','value':'conflict'})
            with self.assertRaises(ValueError):normalizer.normalize(raw,malformed,{},context)

    def test_advisory_database_is_24h_admission_remains_48h(self):
        database=load('security-database');now=dt.datetime(2026,1,2,tzinfo=dt.timezone.utc)
        with patch.object(database,'now',return_value=now):
            status={'valid':True,'schemaVersion':'v6.0.0','built':(now-dt.timedelta(hours=30)).isoformat()}
            database.validate_status(status)
            with self.assertRaises(ValueError):database.validate_status(status,24)

    def test_all_known_controllers_have_explicit_rules_and_future_paths_remain_full(self):
        cfg=json.loads((ROOT/'ci/classifier.json').read_text())
        for path in (ROOT/'ci').iterdir():
            if path.suffix not in ('.py','.sh'):continue
            relative=path.relative_to(ROOT).as_posix()
            rule=next((r for r in cfg['pathRules'] if re.search(r['pattern'],relative)),cfg['fallback'])
            self.assertNotEqual(rule,cfg['fallback'],relative)
        for relative in ('ci/future-controller.py','tests/future-test.py','unknown/new-product.nix'):
            rule=next((r for r in cfg['pathRules'] if re.search(r['pattern'],relative)),cfg['fallback'])
            self.assertEqual(rule['validation'],['*'],relative)

    def test_three_advisory_reports_share_one_snapshot_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp=Path(tmp);native=temp/'bin';native.mkdir();log=temp/'calls'
            for name in ('xo-nixpkg-security-database','xo-nixpkg-security-scan'):
                p=native/name
                p.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
assert not any(os.environ.get(k) for k in ('GH_TOKEN','REGISTRY_TOKEN','CACHIX_AUTH_TOKEN','DECIDER_KEY','ACTIONS_RUNTIME_TOKEN'))
with Path(os.environ['FIXTURE_LOG']).open('a') as stream:stream.write(json.dumps([Path(sys.argv[0]).name,*sys.argv[1:]])+'\\n')
if sys.argv[1]=='prepare':print('a'*64)
''');p.chmod(0o755)
            env=dict(os.environ,PATH=str(native)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=tmp,FIXTURE_LOG=str(log),
                     GH_TOKEN='',REGISTRY_TOKEN='',CACHIX_AUTH_TOKEN='must-strip',DECIDER_KEY='must-strip',ACTIONS_RUNTIME_TOKEN='must-strip')
            result=subprocess.run(['bash',str(ROOT/'ci/security-review-all.sh')],env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(sum(c[1]=='prepare' for c in calls),1)
            self.assertEqual([c[1] for c in calls if c[0]=='xo-nixpkg-security-scan'],['latest','stable','rolling'])
            for call in calls:
                if call[0]=='xo-nixpkg-security-database':self.assertEqual(call[-2:],['--max-age-hours','24'])

if __name__=='__main__':unittest.main()
