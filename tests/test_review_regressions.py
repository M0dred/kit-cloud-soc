"""Evidence, coverage and recovery regressions. Mocks and temporary files only."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE), str(BASE/'src/soc-connector')]
import source_policy as policy
import intel_enrich
from enrich_budget import bounded
from ioc_comment import render_comment
from misp_fixture import event, wire
from misp_sync import update_existing
from ndr_client import NDRClient
from soc_contracts import complete_search, published_event
import vt_comment_new as vt
from wazuh_indexer import WazuhIndexerClient

NOW = datetime.now(timezone.utc)
IP = '8.8.8.8'  # fixture identifiers only
EXCLUDED = policy.protected_ips({'fixture':'1.1.1.1'})
META = {'count':200, 'level':12,'rule':'sshd authentication failures','isp':'','aip':95,'gn':'malicious','otx':22}
PROOF = {'count':20,'level':10,'last_seen':(NOW-timedelta(minutes=2)).isoformat()}
GOOD = {'aipdb':{'score':80,'http':200},'_lookups':{'aipdb':{'status':'ok','checked_at':NOW.isoformat()}}}
SHARDS = {'timed_out':False,'_shards':{'total':2,'successful':2,'failed':0}}
IOC = {'value': IP,'type':'ip-src','to_ids':False,'category':'Network activity','comment':'fixture only'}


def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


class SharingTests(unittest.TestCase):
    def test_asset_exclusion_required_for_sharing_and_at_final_renderer(self):
        for bad in (None, {}, {'a':None}, {'a':'invalid'}, {'a':['8.8.8.8']}):
            with self.subTest(bad=bad), self.assertRaises(ValueError): policy.protected_ips(bad)
        with self.assertRaises(ValueError):
            render_comment('1.1.1.1',100,None,'failed authentication',sensor_public_ips={'fixture':'1.1.1.1'})
        for ip in ('1.1.1.1','224.0.0.1','192.0.2.1'):
            self.assertFalse(policy.shareable(ip, EXCLUDED))
            self.assertFalse(vt.eligible(ip,META,GOOD,PROOF,excluded=EXCLUDED,now=NOW))

    def test_protected_source_never_reaches_lookup_or_misp_write_batch(self):
        mod=load('excluded_orch',BASE/'src/soc-connector/soc-orchestrator.py')
        job=mod.Orchestrator.__new__(mod.Orchestrator);job.cfg={'sensor_public_ips':{'fixture':IP},'misp':{'event_id':1932},'pipeline':{'vt_push_threshold':2,'wazuh_count_threshold':50}}
        job.cfg['misp']['url']='https://example.invalid';job.summary={'stage_results':{}};job.log=lambda *_:None;job.dry_run=False;job.misp=Mock();job.pending_path=Path('not-used')
        row={'ip':IP,'count':100,'rule_level':12}
        with patch.object(mod,'bounded',return_value=({},{})) as budget,patch.object(mod,'update_existing',return_value=0) as update:
            job.stage_enrich_intel([row]);job.stage_update_misp([row],{})
            self.assertEqual(budget.call_args.args[0],[]);self.assertEqual(update.call_args.args[2],[])

    def test_neutral_ssh_samples_are_not_ssh_failures(self):
        for rule in ('sshd: service started','sshd: accepted publickey','ssh session closed'):
            s = render_comment(IP,100,None,rule,level=12,sensor_public_ips={'fixture':'1.1.1.1'})
            self.assertNotIn('Category: SSH authentication failures',s)
            self.assertFalse(vt.shortlisted(IP,vt.parse_comment(s),GOOD,EXCLUDED,NOW))

    def test_only_current_proof_and_fresh_success_qualify(self):
        self.assertTrue(vt.eligible(IP,META,GOOD,PROOF,excluded=EXCLUDED,now=NOW))
        for proof in (None, dict(PROOF,count=19), dict(PROOF,level=9),dict(PROOF,last_seen=(NOW-timedelta(days=2)).isoformat())):
            self.assertFalse(vt.eligible(IP,META,GOOD,proof,excluded=EXCLUDED,now=NOW))
        for entry in ({},dict(GOOD,aipdb={'http':200,'score':0}),dict(GOOD,aipdb={'http':200,'score':False}),
                      {'gn':{'http':200,'classification':'suspicious'},'_lookups':{'gn':{'status':'ok','checked_at':NOW.isoformat()}}},
                      dict(GOOD,_lookups={'aipdb':{'status':'error','checked_at':NOW.isoformat()}}),
                      dict(GOOD,_lookups={'aipdb':{'status':'ok','checked_at':(NOW-timedelta(hours=49)).isoformat()}})):
            self.assertFalse(vt.eligible(IP,META,entry,PROOF,excluded=EXCLUDED,now=NOW))

    def test_internal_evidence_query_filters_both_groups_level_and_window(self):
        cfg={'wazuh':dict(indexer_host='example.invalid', indexer_user='f',indexer_pass='f'), 'sensor_public_ips':{'fixture':'1.1.1.1'}}
        agg={'buckets':[{'key':IP,'doc_count':20,'level':{'value':12},'last':{'value':(NOW-timedelta(minutes=1)).timestamp()*1000}}],
             'sum_other_doc_count':0,'doc_count_error_upper_bound':0}
        with patch.object(WazuhIndexerClient,'query_alerts',return_value=dict(SHARDS,aggregations={'sources':agg})) as query:
            rows=policy.authenticated_failures(cfg,[IP]); self.assertEqual(rows[IP]['count'],20)
            filters=query.call_args.args[0]['query']['bool']['filter']
            self.assertIn({'term':{'rule.groups':'sshd'}},filters)
            self.assertIn({'terms':{'rule.groups':['authentication_failed','authentication_failures']}},filters)
            self.assertIn({'range':{'rule.level':{'gte':10}}},filters)
            win=filters[0]['range']['timestamp']; self.assertEqual(datetime.fromisoformat(win['lte'])-datetime.fromisoformat(win['gte']),timedelta(hours=24))
            with self.assertRaises(ValueError):policy.authenticated_failures(cfg,['1.1.1.1'])
            self.assertEqual(query.call_count,1)
        with patch.object(WazuhIndexerClient,'query_alerts',return_value=dict(SHARDS,aggregations={'sources':dict(agg,sum_other_doc_count=1)})),self.assertRaises(ValueError):
            policy.authenticated_failures(cfg,[IP])


class CoverageTests(unittest.TestCase):
    def test_missing_wazuh_aggregation_is_not_an_empty_window(self):
        c=WazuhIndexerClient('example.invalid','fixture','fixture')
        empty={'aggregations':{'ips':{'buckets':[],'sum_other_doc_count':0},'approx_unique_sources':{'value':0}}}
        for reply in (SHARDS, dict(empty,timed_out=True),dict(empty, _shards={'total':2,'successful':1,'failed':1},timed_out=False)):
            with patch.object(c,'query_alerts',return_value=reply):self.assertTrue(c.fetch_suspicious_ips()['_error']); self.assertIsNone(c.last_coverage)
        with patch.object(c,'query_alerts',return_value=dict(SHARDS,**empty)):self.assertEqual(c.fetch_suspicious_ips(),[])

    def test_ndr_incomplete_and_api_errors_do_not_report_healthy(self):
        for reply in (dict(SHARDS,timed_out=True),dict(SHARDS,_shards={'total':2,'failed':1,'successful':1}),{}):
            with self.assertRaises(ValueError):complete_search(reply)
        c=NDRClient.__new__(NDRClient); c._csrf='fixture'; c.current_user=lambda:{'username':'fixture'}
        c.ruleset=lambda i:{'name':'fixture','rules_count':5}; c.sources=lambda:{'_error':True}
        with self.assertRaises(RuntimeError):c.status()

    def test_ndr_query_distinguishes_verified_empty_from_missing_or_partial_buckets(self):
        n=load('ndr_review',BASE/'ndr-cross.py');empty={'buckets':[],'sum_other_doc_count':0,'doc_count_error_upper_bound':0}
        ok=dict(SHARDS,aggregations={'src':empty,'dst':empty})
        self.assertEqual(n.verified_chunk(ok,[IP]),[])
        for bad in (dict(ok,timed_out=True),dict(ok,aggregations={'src':empty,'dst':{}}),dict(ok,aggregations={'src':dict(empty,sum_other_doc_count=1),'dst':empty})):
            with self.assertRaises((RuntimeError,ValueError)):n.verified_chunk(bad,[IP])

    def test_missing_or_invalid_vt_quota_ledger_is_not_unused_allowance(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(vt,'DAILY',Path(tmp)/'daily.json'):
            with self.assertRaises(FileNotFoundError):vt.daily_used()
            vt.DAILY.write_text(json.dumps({'date':datetime.now(timezone.utc).date().isoformat(),'used':-1}))
            with self.assertRaises(ValueError):vt.daily_used()

    def test_incomplete_misp_list_and_draft_are_not_empty_success(self):
        e=event(); self.assertEqual(published_event(e,1932)['Attribute'],[])
        for k,v in [('id','other'),('published',False),('attribute_count','2'),('Attribute',None)]:
            with self.assertRaises(RuntimeError):published_event({'Event':dict(e['Event'],**{k:v})},1932)
        del e['Event']['Attribute']
        with self.assertRaises(RuntimeError):published_event(e,1932)

    def test_country_and_gn_class_are_not_silently_misrepresented(self):
        d=load('dash_review',BASE/'dashboard-gen.py')
        with patch.object(intel_enrich,'_get',return_value=({'country_name':'China','country_iso_code':'CN','pulse_info':{'count':0}},200)):
            self.assertEqual(intel_enrich.otx(IP,'fixture')['cc'],'CN')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); raw={IP:{'otx':{'cc':'China','pulses':0},'aipdb':{'cc':'CN','score':0},'gn':{'classification':'suspicious'}}}
            (root/'enrich-cache.json').write_text(json.dumps(raw))
            with patch.object(d,'BASE',root),patch.object(d,'THREAT_DB',root/'absent'):
                m=d.public_enrichment(d.enrich_meta_for([IP])[IP]);self.assertEqual(m['country'],'CN');self.assertEqual(m['gn'],'suspicious');self.assertIsNone(d.vt_ledger()['posted_total'])
            self.assertIsNone(policy.iso_country('China')); self.assertIsNone(policy.iso_country('XX'))

    def test_budgets_survive_restarts_and_503_not_counted_as_success(self):
        orch=load('budget_orch', BASE/'src/soc-connector/soc-orchestrator.py')
        gn=Mock(side_effect=[{'http':429},{'_not_found':True,'http':404}]);otx=Mock(side_effect=[{'http':503,'_error':True},{'http':200,'pulses':0}]);cfg={'enabled':True,'api_key':'fixture'}
        sources={'gn':(gn,cfg,2,24,0,'GN'),'otx':(otx,cfg,2,6,0,'OTX')}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def run(h):return bounded([IP],sources,root,orch.Orchestrator._merge_enrichment_cache,lambda *_:None,lambda *_:None,clock=lambda:NOW+timedelta(hours=h))
            _,s=run(0);self.assertEqual(s['otx']['error'],1);self.assertEqual(s['otx']['success'],0)
            _,s=run(1);self.assertEqual(s['gn']['backoff'],1);self.assertEqual(s['otx']['success'],1)
            t=json.loads((root/'enrich-cache.json').read_text())[IP]['_lookups']['otx']['checked_at']
            _,s=run(23);self.assertEqual(s['otx']['cached'],1);self.assertEqual(gn.call_count,1);self.assertEqual(otx.call_count,2)
            self.assertEqual(json.loads((root/'enrich-cache.json').read_text())[IP]['_lookups']['otx']['checked_at'],t)
            _,s=run(24);self.assertEqual(s['gn']['not_found'],1);self.assertEqual(s['otx']['cached'],1)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup); self.path=Path(temp.name)/'pending.json'
        self.client=Mock();self.server=wire(self.client,[])
    def test_draft_after_failed_publish_never_false_green_or_blindly_republishes(self):
        self.client.publish_event.side_effect=lambda _:{'_error':True}
        with self.assertRaises(RuntimeError):update_existing(self.client,1932,[IOC],self.path)
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        for batch in ([IOC],[]):
            with self.assertRaises(RuntimeError):update_existing(self.client,1932,batch,self.path)
        self.assertEqual(self.client.publish_event.call_count,1);self.assertEqual(self.client.add_attribute.call_count,1)
        self.server['published']=True  # simulates separate authenticated reconciliation
        self.assertEqual(update_existing(self.client,1932,[],self.path),0);self.assertFalse(self.path.exists())
    def test_concurrent_prepublication_edit_is_held_for_review(self):
        orig=self.client.add_attribute.side_effect
        def change(**kw):
            result=orig(**kw);self.server['info']='independent editor change';return result
        self.client.add_attribute.side_effect=change
        with self.assertRaises(RuntimeError):update_existing(self.client,1932,[IOC],self.path)
        self.client.publish_event.assert_not_called();self.assertTrue(self.path.exists())
    def test_unrelated_published_event_does_not_clear_intent(self):
        self.path.write_text(json.dumps({'event_id':'1932','expected':{IP:'unconfirmed'}}))
        with self.assertRaises(RuntimeError):update_existing(self.client,1932,[],self.path)
        self.client.publish_event.assert_not_called();self.assertTrue(self.path.exists())
