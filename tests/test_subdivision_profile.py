"""Offline tests of aggregate-only subdivision publication."""
import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from subdivision_profile import local_profile, private_output, profile, verify

IPS = ['8.8.8.8','8.8.4.4','9.9.9.9','1.1.1.1','4.2.2.1']  # Local fixtures; never queried.
STAMP = '2026-11-26 12:01 UTC'
BUILD = '2026-11-01 02:52 UTC'


def fixture():
    return json.dumps({'generated':STAMP, 'wazuh':{'top_src':[[ip,i+1] for i,ip in enumerate(IPS)]},
                       'enrich_meta':{ip:{'country':'US'} for ip in IPS}}).encode()


def records():
    results={}
    for ip, cc, name in zip(IPS,['US','US','US','US','CA'],['First State','First State','First State','Withheld State','Wrong Country State']):
        results[ip]={'country':{'iso_code':cc},'subdivisions':[{'names':{'en':name}}, {'names':{'en':'not first level'}}],
                     'city':{'names':{'en':'Private test city'}},'location':{'latitude':43.0123}}
    return results


class SubdivisionTests(unittest.TestCase):
    def test_minimum_threshold_and_country_agreement(self):
        raw=fixture()
        x=profile(raw, records().get, BUILD)
        self.assertEqual(x['countries']['US'],{'subdivisions':[{'name':'First State','rows':3,'alerts':6}],
                                              'withheld_rows':2,'withheld_alerts':9})
        verify(raw,x)
        output=json.dumps(x)
        for secret in [*IPS,'Withheld State','Wrong Country State','Private test city','not first level','43.0123']:
            self.assertNotIn(secret,output)

    def test_exact_bytes_and_contract(self):
        raw=fixture();x=profile(raw,records().get,BUILD)
        with self.assertRaisesRegex(ValueError,'does not match batch'):
            verify(raw+b'\n',x)
        y=copy.deepcopy(x);y['countries']['US']['subdivisions'][0]['rows']=2
        with self.assertRaisesRegex(ValueError,'invalid subdivision cell'):
            verify(raw,y)
        y=copy.deepcopy(x);y['countries']['US']['withheld_alerts']=1
        with self.assertRaisesRegex(ValueError,'do not reconcile'):
            verify(raw,y)
        y=copy.deepcopy(x);y['countries']['US']['subdivisions'][0]['name']='8.8.8.8'
        with self.assertRaisesRegex(ValueError,'invalid subdivision cell'):
            verify(raw,y)

    def test_exact_profile_output_stays_outside_public_repo(self):
        with TemporaryDirectory() as folder, patch.object(Path,'home',return_value=Path(folder)):
            restricted=Path(folder)/'.local/state/soc-audits';restricted.mkdir(mode=0o700,parents=True)
            self.assertEqual(private_output(restricted/'geo.json'), restricted/'geo.json')
            with self.assertRaisesRegex(ValueError,'private audit directory'):
                private_output(Path(folder)/'docs/subdivisions.json')
            restricted.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'unavailable'):
                private_output(restricted/'geo.json')

    def test_optional_database_unavailable_without_mutation(self):
        raw=fixture()
        with TemporaryDirectory() as folder:
            before=local_profile(raw,Path(folder)/'missing')
            verify(raw,before)
            self.assertIsNone(before['countries']);self.assertIsNone(before['database_build_utc'])
