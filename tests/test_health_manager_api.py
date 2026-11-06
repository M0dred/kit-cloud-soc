"""Fixture-only Wazuh Manager inventory coverage checks; no credentials or network."""
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('soc_health_inventory', ROOT / 'health-check.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


def response(data):
    return io.BytesIO(json.dumps(data).encode())


def listing(items, total, **overrides):
    data = {'affected_items': items, 'total_affected_items': total,
            'failed_items': [], 'total_failed_items': 0}
    data.update(overrides)
    return {'error': 0, 'data': data}


class ManagerInventoryTests(unittest.TestCase):
    def test_fetches_all_pages_and_does_not_treat_cap_as_complete(self):
        records = [{'name': f'fixture-agent-{n}', 'status': 'active'} for n in range(205)]
        offsets = []
        def open_(req, **_):
            parts = urlsplit(req.full_url)
            if parts.path.endswith('/authenticate'):
                return response({'error': 0, 'data': {'token': 'fixture'}})
            qs = parse_qs(parts.query)
            self.assertEqual(qs.get('limit'), ['100'])
            offset = int(qs['offset'][0]); offsets.append(offset)
            return response(listing(records[offset:offset + 100], len(records)))
        with patch.object(health.urllib.request, 'urlopen', side_effect=open_):
            agents = health.agent_states('fixture', 'fixture')
        self.assertEqual(len(agents), 205)
        self.assertEqual(offsets, [0, 100, 200])

    def test_incomplete_ambiguous_or_failed_inventory_raises(self):
        cases = [
            {'error': 1, 'data': {}},
            listing([], 0),  # empty inventory cannot establish coverage
            listing([], 2),  # count says more but server returned no progress
            listing([{'name': 'same', 'status': 'active'}, {'name': 'same', 'status': 'active'}], 2),
            listing([{'name': 'bad'}], 1),
            listing([{'name': 'fixture', 'status': 'active'}], 1, total_failed_items=1),
            listing([{'name': 'fixture', 'status': 'active'}], 1, total_failed_items=False),
            {'error': False, 'data': listing([{'name': 'fixture', 'status': 'active'}], 1)['data']},
            {'error': 0, 'data': {'affected_items': [], 'failed_items': [], 'total_failed_items': 0}},
        ]
        for fixture in cases:
            with self.subTest(fixture=fixture):
                def open_(req, **_):
                    if urlsplit(req.full_url).path.endswith('/authenticate'):
                        return response({'error': 0, 'data': {'token': 'fixture'}})
                    return response(fixture)
                with patch.object(health.urllib.request, 'urlopen', side_effect=open_):
                    with self.assertRaises((RuntimeError, ValueError)):
                        health.agent_states('fixture', 'fixture')

    def test_truncated_nonempty_page_fails_without_unbounded_followup_requests(self):
        replies = [response({'error': 0, 'data': {'token': 'fixture'}}),
                   response(listing([{'name': 'fixture', 'status': 'active'}], 2))]
        with patch.object(health.urllib.request, 'urlopen', side_effect=replies) as req:
            with self.assertRaises((RuntimeError, ValueError)):
                health.agent_states('fixture', 'fixture')
            self.assertEqual(req.call_count, 2)

    def test_total_changing_during_pagination_fails_closed(self):
        page = [{'name': f'fixture-{n}', 'status': 'active'} for n in range(100)]
        replies = [response({'error': 0, 'data': {'token': 'fixture'}}),
                   response(listing(page, 150)),
                   response(listing([{'name': 'last', 'status': 'active'}], 101))]
        with patch.object(health.urllib.request, 'urlopen', side_effect=replies):
            with self.assertRaises((RuntimeError, ValueError)):
                health.agent_states('fixture', 'fixture')


if __name__ == '__main__':
    unittest.main()
