"""Fail-closed contracts for complete search responses and the flat managed event."""
import hashlib
import json


def complete_search(reply):
    if not isinstance(reply, dict) or reply.get('_error') or reply.get('error') or reply.get('timed_out') is not False:
        raise ValueError('search failed, incomplete or timed out')
    s = reply.get('_shards')
    if not isinstance(s, dict) or any(type(s.get(k)) is not int for k in ('total', 'successful', 'failed')) or not (s['total'] > 0 and s['successful'] == s['total'] and s['failed'] == 0):
        raise ValueError('search shard coverage incomplete')
    return reply


def managed_event(reply, event_id):
    ev = reply.get('Event') if isinstance(reply, dict) and not reply.get('_error') else None
    if not isinstance(ev, dict) or str(ev.get('id')) != str(event_id) or not isinstance(ev.get('Attribute'), list):
        raise RuntimeError('MISP event lookup failed or attribute inventory incomplete')
    attrs = ev['Attribute']
    n = ev.get('attribute_count')
    if not str(n).isdecimal() or int(n) != len(attrs) or ev.get('Object'):
        raise RuntimeError('MISP flat event attribute coverage unverified')
    ids = set()
    for a in attrs:
        if (not isinstance(a, dict) or not str(a.get('id')).isdecimal() or str(a['id']) in ids or
                str(a.get('event_id')) != str(event_id) or not isinstance(a.get('value'), str) or not a['value'] or
                not isinstance(a.get('type'), str) or not a['type'] or a.get('deleted', False) not in (False, 0, '0')):
            raise RuntimeError('MISP attribute invalid or duplicated')
        ids.add(str(a['id']))
    return ev


def published_event(reply, event_id):
    ev = managed_event(reply, event_id)
    if ev.get('published') not in (True, 1, '1'):
        raise RuntimeError('MISP event has unconfirmed or unpublished changes; manual reconciliation required')
    return ev


def revision_digest(event, omit_ids=(), *, after_publish=False):
    """Conservative pre-publication comparison, not a server-side transaction."""
    metadata = {k:v for k,v in event.items() if k not in ('Attribute','attribute_count','published','timestamp','RelatedEvent')}
    if after_publish:
        metadata.pop('publish_timestamp', None)  # MISP advances this on normal publish
        metadata.pop('first_publication', None)
    metadata['Attribute'] = sorted((a for a in event['Attribute'] if str(a['id']) not in omit_ids), key=lambda a:str(a['id']))
    return hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
