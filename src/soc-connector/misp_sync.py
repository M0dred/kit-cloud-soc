"""Reconcile writes to the existing managed event. Never auto-republish a draft."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
from soc_contracts import managed_event, published_event, revision_digest


def _signature(comment):
    return hashlib.sha256(comment.encode()).hexdigest()


def _confirmed(a, value, digest):
    return (a.get('value') == value and a.get('type') == 'ip-src' and
            a.get('to_ids') in (False, 0, '0') and isinstance(a.get('comment'), str) and
            _signature(a['comment']) == digest)


def _record(path, data):
    tmp = path.with_suffix('.tmp')
    try:
        with tmp.open('x') as f:
            os.fchmod(f.fileno(), 0o600); json.dump(data, f); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def update_existing(client, event_id, iocs, journal):
    """The cron lock serializes local jobs, not MISP editors. Compare the revision
    immediately before publish. MISP has no conditional publish transaction.
    Any ambiguity leaves a root-only intent record for manual investigation.
    """
    path = Path(journal)
    with path.with_suffix('.lock').open('a') as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _update(client, event_id, iocs, path)


def _update(client, event_id, iocs, path):
    before = published_event(client.get_event(event_id), event_id)
    if path.exists():
        pending = json.loads(path.read_text())
        wanted = pending['expected']
        if (str(pending['event_id']) != str(event_id) or not isinstance(wanted,dict) or not wanted or
                not all(any(_confirmed(a, ip, sig) for a in before['Attribute']) for ip, sig in wanted.items())):
            raise RuntimeError('MISP pending writes not confirmed; manual reconciliation required')
        path.unlink()  # service already confirms all intended observations published
    existing = {a['value'] for a in before['Attribute'] if a['type'] in ('ip-src','ip-dst')}
    todo = {r['value']:r for r in iocs if r['value'] not in existing}
    if not todo:
        return 0
    if any(r['type'] != 'ip-src' or r['to_ids'] is not False for r in todo.values()):
        raise ValueError('managed observations must be IDS-disabled sources')
    expected = {ip:_signature(r['comment']) for ip,r in todo.items()}
    _record(path, {'event_id':str(event_id), 'expected':expected})
    ids = {}
    for ip, r in todo.items():
        result = client.add_attribute(event_id=event_id, type_='ip-src', value=ip,
                                      category=r['category'], comment=r['comment'], to_ids=False)
        a = (result.get('Attribute') or result) if isinstance(result,dict) else {}
        if not isinstance(a,dict) or not str(a.get('id')).isdecimal() or result.get('_error') or str(a['id']) in ids:
            raise RuntimeError('MISP add not confirmed; manual reconciliation required')
        ids[str(a['id'])] = ip
    after = managed_event(client.get_event(event_id), event_id)
    def matches(event, *, published=False):
        new = {str(a['id']):a for a in event['Attribute'] if str(a['id']) in ids}
        return (new.keys() == ids.keys() and all(_confirmed(new[i],ip,expected[ip]) for i,ip in ids.items()) and
                revision_digest(before, after_publish=published) == revision_digest(event, ids, after_publish=published))
    if not matches(after):
        raise RuntimeError('MISP revision changed unexpectedly; refusing to publish')
    if after.get('published') not in (True,1,'1'):
        res = client.publish_event(event_id)
        if not isinstance(res,dict) or res.get('_error') or res.get('errors'):
            raise RuntimeError('MISP publish unconfirmed; manual reconciliation required')
    confirmed = published_event(client.get_event(event_id), event_id)
    if not matches(confirmed, published=True):
        raise RuntimeError('MISP published revision differs; manual reconciliation required')
    path.unlink()
    return len(todo)
