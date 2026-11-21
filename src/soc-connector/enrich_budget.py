"""Independent bounded lookup budgets. A cache hit is not a new observation."""
import json
import os
from datetime import datetime, timedelta, timezone


def utc(stamp):
    when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    if not when.tzinfo:
        raise ValueError('timezone required')
    return when


def _write(path, data):
    tmp = path.with_suffix('.tmp')
    with tmp.open('w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(data, f, indent=1); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)


def bounded(ips, sources, directory, merge, log, sleep, *, clock=lambda: datetime.now(timezone.utc)):
    cache_file = directory / 'enrich-cache.json'
    pause_file = directory / 'enrich-backoff.json'
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    pauses = json.loads(pause_file.read_text()) if pause_file.exists() else {}
    if not isinstance(cache,dict) or not isinstance(pauses,dict):
        raise ValueError('invalid enrichment state')
    stats = {k:dict.fromkeys(('attempted','success','not_found','error','limited','cached','backoff','cap','disabled'),0) for k in sources}
    out = {}; updates = {}
    for ip in dict.fromkeys(ips):
        entry = cache.get(ip,{})
        result = out.setdefault(ip,{})
        for k,(lookup,cfg,default_cap,pause_hours,delay,label) in sources.items():
            s = stats[k]; now = clock()
            if not cfg.get('enabled') or not cfg.get('api_key'):
                s['disabled'] += 1; continue
            history = entry.get('_lookups',{}).get(k,{})
            if k in entry and history.get('status') in ('ok','not_found') and history.get('checked_at'):
                if timedelta(0) <= now-utc(history['checked_at']) <= timedelta(hours=24):
                    result[k] = entry[k]; s['cached'] += 1; continue
            if k in pauses and utc(pauses[k]) > now:
                s['backoff'] += 1; continue
            if s['attempted'] >= int(cfg.get('max_per_run', default_cap)):
                s['cap'] += 1; continue
            s['attempted'] += 1
            value = lookup(ip, cfg['api_key']); when = clock()
            if value.get('_rate_limited') or value.get('http') == 429:
                value.update({'_rate_limited': True, '_error':True}); s['limited'] += 1
                # A local minimum pause, not a claim about account quota reset.
                pauses[k] = (when+timedelta(hours=pause_hours)).isoformat()
                _write(pause_file, pauses); log(f'    {label} rate-limited, skipping rest')
            elif value.get('_error'):
                s['error'] += 1
            elif value.get('_not_found'):
                s['not_found'] += 1
            else:
                s['success'] += 1
            result[k] = value
            updates.setdefault(ip,{}).update({k:value, k+'_checked_at':when.isoformat()})
            if not value.get('_rate_limited'):
                sleep(delay)
    if updates:
        _write(cache_file, merge(cache, updates))
    return out, stats
