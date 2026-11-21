"""Local-only sharing policy: typed inputs; no text-derived reputation or alert counts."""
import ipaddress
import re
from datetime import datetime, timedelta, timezone


# ISO 3166-1 alpha-2. Never manufacture a code from part of a country name.
ISO2 = frozenset(('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split())


def iso_country(value):
    return value.upper() if isinstance(value,str) and value.upper() in ISO2 else None


def public_unicast(value):
    try:
        a = ipaddress.ip_address(value)
        return isinstance(value, str) and a.version == 4 and a.is_global and not a.is_multicast and str(a) == value
    except (ValueError, TypeError):
        return False


def protected_ips(inventory):
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError('protected address inventory required for sharing')
    try:
        if not all(isinstance(v, str) for v in inventory.values()):
            raise ValueError
        return frozenset(str(ipaddress.ip_address(v)) for v in inventory.values())
    except ValueError:
        raise ValueError('invalid protected address inventory') from None


def shareable(ip, excluded):
    return public_unicast(ip) and ip not in excluded


def ssh_failure_sample(rule):
    text = str(rule or '').lower()
    # Descriptions are used only for a *sample* label. Selection additionally
    # requires an independent, outcome-specific Wazuh aggregation.
    return (bool(re.search(r'\bssh(?:d)?\b', text)) and
            not re.search(r'\b(?:accepted|successful|started|closed)\b', text) and
            bool(re.search(r'\b(?:failed password|authentication fail(?:ed|ure|ures)|invalid user|failed authentication)\b', text)))


def fresh_intel(entry, now=None):
    now = now or datetime.now(timezone.utc)
    results = {}
    for name in ('gn', 'otx', 'aipdb'):
        v, h = entry.get(name), (entry.get('_lookups') or {}).get(name) or {}
        if not isinstance(v, dict) or any(v.get(k) for k in ('_error','_rate_limited','_not_found')) or h.get('status') != 'ok' or v.get('http') != 200:
            continue
        try:
            dt = datetime.fromisoformat(h['checked_at'].replace('Z','+00:00'))
            if dt.tzinfo and timedelta(0) <= now-dt <= timedelta(hours=48):
                results[name] = v
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
            pass
    return results


def authenticated_failures(cfg, ips):
    """One internal read per ≤100 shortlisted sources. No query to an intel provider.

    Count documents with BOTH sshd and a normalized auth-failure group, each
    level >=10. All source keys fit in every shard's terms aggregation.
    """
    if not ips:
        return {}
    from wazuh_indexer import WazuhIndexerClient
    from soc_contracts import complete_search
    w = cfg['wazuh']; client = WazuhIndexerClient(w['indexer_host'], w['indexer_user'], w['indexer_pass'], verify_tls=w.get('verify_tls',True))
    ips = sorted(set(ips)); excluded = protected_ips(cfg.get('sensor_public_ips'))
    if len(ips) > 10000 or not all(shareable(ip, excluded) for ip in ips):
        raise ValueError('invalid or oversized SSH evidence scope')
    now = datetime.now(timezone.utc); start = now-timedelta(hours=24); out = {}
    for offset in range(0, len(ips), 100):
        chunk = ips[offset:offset+100]
        query = {'size':0,'query':{'bool':{'filter':[
            {'range':{'timestamp':{'gte':start.isoformat(),'lte':now.isoformat()}}}, {'terms':{'data.srcip':chunk}},
            {'term':{'rule.groups':'sshd'}}, {'terms':{'rule.groups':['authentication_failed','authentication_failures']}},
            {'range':{'rule.level':{'gte':10}}}]}}, 'aggs':{'sources':{'terms':{'field':'data.srcip','include':chunk,'size':len(chunk)},
                'aggs':{'last':{'max':{'field':'timestamp'}},'level':{'max':{'field':'rule.level'}}}}}}
        reply = complete_search(client.query_alerts(query, index='wazuh-alerts-4.x-*'))
        agg = reply['aggregations']['sources']
        if type(agg.get('buckets')) is not list or agg.get('sum_other_doc_count') != 0 or agg.get('doc_count_error_upper_bound') != 0:
            raise ValueError('SSH evidence aggregation incomplete')
        for row in agg['buckets']:
            ip = row['key']; n = row['doc_count']; level = row['level']['value']; last = datetime.fromtimestamp(row['last']['value']/1000, timezone.utc)
            if (ip not in chunk or ip in out or type(n) is not int or n < 1 or type(level) not in (float,int) or
                    not 10 <= level <= 16 or level != int(level) or not start-timedelta(milliseconds=1) <= last <= now):
                raise ValueError('invalid SSH evidence bucket')
            out[ip] = {'count':n,'level':int(level),'last_seen':last.isoformat()}
    return out
