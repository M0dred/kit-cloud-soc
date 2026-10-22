#!/usr/bin/env python3
"""CLI for Clear NDR (part of soc-connector)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from ndr_client import NDRClient

DEFAULT_CONFIG = Path.home() / ".config/soc-orchestrator/config.yaml"


def load_ndr_cfg(path: Path) -> dict:
    import yaml
    cfg = yaml.safe_load(path.read_text())
    ndr = cfg.get("ndr") or {}
    if not ndr.get("url"):
        raise SystemExit("config.yaml missing ndr.url")
    return ndr


def client(cfg: dict) -> NDRClient:
    c = NDRClient(cfg["url"], cfg["username"], cfg["password"], verify_tls=cfg.get("verify_tls", False))
    login = c.login()
    if login.get("_error"):
        raise SystemExit(f"login failed: {login}")
    return c


def main() -> None:
    p = argparse.ArgumentParser(description="Clear NDR helper (SOC)")
    p.add_argument("--config", "-c", default=str(DEFAULT_CONFIG))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="User, sources, default ruleset")
    sub.add_parser("sources", help="List rule sources")
    u = sub.add_parser("update-et", help="Update ETOpen + lateral sources, then rebuild ruleset")
    u.add_argument("--et-only", action="store_true", help="Skip lateral source")
    s = sub.add_parser("sessions", help="Arkime session search")
    s.add_argument("--ip", required=True, help="IP to search (src or dst)")
    s.add_argument("--length", type=int, default=10)
    sub.add_parser("arkime-users", help="List Arkime users")
    args = p.parse_args()
    ndr = load_ndr_cfg(Path(args.config))
    c = client(ndr)

    if args.cmd == "status":
        print(json.dumps(c.status(), indent=2, default=str))
    elif args.cmd == "sources":
        print(json.dumps(c.sources(), indent=2, default=str))
    elif args.cmd == "update-et":
        print("update ETOpen (pk=1)...", flush=True)
        print(json.dumps(c.update_source(1), indent=2))
        if not args.et_only:
            print("update lateral (pk=2)...", flush=True)
            print(json.dumps(c.update_source(2), indent=2))
        print("rebuild Default ruleset (pk=1)...", flush=True)
        print(json.dumps(c.update_ruleset(1), indent=2))
        print("current:")
        print(json.dumps(c.status(), indent=2, default=str))
    elif args.cmd == "sessions":
        print(json.dumps(c.arkime_sessions(f"ip == {args.ip}", length=args.length), indent=2, default=str)[:8000])
    elif args.cmd == "arkime-users":
        print(json.dumps(c.arkime_users(), indent=2, default=str)[:4000])


if __name__ == "__main__":
    main()
