#!/usr/bin/env python3
"""Clear NDR (Scirius / SELKS) REST client. Stdlib only.

Auth is Django session + CSRF (same as the Hunt UI).
Verified against Clear NDR CE at https://10.0.1.50:8443
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar


class NDRClient:
    def __init__(self, url: str, username: str, password: str, verify_tls: bool = False):
        self.base = url.rstrip("/")
        self.username = username
        self.password = password
        self._csrf = None
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self._cj),
        )
        self._opener.addheaders = [("User-Agent", "soc-connector-ndr/1.0")]

    def login(self) -> dict:
        html = self._opener.open(self.base + "/accounts/login/", timeout=20).read().decode("utf-8", "replace")
        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        if not m:
            return {"_error": True, "_message": "no csrf token on login page"}
        data = urllib.parse.urlencode({
            "csrfmiddlewaretoken": m.group(1),
            "username": self.username,
            "password": self.password,
            "next": "/",
        }).encode()
        req = urllib.request.Request(self.base + "/accounts/login/", data=data, method="POST")
        req.add_header("Referer", self.base + "/accounts/login/")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        resp = self._opener.open(req, timeout=20)
        for c in self._cj:
            if c.name == "csrftoken":
                self._csrf = c.value
        if "login" in resp.geturl().lower():
            return {"_error": True, "_message": "login failed"}
        return {"ok": True, "url": resp.geturl()}

    def _req(self, method: str, path: str, data=None, timeout: int = 60):
        body = None
        headers = {"Referer": self.base + "/rules/"}
        if self._csrf:
            headers["X-CSRFToken"] = self._csrf
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            resp = self._opener.open(req, timeout=timeout)
            raw = resp.read()
            try:
                return json.loads(raw.decode())
            except Exception:
                return {"_raw": raw[:400].decode("utf-8", "replace"), "_status": resp.status}
        except urllib.error.HTTPError as e:
            raw = e.read()[:500]
            try:
                parsed = json.loads(raw.decode())
            except Exception:
                parsed = raw.decode("utf-8", "replace")
            return {"_error": True, "_status": e.code, "_body": parsed}

    def current_user(self) -> dict:
        raw = self._opener.open(self.base + "/accounts/current_user/", timeout=15).read().decode("utf-8", "replace")
        m = re.search(r"var current_user = ({.*});", raw)
        if not m:
            return {"_error": True, "_message": "no current_user"}
        return json.loads(m.group(1))

    def sources(self) -> dict:
        return self._req("GET", "/rest/rules/source/?format=json")

    def source(self, pk: int) -> dict:
        return self._req("GET", f"/rest/rules/source/{pk}/")

    def update_source(self, pk: int) -> dict:
        """Queue a source fetch. Returns {task_pk: N}."""
        return self._req("POST", f"/rest/rules/source/{pk}/update_source/", data={})

    def ruleset(self, pk: int = 1) -> dict:
        return self._req("GET", f"/rest/rules/ruleset/{pk}/")

    def update_ruleset(self, pk: int = 1) -> dict:
        """Rebuild Default ruleset from sources. Returns {task_pk: N}."""
        return self._req("POST", f"/rest/rules/ruleset/{pk}/update_ruleset/", data={})

    def system_settings(self) -> dict:
        return self._req("GET", "/rest/rules/system_settings/?format=json")

    def status(self) -> dict:
        if not self._csrf:
            login = self.login()
            if login.get("_error"):
                return login
        user = self.current_user()
        src = self.sources()
        rs = self.ruleset(1)
        return {
            "user": {k: user.get(k) for k in ("username", "role", "email", "timezone") if isinstance(user, dict)},
            "sources": [
                {
                    "pk": s.get("pk"),
                    "name": s.get("name"),
                    "version": s.get("version"),
                    "updated_date": s.get("updated_date"),
                    "uri": s.get("uri"),
                }
                for s in (src.get("results") or [])
            ],
            "ruleset": {
                "name": rs.get("name"),
                "rules_count": rs.get("rules_count"),
                "updated_date": rs.get("updated_date"),
                "validity": rs.get("validity"),
                "errors": rs.get("errors"),
            },
        }

    def arkime_sessions(self, expression: str, length: int = 20) -> dict:
        """Query Arkime sessions (same NDR login). expression e.g. ip == 1.2.3.4"""
        if not self._csrf:
            login = self.login()
            if login.get("_error"):
                return login
        q = urllib.parse.urlencode({"expression": expression, "length": str(length)})
        return self._req("GET", f"/arkime/api/sessions?{q}")

    def arkime_users(self) -> dict:
        if not self._csrf:
            login = self.login()
            if login.get("_error"):
                return login
        return self._req("POST", "/arkime/api/users", data={})
