#!/usr/bin/env python3
"""Self-contained runtime checks: one scenario = launch, drive, assert, clean up.

    python3 .claude/skills/verify-albauth/scripts/prove.py <scenario> [--keep]

Each scenario launches its own instance through harness.py (so it can run as
a plan's verify command with nothing set up beforehand), drives the real
albauth binary over MCP stdio or its CLI, checks what came back AND the
fixture's record of what reached the application, then cleans up. It prints
one JSON object and exits 0 when every assertion holds, 1 when one fails,
2 when the instance could not be set up.

`--list` prints the scenarios. `--keep` leaves the instance running for a
look around (run harness.py cleanup afterwards).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
HARNESS = [sys.executable, str(SCRIPTS / "harness.py")]


class Fail(Exception):
    pass


class Run:
    def __init__(self, scenario):
        self.instance = f"prove-{scenario}-{os.getpid()}"
        self.checks = []

    def h(self, *args, timeout=300):
        p = subprocess.run(HARNESS + [args[0], "--instance", self.instance, *args[1:]],
                           capture_output=True, text=True, timeout=timeout)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"raw": p.stdout[-2000:], "stderr": p.stderr[-2000:]}

    def env(self):
        root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip()
        return json.loads((Path(root) / ".verify-run" / self.instance / "env.json").read_text())

    def check(self, name, ok, detail=None):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})

    def calls(self, *specs, timeout=180):
        code, r = self.h("call", *specs, "--timeout", str(timeout), timeout=timeout + 60)
        if code != 0 or "calls" not in r:
            raise Fail(f"call failed: {json.dumps(r)[:800]}")
        return r

    def fixture(self, host, route):
        return self.h("fixture", host, route)[1].get("body")

    def session(self, domain):
        return self.h("session", domain)[1]

    def cli(self, *argv, timeout=180):
        return self.h("cli", "--timeout", str(timeout), "--", *argv, timeout=timeout + 30)[1]

    def config_append(self, text):
        p = Path(self.env()["config"])
        p.write_text(p.read_text() + text)

    def config_set(self, domain, key, value_toml):
        """Insert `key = value` at the top of a [[domain]] block (replacing any)."""
        p = Path(self.env()["config"])
        lines, out, cur = p.read_text().splitlines(), [], None
        for ln in lines:
            if ln.startswith("name = "):
                cur = ln.split("=", 1)[1].strip().strip('"')
            if cur == domain and ln.split("=", 1)[0].strip() == key:
                continue
            out.append(ln)
            if ln.startswith("name = ") and cur == domain:
                out.append(f"{key} = {value_toml}")
        p.write_text("\n".join(out) + "\n")


def data(call):
    return call["data"] if isinstance(call["data"], dict) else {}


def hits(run, host):
    return run.fixture(host, "hits") or {}


# ----------------------------------------------------------------- scenarios
def s_html_errors(r):
    """R1: an application's non-2xx HTML (other than 401/403) is returned, no re-login."""
    r.fixture("alb-api", "reset")
    res = r.calls(*[f'http_request={{"url":"{{host:alb-api}}/html/{c}"}}' for c in (404, 500, 502, 503)])
    for call, code in zip(res["calls"], (404, 500, 502, 503)):
        d = data(call)
        r.check(f"html {code} returned as result", not call["isError"] and d.get("status") == code,
                {"isError": call["isError"], "error": d.get("error"), "status": d.get("status")})
        r.check(f"html {code} no relogin", d.get("relogin_performed") is False)
    h = hits(r, "alb-api")
    for c in (404, 500, 502, 503):
        r.check(f"GET /html/{c} reached the app once", h.get(f"GET /html/{c}") == 1, h.get(f"GET /html/{c}"))
    r.check("no browser login (login probe never hit)", "GET /" not in h, h)


def s_html_signin(r):
    """R2: a 401/403 text/html answer to a JSON request still counts as the proxy's sign-in page."""
    r.fixture("alb-api", "reset")
    before = r.session("alb-api")
    res = r.calls('http_request={"url":"{host:alb-api}/html/403"}')
    call = res["calls"][0]
    h = hits(r, "alb-api")
    after = r.session("alb-api")
    r.check("a re-login ran (login probe hit by the browser)", h.get("GET /", 0) >= 1, h)
    r.check("request retried exactly once", h.get("GET /html/403") == 2, h.get("GET /html/403"))
    r.check("session was replaced", before.get("cookies") != after.get("cookies"))
    r.check("persistent 403 reported as auth_loop", call["isError"] and data(call).get("error") == "auth_loop",
            data(call).get("error"))


def s_redirects_same(r):
    """R3: same-host redirects, with or without a body, come back unchanged."""
    r.fixture("alb-api", "reset")
    specs, expect = [], []
    for code in (301, 302, 303, 307, 308):
        for bare in ("", "?bare=1"):
            specs.append(f'http_request={{"url":"{{host:alb-api}}/redirect/same/{code}{bare}"}}')
            expect.append((code, bare))
    res = r.calls(*specs)
    for call, (code, bare) in zip(res["calls"], expect):
        d = data(call)
        r.check(f"same-host {code}{bare} returned", not call["isError"] and d.get("status") == code,
                {"error": d.get("error"), "status": d.get("status")})
        r.check(f"same-host {code}{bare} location kept",
                (d.get("headers") or {}).get("location") == "/json")
    h = hits(r, "alb-api")
    r.check("no browser login", "GET /" not in h, h)


def s_redirect_cross(r):
    """R4: a cross-host redirect that is not an OAuth authorization request comes back unchanged."""
    r.fixture("alb-api", "reset")
    codes = (302, 303, 307)
    res = r.calls(*[f'http_request={{"url":"{{host:alb-api}}/redirect/cross/{c}"}}' for c in codes])
    for call, code in zip(res["calls"], codes):
        d = data(call)
        loc = (d.get("headers") or {}).get("location", "")
        r.check(f"cross-host {code} returned", not call["isError"] and d.get("status") == code,
                {"error": d.get("error"), "status": d.get("status")})
        r.check(f"cross-host {code} location is the presigned URL", "X-Amz-Signature" in loc, loc)
    h = hits(r, "alb-api")
    r.check("each reached the app once", all(h.get(f"GET /redirect/cross/{c}") == 1 for c in codes), h)
    r.check("no browser login", "GET /" not in h, h)


def s_relogin_unlisted_idp(r):
    """R5: an authorization-request redirect to an IdP host not in idp_hostnames re-logs in."""
    before = r.session("alb-api")
    r.fixture("alb-api", "expire")
    r.fixture("alb-api", "reset")
    res = r.calls('http_request={"url":"{host:alb-api}/json"}')
    d = data(res["calls"][0])
    after = r.session("alb-api")
    r.check("request succeeded after re-login", not res["calls"][0]["isError"] and d.get("status") == 200,
            {"error": d.get("error"), "status": d.get("status")})
    r.check("relogin_performed true", d.get("relogin_performed") is True)
    r.check("new session stored and valid", after.get("valid_at_proxy") is True
            and before.get("cookies") != after.get("cookies"))


def s_write_not_resent(r):
    """R6: a write judged unauthenticated by anything but an IdP redirect is sent once only."""
    r.fixture("alb-api", "reset")
    res = r.calls('http_request={"url":"{host:alb-api}/html/403","method":"POST","body":"{}"}')
    call = res["calls"][0]
    d = data(call)
    h = hits(r, "alb-api")
    r.check("POST reached the app exactly once", h.get("POST /html/403") == 1, h.get("POST /html/403"))
    r.check("error is resend_required", call["isError"] and d.get("error") == "resend_required", d)
    r.check("a re-login ran", h.get("GET /", 0) >= 1, h)


def s_write_resent_after_idp(r):
    """R7: a write that met the proxy's IdP redirect is resent once after logging in."""
    r.fixture("alb-api", "expire")
    r.fixture("alb-api", "reset")
    res = r.calls('http_request={"url":"{host:alb-api}/html/500","method":"POST","body":"{}"}')
    call = res["calls"][0]
    d = data(call)
    h = hits(r, "alb-api")
    r.check("result is the app's 500", not call["isError"] and d.get("status") == 500,
            {"error": d.get("error"), "status": d.get("status")})
    r.check("relogin_performed true", d.get("relogin_performed") is True)
    r.check("POST reached the app exactly once", h.get("POST /html/500") == 1, h.get("POST /html/500"))


def s_app_refusal(r):
    """R8: with session_check_path, the app's own 401 is returned without a re-login."""
    r.config_set("o2-api", "session_check_path", '"/oauth2/auth"')
    before = r.session("o2-api")
    res = r.calls('http_request={"url":"{host:o2-api}/app401"}',
                  'http_request={"url":"{host:o2-api}/app401","headers":{"X-App-Token":"good"}}')
    first, second = res["calls"]
    d = data(first)
    after = r.session("o2-api")
    r.check("app 401 returned as result", not first["isError"] and d.get("status") == 401,
            {"error": d.get("error"), "status": d.get("status")})
    r.check("app body kept", "invalid application token" in (d.get("body") or ""))
    r.check("no relogin", d.get("relogin_performed") is False)
    r.check("session untouched", before.get("cookies") == after.get("cookies"))
    r.check("same session works with the right app token", data(second).get("status") == 200)


def s_o2_expired(r):
    """R9: with session_check_path, a 401 whose check also fails re-logs in."""
    r.config_set("o2-api", "session_check_path", '"/oauth2/auth"')
    r.fixture("o2-api", "expire")
    res = r.calls('http_request={"url":"{host:o2-api}/json"}')
    d = data(res["calls"][0])
    after = r.session("o2-api")
    r.check("request succeeded after re-login", not res["calls"][0]["isError"] and d.get("status") == 200,
            {"error": d.get("error"), "status": d.get("status")})
    r.check("relogin_performed true", d.get("relogin_performed") is True)
    r.check("new session valid at proxy", after.get("valid_at_proxy") is True)


def s_domain_setup(r):
    """R10: add-domain detects oauth2-proxy and sets session_check_path."""
    env = r.env()
    cfg = Path(env["config"])
    # A second oauth2 fixture host is not available, so probe the o2 host after
    # removing the o2-api block (two domains may not claim one host).
    text = cfg.read_text()
    cfg.write_text(text.split("[[domain]]\nname = \"o2-api\"")[0])
    out = r.cli("config", "add-domain", "o2-probe", "--base-url", env["hosts"]["o2-api"])
    after = cfg.read_text()
    block = after.split('name = "o2-probe"')[-1] if 'name = "o2-probe"' in after else ""
    r.check("add-domain exited 0", out.get("exit") == 0, out.get("stderr", "")[-400:])
    r.check("probe found the login path", "/oauth2/start" in block, block)
    r.check("cookie family set", 'cookie_name_prefix = "_oauth2_proxy"' in block, block)
    r.check("treat_401_as_expired on", "treat_401_as_expired = true" in block, block)
    r.check("session_check_path set", 'session_check_path = "/oauth2/auth"' in block, block)


def s_storage(r):
    """R11 (runtime half): a two-chunk 5.2 KB session imports, persists and works."""
    imp = r.h("import", "alb-api", "--big")[1]
    s = r.session("alb-api")
    res = r.calls('auth_status={"domain":"alb-api"}', 'http_request={"url":"{host:alb-api}/json"}')
    names = [(c["name"], c["len"]) for c in s.get("cookies", [])]
    r.check("import exited 0", imp.get("exit") == 0, imp)
    r.check("both chunks stored", names == [("AWSELBAuthSessionCookie-0", 4000),
                                            ("AWSELBAuthSessionCookie-1", 1200)], names)
    r.check("stored session valid at proxy", s.get("valid_at_proxy") is True)
    st = res["calls"][0]["data"]
    r.check("auth_status authenticated", isinstance(st, list) and st and st[0].get("authenticated") is True, st)
    r.check("request works", data(res["calls"][1]).get("status") == 200)


def s_rotate(r):
    """R12: a refreshed session cookie from the proxy replaces the stored one."""
    before = r.session("alb-api")
    res = r.calls('http_request={"url":"{host:alb-api}/rotate"}', 'http_request={"url":"{host:alb-api}/json"}')
    after = r.session("alb-api")
    d = data(res["calls"][0])
    r.check("rotate returned 200", d.get("status") == 200)
    r.check("set-cookie not returned to the caller", "set-cookie" not in (d.get("headers") or {}))
    r.check("stored session changed", before.get("cookies") != after.get("cookies"),
            {"before": before.get("cookies"), "after": after.get("cookies")})
    r.check("new stored session valid at proxy", after.get("valid_at_proxy") is True)
    r.check("next request still authenticated", data(res["calls"][1]).get("status") == 200)


def s_signin_page(r):
    """R13+R14: a browser login that meets a 403 sign-in page keeps only the real session."""
    r.config_set("o2-api", "login_probe_path", '"/oauth2/sign_in"')
    res = r.calls('auth_login={"domain":"o2-api","force":true}', timeout=90)
    call = res["calls"][0]
    s = r.session("o2-api")
    names = [c["name"] for c in s.get("cookies", [])]
    r.check("auth_login succeeded", not call["isError"], data(call) or call["data"])
    r.check("only the session cookie stored", names == ["_oauth2_proxy"], names)
    r.check("stored session valid at proxy", s.get("valid_at_proxy") is True)


def s_force(r):
    """R15: auth_login force mints a new session even when the browser still holds one."""
    # Hold the first login on the IdP for longer than Chrome's cookie-flush
    # timer, so its session cookie is on disk in the profile when the second
    # login starts. Without the hold the window closes first, the profile
    # never keeps the cookie, and a force that does nothing would still pass.
    r.fixture("alb-api", "hold?seconds=40")
    first = r.calls('auth_login={"domain":"alb-api","force":true}', timeout=150)
    a = r.session("alb-api")
    second = r.calls('auth_login={"domain":"alb-api","force":true}', timeout=90)
    b = r.session("alb-api")
    r.check("both logins succeeded", not first["calls"][0]["isError"] and not second["calls"][0]["isError"])
    r.check("second force produced a different session", a.get("cookies") != b.get("cookies"),
            {"first": a.get("cookies"), "second": b.get("cookies")})
    r.check("new session valid at proxy", b.get("valid_at_proxy") is True)


def s_redaction(r):
    """R16 (runtime half): no stored session value appears on stderr, for either cookie family."""
    res = r.calls('http_request={"url":"{host:o2-api}/json"}', 'http_request={"url":"{host:alb-api}/json"}')
    env = r.env()
    root = Path(env["home"])
    files = list(root.rglob("sessions.json"))
    values = []
    for f in files:
        for dom in (json.loads(f.read_text()).get("domains") or {}).values():
            values += [c["value"] for c in dom.get("cookies", [])]
    err = res.get("stderr_tail", "")
    r.check("found stored values to check", len(values) >= 2, len(values))
    r.check("no stored value on stderr", not any(v in err for v in values))


def s_discovery(r):
    """R17+R18+R19: an unconfigured host behind a login wall is spotted, added read-only, usable at once."""
    res = r.calls('http_request={"url":"{host:unconfigured}/json"}',
                  'add_domain={"name":"found-api","base_url":"{host:unconfigured}"}',
                  'list_domains={}',
                  'add_domain={"name":"bad-api","base_url":"{host:unconfigured}","allow_methods":["POST"]}',
                  'http_request={"url":"{host:unconfigured}/json"}', timeout=120)
    c = res["calls"]
    d0 = data(c[0])
    sug = d0.get("suggestion") or {}
    r.check("unknown_domain with a suggestion", c[0]["isError"] and d0.get("error") == "unknown_domain" and sug,
            d0)
    r.check("suggestion names the base URL", r.env()["hosts"]["unconfigured"] in json.dumps(sug), sug)
    r.check("add_domain succeeded", not c[1]["isError"], c[1]["data"])
    listed = [x for x in (c[2]["data"] if isinstance(c[2]["data"], list) else [])
              if x.get("name") == "found-api"]
    r.check("found-api listed in the same server", bool(listed), c[2]["data"])
    r.check("found-api is read-only", bool(listed) and listed[0].get("allow_methods") == ["GET"],
            listed[0].get("allow_methods") if listed else None)
    r.check("write methods refused", c[3]["isError"], c[3]["data"])
    cfg = Path(r.env()["config"]).read_text()
    r.check("config file gained found-api only", 'name = "found-api"' in cfg and 'name = "bad-api"' not in cfg)
    r.check("new domain reachable after login", isinstance(c[4]["data"], dict)
            and c[4]["data"].get("status") == 200, c[4]["data"])


SCENARIOS = {
    "html-errors": s_html_errors, "html-signin": s_html_signin, "redirects-same": s_redirects_same,
    "redirect-cross": s_redirect_cross, "relogin-unlisted-idp": s_relogin_unlisted_idp,
    "write-not-resent": s_write_not_resent, "write-resent-after-idp": s_write_resent_after_idp,
    "app-refusal": s_app_refusal, "o2-expired": s_o2_expired, "domain-setup": s_domain_setup,
    "storage": s_storage, "rotate": s_rotate, "signin-page": s_signin_page, "force": s_force,
    "redaction": s_redaction, "discovery": s_discovery,
}


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    if args[0] == "--list":
        for k, fn in SCENARIOS.items():
            print(f"{k:24} {fn.__doc__}")
        return 0
    name, keep = args[0], "--keep" in args
    if name not in SCENARIOS:
        print(json.dumps({"error": f"unknown scenario {name!r}", "known": sorted(SCENARIOS)}))
        return 2
    r = Run(name)
    code, launched = r.h("launch")
    if code != 0:
        print(json.dumps({"scenario": name, "error": "launch failed", "detail": launched}, indent=2))
        r.h("cleanup")
        return 2
    try:
        SCENARIOS[name](r)
        error = None
    except Fail as e:
        error = str(e)
    finally:
        if not keep:
            r.h("cleanup")
    ok = error is None and r.checks and all(c["ok"] for c in r.checks)
    print(json.dumps({"scenario": name, "instance": r.instance, "pass": bool(ok), "error": error,
                      "checks": r.checks}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
