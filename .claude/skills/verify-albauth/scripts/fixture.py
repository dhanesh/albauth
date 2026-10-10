#!/usr/bin/env python3
"""A local stand-in for the systems albauth sits between: the login proxy, the
identity provider and the application behind them.

albauth's job is to tell those three apart from the responses alone, so this
fixture serves every response shape the review found mattered — HTML error
pages, redirects with and without a body, a presigned-download redirect, an
application's own 401, a proxy that rotates its session cookie — under one
port per proxy style.

Modes:
  alb      An AWS ALB `authenticate-oidc` rule: no session -> 302 to the IdP.
  oauth2   oauth2-proxy behind Traefik forwardAuth: no session -> 401, login
           starts at /oauth2/start, /oauth2/auth answers 202 or 401.

The IdP is served by the same process under /idp/, but addressed as
`localhost:<port>` while the protected app is `127.0.0.1:<port>`, so every
IdP hop is a genuine cross-host redirect. It approves every request at once,
which lets a real browser login finish with nobody at the keyboard.

Admin routes live under /__fixture/ and stand in for what a human would do
at the proxy (issue a session, revoke one) or observe (how many times the
app was hit). They are part of the mock, not of albauth.

Stdlib only. Every response the app half produces is logged as one JSON line
to stdout.
"""
import argparse
import json
import secrets
import sys
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

ALB_PREFIX = "AWSELBAuthSessionCookie"
O2_COOKIE = "_oauth2_proxy"
O2_CSRF = "_oauth2_proxy_csrf"


class State:
    def __init__(self, mode, port, instance):
        self.mode, self.port, self.instance = mode, port, instance
        self.lock = threading.Lock()
        self.valid = set()  # valid session values (joined chunks for ALB)
        self.hits = {}
        # Seconds the next ALB login is held on the IdP host after the session
        # cookie is set (one-shot; see /__fixture/hold).
        self.hold = 0

    def mint(self, big=False):
        """Return a fresh valid session as [(name, value), ...]."""
        if self.mode == "alb":
            if big:
                chunks = [secrets.token_urlsafe(3000)[:4000], secrets.token_urlsafe(900)[:1200]]
            else:
                chunks = [secrets.token_urlsafe(48)]
            cookies = [(f"{ALB_PREFIX}-{i}", v) for i, v in enumerate(chunks)]
            key = "".join(chunks)
        else:
            value = secrets.token_urlsafe(48)
            cookies, key = [(O2_COOKIE, value)], value
        with self.lock:
            self.valid.add(key)
        return cookies

    def session_key(self, jar):
        if self.mode == "alb":
            chunks = sorted((k, v) for k, v in jar.items() if k.startswith(ALB_PREFIX + "-"))
            return "".join(v for _, v in chunks) or None
        return jar.get(O2_COOKIE)

    def is_valid(self, jar):
        key = self.session_key(jar)
        with self.lock:
            return key is not None and key in self.valid

    def hit(self, method, path):
        with self.lock:
            k = f"{method} {path}"
            self.hits[k] = self.hits.get(k, 0) + 1


HTML_REDIRECT_BODY = '<a href="{loc}">Found</a>.\n'


class Handler(BaseHTTPRequestHandler):
    server_version = "albauth-fixture/1"
    state: State = None  # set per server

    # ---------------------------------------------------------------- helpers
    def log_message(self, fmt, *args):  # keep stderr quiet; stdout gets JSON
        pass

    def jar(self):
        c = SimpleCookie()
        c.load(self.headers.get("Cookie", ""))
        return {k: m.value for k, m in c.items()}

    def send(self, status, body=b"", ctype="application/json", headers=(), cookies=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if body or ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        print(json.dumps({"method": self.command, "path": self.path, "status": status}), flush=True)

    def js(self, status, obj, **kw):
        self.send(status, json.dumps(obj), "application/json", **kw)

    def app_host(self):
        return f"127.0.0.1:{self.state.port}"

    def idp_authorize_url(self, redirect_path, state="s"):
        q = urlencode({"client_id": "albauth-fixture", "response_type": "code",
                       "scope": "openid", "state": state,
                       "redirect_uri": f"http://{self.app_host()}{redirect_path}"})
        return f"http://localhost:{self.state.port}/idp/authorize?{q}"

    def set_session_cookies(self, cookies):
        # Persistent, as real proxies issue them (an ALB session cookie carries
        # the session timeout): a browser profile keeps it across restarts.
        return [f"{n}={v}; Path=/; HttpOnly; Max-Age=3600" for n, v in cookies]

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_PUT(self):
        self.route()

    def do_PATCH(self):
        self.route()

    def do_DELETE(self):
        self.route()

    def do_HEAD(self):
        self.route()

    def route(self):
        self.read_body()
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        st = self.state

        if p.startswith("/__fixture/"):
            return self.admin(p, q)
        if p == "/idp/authorize":
            # Auto-approve: straight back to the redirect_uri with a code.
            target = q.get("redirect_uri", [""])[0]
            sep = "&" if "?" in target else "?"
            loc = f"{target}{sep}code=ok&state={q.get('state', [''])[0]}"
            return self.send(302, HTML_REDIRECT_BODY.format(loc=loc), "text/html; charset=utf-8",
                             headers=[("Location", loc)])

        if p == "/idp/hold":
            # An IdP page the login lingers on, off the API host so the login
            # cannot settle, until it sends the browser back.
            back = q.get("back", ["/"])[0]
            secs = int(q.get("seconds", ["0"])[0])
            page = (f'<!doctype html><title>Hold</title>'
                    f'<meta http-equiv="refresh" content="{secs};url={back}"><p>One moment.</p>')
            return self.send(200, page, "text/html; charset=utf-8")

        if st.mode == "alb" and p == "/oauth2/idpresponse":
            loc = "/"
            with st.lock:
                hold, st.hold = st.hold, 0
            if hold:
                loc = (f"http://localhost:{st.port}/idp/hold?"
                       + urlencode({"seconds": hold, "back": f"http://{self.app_host()}/"}))
            return self.send(302, "", "text/html", headers=[("Location", loc)],
                             cookies=self.set_session_cookies(st.mint(big=st_big(q))))
        if st.mode == "oauth2":
            if p == "/oauth2/start":
                loc = self.idp_authorize_url("/oauth2/callback")
                return self.send(302, HTML_REDIRECT_BODY.format(loc=loc), "text/html; charset=utf-8",
                                 headers=[("Location", loc)],
                                 cookies=[f"{O2_CSRF}={secrets.token_urlsafe(16)}; Path=/; HttpOnly"])
            if p == "/oauth2/callback":
                cookies = self.set_session_cookies(st.mint())
                cookies.append(f"{O2_CSRF}=; Path=/; Max-Age=0")
                return self.send(302, "", "text/html", headers=[("Location", "/")], cookies=cookies)
            if p == "/oauth2/auth":
                return self.send(202 if st.is_valid(self.jar()) else 401, "", "text/plain")
            if p == "/oauth2/sign_in":
                # oauth2-proxy's sign-in page: a 403 on the protected host that
                # sets a CSRF cookie sharing the session cookie's prefix, then
                # moves on to /oauth2/start a moment later.
                page = ('<!doctype html><title>Sign in</title>'
                        '<meta http-equiv="refresh" content="2;url=/oauth2/start">'
                        '<p>Sign in with your identity provider.</p>')
                return self.send(403, page, "text/html; charset=utf-8",
                                 cookies=[f"{O2_CSRF}={secrets.token_urlsafe(16)}; Path=/; HttpOnly"])

        # Everything else is the protected application.
        if not st.is_valid(self.jar()):
            if st.mode == "alb":
                loc = self.idp_authorize_url("/oauth2/idpresponse")
                return self.send(302, "", None, headers=[("Location", loc)])
            return self.send(401, "Unauthorized\n", "text/plain; charset=utf-8")
        st.hit(self.command, p)
        return self.app(p, q)

    def app(self, p, q):
        parts = [s for s in p.split("/") if s]
        if p in ("/", "/json"):
            return self.js(200, {"ok": True, "path": p, "method": self.command})
        if len(parts) == 2 and parts[0] == "html":
            code = int(parts[1])
            return self.send(code, f"<!doctype html><title>{code}</title><h1>{code}</h1>",
                             "text/html; charset=utf-8")
        if len(parts) == 3 and parts[0] == "redirect" and parts[1] in ("same", "cross"):
            code = int(parts[2])
            if parts[1] == "same":
                loc = "/json"
            else:
                loc = (f"http://localhost:{self.state.port}/bucket/report.pdf"
                       "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=fixture")
            if q.get("bare"):
                return self.send(code, "", None, headers=[("Location", loc)])
            return self.send(code, HTML_REDIRECT_BODY.format(loc=loc), "text/html; charset=utf-8",
                             headers=[("Location", loc)])
        if p == "/rotate":
            # The proxy refreshes the session: a new value under the same name.
            fresh = self.state.mint()
            return self.js(200, {"rotated": [n for n, _ in fresh]},
                           cookies=self.set_session_cookies(fresh))
        if p == "/app401":
            if self.headers.get("X-App-Token") == "good":
                return self.js(200, {"ok": True, "app_token": "accepted"})
            return self.js(401, {"error": "invalid application token"},
                           headers=[("WWW-Authenticate", 'Bearer realm="app"')])
        return self.js(404, {"error": "no such fixture route", "path": p})

    def admin(self, p, q):
        st = self.state
        if p == "/__fixture/health":
            return self.js(200, {"mode": st.mode, "port": st.port, "instance": st.instance})
        if p == "/__fixture/issue":
            cookies = st.mint(big=st_big(q))
            return self.js(200, {"cookies": [{"name": n, "value": v} for n, v in cookies],
                                 "import": "\n".join(f"{n}={v}" for n, v in cookies) + "\n"})
        if p == "/__fixture/expire":
            with st.lock:
                n = len(st.valid)
                st.valid.clear()
            return self.js(200, {"revoked": n})
        if p == "/__fixture/hold":
            # Hold the next login on the IdP host for this many seconds after
            # the session cookie is set. Chrome writes cookies to disk on a
            # timer (about 30 s), so a hold longer than that leaves the
            # session in the browser profile, as a real long login would.
            with st.lock:
                st.hold = int(q.get("seconds", ["0"])[0])
            return self.js(200, {"hold": st.hold})
        if p == "/__fixture/hits":
            with st.lock:
                return self.js(200, dict(st.hits))
        if p == "/__fixture/reset":
            with st.lock:
                st.hits.clear()
            return self.js(200, {"reset": True})
        if p == "/__fixture/valid":
            # Is this cookie header a live session? Lets a verifier check a
            # stored session without ever printing its value.
            return self.js(200, {"valid": st.is_valid(self.jar())})
        return self.js(404, {"error": "no such admin route"})


def st_big(q):
    return bool(q.get("big"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["alb", "oauth2"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--instance", required=True)
    a = ap.parse_args()
    state = State(a.mode, a.port, a.instance)
    handler = type("H", (Handler,), {"state": state})
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), handler)
    print(json.dumps({"ready": True, "mode": a.mode, "port": a.port}), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
