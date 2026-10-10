#!/usr/bin/env python3
"""Drive albauth the way an MCP client and a user do, one isolated instance at a time.

Every subcommand takes --instance. An instance owns:
  .verify-run/<instance>/
    albauth              the binary built from the checkout under test
    home/                HOME for albauth: state dir, sessions.json, browser profiles
    config.toml          its ALBAUTH_CONFIG
    env.json             ports and paths, written by launch
    fixture-*.pid/.log   the local proxy/IdP/app stand-ins (scripts/fixture.py)

Three fixture ports per instance, from one claim of a 3-port span:
  base+0  alb      configured as domain "alb-api"
  base+1  oauth2   configured as domain "o2-api"
  base+2  alb      NOT configured: the host a user has not told albauth about

All output is JSON on stdout. Cookie values are never printed: sessions are
shown by cookie name and a sha256 prefix of the value.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
RECORDER = SCRIPTS / "verify_evidence.py"
FIXTURE = SCRIPTS / "fixture.py"


def repo_root(worktree=None):
    start = worktree or os.getcwd()
    out = subprocess.run(["git", "-C", start, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True)
    return Path(out.stdout.strip())


def run_dir(args):
    return repo_root(args.worktree) / ".verify-run" / args.instance


def load_env(args):
    p = run_dir(args) / "env.json"
    if not p.exists():
        die(f"instance {args.instance!r} is not launched (no {p})")
    return json.loads(p.read_text())


def out(obj, code=0):
    print(json.dumps(obj, indent=2, sort_keys=True))
    sys.exit(code)


def die(msg, code=2):
    out({"error": msg}, code)


def child_env(env):
    e = os.environ.copy()
    e["HOME"] = env["home"]
    e["ALBAUTH_CONFIG"] = env["config"]
    e.pop("XDG_STATE_HOME", None)
    return e


def http(url, timeout=5):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def config_toml(base):
    return f'''[settings]
storage = "file"
log_level = "debug"

[[domain]]
name = "alb-api"
base_url = "http://127.0.0.1:{base}"
allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
login_timeout_seconds = 30
timeout_seconds = 10

[[domain]]
name = "o2-api"
base_url = "http://127.0.0.1:{base + 1}"
cookie_name_prefix = "_oauth2_proxy"
treat_401_as_expired = true
login_probe_path = "/oauth2/start"
allow_methods = ["GET", "POST"]
login_timeout_seconds = 30
timeout_seconds = 10
'''


# ------------------------------------------------------------------ commands
def cmd_launch(args):
    rd = run_dir(args)
    if (rd / "env.json").exists():
        die(f"instance {args.instance!r} is already launched; run cleanup first")
    rd.mkdir(parents=True, exist_ok=True)
    root = repo_root(args.worktree)

    claim = subprocess.run([sys.executable, str(RECORDER), "port", "--instance", args.instance,
                            "--span", "3"] + (["--worktree", args.worktree] if args.worktree else []),
                           capture_output=True, text=True)
    if claim.returncode != 0 or not claim.stdout.startswith("PORT:"):
        die(f"port claim failed: {claim.stdout.strip()} {claim.stderr.strip()}")
    base = int(claim.stdout.split()[1])

    binary = rd / "albauth"
    build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/albauth"], cwd=root,
                           capture_output=True, text=True)
    if build.returncode != 0:
        die(f"go build failed: {build.stderr[-600:]}")

    home = rd / "home"
    home.mkdir(exist_ok=True)
    cfg = rd / "config.toml"
    cfg.write_text(config_toml(base))
    env = {"instance": args.instance, "base": base, "binary": str(binary), "home": str(home),
           "config": str(cfg), "root": str(root),
           "hosts": {"alb-api": f"http://127.0.0.1:{base}",
                     "o2-api": f"http://127.0.0.1:{base + 1}",
                     "unconfigured": f"http://127.0.0.1:{base + 2}"}}

    for key, mode, port in (("alb", "alb", base), ("o2", "oauth2", base + 1),
                            ("unconfigured", "alb", base + 2)):
        log = open(rd / f"fixture-{key}.log", "w")
        proc = subprocess.Popen([sys.executable, str(FIXTURE), "--mode", mode, "--port", str(port),
                                 "--instance", args.instance], stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        (rd / f"fixture-{key}.pid").write_text(str(proc.pid))

    # Readiness: each fixture's health route answers for THIS instance. 15 s max.
    deadline = time.time() + 15
    pending = dict(env["hosts"])
    while pending and time.time() < deadline:
        for name, url in list(pending.items()):
            try:
                status, body = http(url + "/__fixture/health", timeout=1)
                if status == 200 and body and body.get("instance") == args.instance:
                    pending.pop(name)
            except OSError:
                pass
        time.sleep(0.2)
    if pending:
        die(f"fixtures not ready after 15s: {sorted(pending)}")
    (rd / "env.json").write_text(json.dumps(env, indent=2))

    # Give both configured domains a working session, the way a headless user
    # would: `albauth auth import` with the cookie the proxy issued.
    for dom in ("alb-api", "o2-api"):
        r = do_import(env, dom, big=False)
        if r["exit"] != 0:
            die(f"auth import for {dom} failed: {r}")
    out({"launched": args.instance, "base_port": base, "hosts": env["hosts"],
         "binary": str(binary), "ready": True})


def do_import(env, domain, big):
    host = env["hosts"][domain]
    status, body = http(host + "/__fixture/issue" + ("?big=1" if big else ""))
    if status != 200:
        return {"exit": 1, "error": f"fixture issue answered {status}"}
    p = subprocess.run([env["binary"], "auth", "import", domain], input=body["import"] + "\n",
                       capture_output=True, text=True, env=child_env(env), timeout=30)
    return {"exit": p.returncode, "stderr_tail": redact_tail(p.stderr, body)}


def redact_tail(text, issued):
    for c in issued.get("cookies", []):
        text = text.replace(c["value"], f"<redacted:{len(c['value'])}>")
    return text[-600:]


def cmd_doctor(args):
    env = load_env(args)
    checks = {}
    for name, url in env["hosts"].items():
        try:
            status, body = http(url + "/__fixture/health", timeout=2)
            checks[f"fixture-{name}"] = status == 200 and body.get("instance") == args.instance
        except OSError:
            checks[f"fixture-{name}"] = False
    v = subprocess.run([env["binary"], "version"], capture_output=True, text=True, env=child_env(env))
    checks["binary"] = v.returncode == 0
    c = subprocess.run([env["binary"], "config", "validate"], capture_output=True, text=True,
                       env=child_env(env))
    checks["config"] = c.returncode == 0
    ok = all(checks.values())
    out({"instance": args.instance, "ok": ok, "checks": checks, "version": v.stdout.strip()},
        0 if ok else 1)


def mcp(env, calls, timeout=120):
    """Run one `albauth serve`, send initialize + the given tools/call list."""
    msgs = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "verify-albauth", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"}]
    for i, (tool, arguments) in enumerate(calls, start=1):
        msgs.append({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"name": tool, "arguments": arguments}})
    proc = subprocess.Popen([env["binary"], "serve"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=child_env(env))
    # Send calls one at a time and wait for each answer, so a later call sees
    # the state an earlier one left (a config reload, a refreshed session).
    proc.stdin.write(json.dumps(msgs[0]) + "\n" + json.dumps(msgs[1]) + "\n")
    proc.stdin.flush()
    results, deadline = {}, time.time() + timeout
    want = 0
    pending_lines = []

    def read_until(target_id):
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                return None
            try:
                m = json.loads(line)
            except ValueError:
                return "stdout-not-jsonrpc: " + line[:200]
            if m.get("id") == target_id:
                return m
        return None

    if read_until(0) is None:
        proc.kill()
        return {"error": "no initialize answer", "stderr": proc.stderr.read()[-800:]}
    for i in range(1, len(calls) + 1):
        proc.stdin.write(json.dumps(msgs[i + 1]) + "\n")
        proc.stdin.flush()
        m = read_until(i)
        if m is None or isinstance(m, str):
            proc.kill()
            return {"error": m or f"no answer to call {i} within {timeout}s",
                    "stderr": proc.stderr.read()[-800:]}
        res = m.get("result", {})
        text = (res.get("content") or [{}])[0].get("text", "")
        try:
            data = json.loads(text)
        except ValueError:
            data = text
        results[i] = {"tool": calls[i - 1][0], "isError": bool(res.get("isError")), "data": data}
    proc.stdin.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    stderr = proc.stderr.read()
    return {"calls": [results[i] for i in sorted(results)], "stderr_tail": stderr[-1500:]}


def cmd_call(args):
    env = load_env(args)
    calls = []
    for spec in args.calls:
        tool, _, raw = spec.partition("=")
        arguments = json.loads(raw) if raw else {}
        for k, v in list(arguments.items()):  # {host:alb-api} -> fixture URL
            if isinstance(v, str) and v.startswith("{host:"):
                name, _, rest = v[6:].partition("}")
                arguments[k] = env["hosts"][name] + rest
        calls.append((tool, arguments))
    r = mcp(env, calls, timeout=args.timeout)
    out(r, 1 if "error" in r else 0)


def cmd_fixture(args):
    env = load_env(args)
    status, body = http(env["hosts"][args.host] + "/__fixture/" + args.route.lstrip("/"))
    out({"status": status, "body": body}, 0 if status == 200 else 1)


def stored_session(env, domain):
    sessions = Path(env["home"]) / "Library" / "Application Support" / "albauth" / "sessions.json"
    if sys.platform != "darwin":
        sessions = Path(env["home"]) / ".local" / "state" / "albauth" / "sessions.json"
    if not sessions.exists():
        return None, sessions
    data = json.loads(sessions.read_text())
    return (data.get("domains") or {}).get(domain), sessions


def cmd_session(args):
    env = load_env(args)
    s, path = stored_session(env, args.domain)
    if s is None:
        out({"domain": args.domain, "stored": False, "file": str(path)})
    cookies = s.get("cookies") or []
    header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    host = env["hosts"].get(args.domain)
    valid = None
    if host:
        req = urllib.request.Request(host + "/__fixture/valid", headers={"Cookie": header})
        with urllib.request.urlopen(req, timeout=5) as r:
            valid = json.loads(r.read())["valid"]
    out({"domain": args.domain, "stored": True, "file": str(path),
         "cookies": [{"name": c["name"], "len": len(c["value"]),
                      "sha256": hashlib.sha256(c["value"].encode()).hexdigest()[:12]}
                     for c in cookies],
         "acquired_at": s.get("acquired_at"), "valid_at_proxy": valid})


def cmd_import(args):
    env = load_env(args)
    r = do_import(env, args.domain, big=args.big)
    out(r, r["exit"])


def cmd_cli(args):
    env = load_env(args)
    p = subprocess.run([env["binary"]] + args.argv, capture_output=True, text=True,
                       env=child_env(env), timeout=args.timeout)
    out({"argv": args.argv, "exit": p.returncode, "stdout": p.stdout[-3000:],
         "stderr": p.stderr[-3000:]}, 0)


def cmd_cleanup(args):
    rd = run_dir(args)
    stopped = []
    for pid_file in rd.glob("fixture-*.pid"):
        try:
            pid = int(pid_file.read_text())
            os.killpg(pid, signal.SIGTERM)
            stopped.append(pid)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    subprocess.run([sys.executable, str(RECORDER), "release", "--instance", args.instance]
                   + (["--worktree", args.worktree] if args.worktree else []),
                   capture_output=True, text=True)
    if rd.exists():
        shutil.rmtree(rd)
    out({"cleaned": args.instance, "stopped_pids": stopped})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn):
        p = sub.add_parser(name)
        p.add_argument("--instance", required=True)
        p.add_argument("--worktree", default=None)
        p.set_defaults(fn=fn)
        return p

    add("launch", cmd_launch)
    add("doctor", cmd_doctor)
    p = add("call", cmd_call)
    p.add_argument("calls", nargs="+", help="tool=JSON-args; '{host:alb-api}/path' expands to the fixture URL")
    p.add_argument("--timeout", type=int, default=120)
    p = add("fixture", cmd_fixture)
    p.add_argument("host", choices=["alb-api", "o2-api", "unconfigured"])
    p.add_argument("route", help="admin route under /__fixture/, e.g. hits, expire, reset")
    p = add("session", cmd_session)
    p.add_argument("domain")
    p = add("import", cmd_import)
    p.add_argument("domain")
    p.add_argument("--big", action="store_true", help="issue a two-chunk 5.2 KB ALB session")
    p = add("cli", cmd_cli)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("argv", nargs=argparse.REMAINDER)
    add("cleanup", cmd_cleanup)
    a = ap.parse_args()
    if a.cmd == "cli" and a.argv and a.argv[0] == "--":
        a.argv = a.argv[1:]
    a.fn(a)


if __name__ == "__main__":
    main()
