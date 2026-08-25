#!/usr/bin/env python3
"""LSC-4: validate carried loop state AT THE ITERATION BOUNDARY.

A malformed state field is caught in the round that produced it, rather than
becoming the next round's premise. On violation the policy is REPAIR (drop the
bad field, restore the last valid value from state.prev.json) and, when the
state is unrepairable, HALT into SAFE_STATE=stopped.

Deliberately stdlib-only: no jsonschema dependency, so the guardrail can never
be skipped for want of a pip install.
"""
import json, pathlib, sys, hashlib

LOOP = pathlib.Path(__file__).resolve().parent.parent / ".loop"
SCHEMA = json.loads((LOOP / "state.schema.json").read_text())
PHASES = set(SCHEMA["properties"]["phase"]["enum"])

def violations(s):
    v = []
    if not isinstance(s, dict): return ["state is not an object"]
    for k in SCHEMA["required"]:
        if k not in s: v.append(f"missing required field: {k}")
    for k in s:
        if k not in SCHEMA["properties"]: v.append(f"unknown field: {k}")
    if not isinstance(s.get("iter"), int) or not 0 <= s.get("iter", -1) <= 40:
        v.append("iter must be int in [0,40]")
    if s.get("phase") not in PHASES:
        v.append(f"phase {s.get('phase')!r} not in {sorted(PHASES)}")
    ver = s.get("verify")
    if not isinstance(ver, dict):
        v.append("verify must be an object")
    else:
        if not isinstance(ver.get("exit_code"), int): v.append("verify.exit_code must be int")
        if not isinstance(ver.get("failures"), list): v.append("verify.failures must be a list")
        for pkg, pct in (ver.get("coverage_by_pkg") or {}).items():
            if not isinstance(pct, (int, float)) or not 0 <= pct <= 100:
                v.append(f"coverage_by_pkg[{pkg}] out of range: {pct!r}")
    d = s.get("last_failure_digest", "")
    if d and (len(d) != 64 or any(c not in "0123456789abcdef" for c in d)):
        v.append("last_failure_digest must be sha256 hex or empty")
    n = s.get("consecutive_no_progress")
    if not isinstance(n, int) or not 0 <= n <= 6:
        v.append("consecutive_no_progress must be int in [0,6]")
    return v

def main():
    p = LOOP / "state.json"
    if not p.exists():
        print("HALT: state.json absent"); return 2
    try:
        s = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"HALT: state.json is not valid JSON: {e}"); return 2

    v = violations(s)
    if not v:
        (LOOP / "state.prev.json").write_text(json.dumps(s, indent=2))
        print(f"state OK  iter={s['iter']} phase={s['phase']} "
              f"exit={s['verify']['exit_code']} no_progress={s['consecutive_no_progress']}")
        return 0

    # REPAIR from the last known-good state, if we have one.
    prev_p = LOOP / "state.prev.json"
    print("STATE VIOLATION(S):", *(f"\n  - {x}" for x in v), sep="")
    if prev_p.exists():
        prev = json.loads(prev_p.read_text())
        if not violations(prev):
            repaired = dict(prev)
            for k in ("iter", "phase"):
                if k in s and not violations({**prev, k: s[k]}): repaired[k] = s[k]
            p.write_text(json.dumps(repaired, indent=2))
            print(f"REPAIRED: restored last valid state (iter={repaired['iter']}). "
                  "Violations above are fed back as DATA for the next round.")
            return 1
    print("HALT: unrepairable state, no valid predecessor. SAFE_STATE=stopped")
    (LOOP / "HALT").write_text("unrepairable state\n")
    return 2

if __name__ == "__main__":
    sys.exit(main())
