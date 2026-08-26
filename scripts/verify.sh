#!/usr/bin/env bash
# ============================================================================
# scripts/verify.sh — the loop's ONLY authority on "done".
#
# LSC-5 (external leverage): every signal below comes from a real tool —
#   compiler, test runner, coverage profile, grep — never a model's opinion.
# LSC-2 (stop signal): this script, and only this script, writes .loop/DONE.
# LSC-10 (drift): the acceptance bar is re-derived from spec.md §13 here, so
#   it cannot quietly move between rounds.
#
# Exit 0 == the build is complete. Any other exit == not done, and the failure
# list on stdout is the diagnostic feedback for the next round.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
source .loop/config.env

# Run through the toolchain mise.toml pins, so the result does not depend on
# whichever `go` happens to be first on the caller's PATH. Re-exec once.
export PATH="$HOME/.local/bin:$PATH"
if [ -z "${ALBAUTH_VERIFY_PINNED:-}" ] && [ -f mise.toml ] && command -v mise >/dev/null 2>&1; then
  export ALBAUTH_VERIFY_PINNED=1
  exec mise exec -- "$0" "$@"
fi

FAILURES=()
fail() { FAILURES+=("$1"); printf '  ✗ %s\n' "$1"; }
pass() { printf '  ✓ %s\n' "$1"; }
section() { printf '\n[%s]\n' "$1"; }

rm -f .loop/DONE

# ---------------------------------------------------------------- 1. format
section "toolchain"
if command -v mise >/dev/null 2>&1; then
  pass "mise present ($(mise --version 2>/dev/null | head -1))"
  [ -f mise.toml ] && pass "mise.toml pins the toolchain" || fail "mise.toml missing (toolchain is unpinned)"
else
  echo "  ~ mise not installed; using the ambient go toolchain"
fi
if ! command -v go >/dev/null; then fail "go toolchain not found"; fi
GOVER=$(go env GOVERSION 2>/dev/null)
GOREQ=$(awk '/^go /{print $2; exit}' go.mod 2>/dev/null)
case "$GOVER" in go*) pass "go toolchain $GOVER (go.mod requires $GOREQ)";; *) fail "cannot determine go version";; esac

section "gofmt"
UNFMT=$(gofmt -l . 2>/dev/null | grep -v '^$' || true)
if [ -n "$UNFMT" ]; then fail "gofmt: unformatted files: $(echo "$UNFMT" | tr '\n' ' ')"; else pass "gofmt clean"; fi

# ------------------------------------------------------------------- 2. vet
section "dependencies"
# Warm the module cache first. Otherwise the download progress `go` writes to
# stderr looks like a vet finding to the check below.
if DL=$(go mod download all 2>&1); then
  pass "modules present"
else
  fail "go mod download: $(printf '%s' "$DL" | head -5 | tr '\n' '|')"
fi

section "go vet"
# Drop progress chatter; only real diagnostics should count as a failure.
VET=$(go vet ./... 2>&1 | grep -vE '^go: (downloading|extracting|finding)' || true)
if [ -n "$VET" ]; then fail "go vet: $(echo "$VET" | head -20 | tr '\n' '|')"; else pass "go vet clean"; fi

# ------------------------------------------- 3. static cross-compile (§13.1)
section "cross-compile (CGO_ENABLED=0, spec §13.1)"
for T in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  GOOS=${T%/*}; GOARCH=${T#*/}
  OUT=$(CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o /dev/null ./cmd/albauth 2>&1) \
    && pass "build $T" || fail "build $T: $(echo "$OUT" | head -5 | tr '\n' '|')"
done

# ------------------------------------------------------- 4. unit tests + cover
section "unit tests + coverage"
TESTOUT=$(go test -covermode=atomic -coverprofile=.loop/cover.out ./... 2>&1)
TESTRC=$?
if [ $TESTRC -ne 0 ]; then
  echo "$TESTOUT" | grep -E '^(---|\s+---|FAIL|ok|\s+.*_test\.go:)' | head -60
  fail "go test ./... failed (rc=$TESTRC)"
else
  pass "go test ./... passed"
fi

if [ -f .loop/cover.out ]; then
  # per-package coverage, honestly computed from the profile
  go tool cover -func=.loop/cover.out > .loop/cover.txt 2>/dev/null || true
  PKGS=$(go list ./... 2>/dev/null)
  for P in $PKGS; do
    case " $COVERAGE_ALLOWLIST " in *" $P "*) pass "coverage $P: EXEMPT (allowlisted)"; continue;; esac
    PCT=$(echo "$TESTOUT" | grep -E "coverage:.*of statements" | grep -F "$P" | grep -oE '[0-9.]+%' | head -1 | tr -d '%')
    if [ -z "$PCT" ]; then
      # package with no statements is vacuously covered; anything else is a gap
      NSTMT=$(grep -c "^${P}/" .loop/cover.txt 2>/dev/null || echo 0)
      if [ "$NSTMT" = "0" ]; then pass "coverage $P: no statements"; else fail "coverage $P: NO TESTS"; fi
      continue
    fi
    if awk -v a="$PCT" -v b="$COVERAGE_MIN" 'BEGIN{exit !(a+0 >= b+0)}'; then
      pass "coverage $P: ${PCT}%"
    else
      UNCOV=$(awk -v p="$P/" '$0 ~ "^"p && $NF!="100.0%"{print $1" "$2" "$NF}' .loop/cover.txt | head -8 | tr '\n' '|')
      fail "coverage $P: ${PCT}% < ${COVERAGE_MIN}% — uncovered: $UNCOV"
    fi
  done
fi

# ----------------------------------------------------------------- 5. e2e
section "e2e suite (-tags e2e)"
E2E=$(go test -tags e2e -count=1 -v ./test/e2e/... 2>&1); E2ERC=$?
if [ $E2ERC -ne 0 ]; then
  echo "$E2E" | grep -E '^(---|\s+---|FAIL|\s+.*_test\.go:)' | head -40
  fail "e2e suite failed (rc=$E2ERC)"
else
  E2ECASES=$(printf '%s\n' "$E2E" | grep -c '^--- PASS' || true)
  pass "e2e suite passed (${E2ECASES:-0} cases)"
fi

# ------------------------------------------- 6. stdout purity (spec §13.7)
section "stdout purity (spec §13.7)"
if go test -tags e2e -run 'TestStdoutIsPureJSONRPC' -count=1 ./test/e2e/... >/dev/null 2>&1; then
  pass "stdout carries only JSON-RPC"
else
  fail "stdout purity test missing or failing (spec §13.7)"
fi

# ------------------------------------------------ 7. docs (user-facing bar)
section "documentation"
for DOC in README.md docs/getting-started.md docs/configuration.md docs/troubleshooting.md docs/smoke-test.md docs/compatibility.md; do
  [ -s "$DOC" ] && pass "$DOC present" || fail "missing/empty $DOC"
done
if [ -f README.md ]; then
  for NEEDLE in "Quick start" "config.toml" "http_request" "auth import" "Coverage"; do
    grep -qi -- "$NEEDLE" README.md && pass "README covers '$NEEDLE'" || fail "README missing section on '$NEEDLE'"
  done
fi
[ -s config.example.toml ] && pass "config.example.toml present" || fail "missing config.example.toml"

# The installer and the agent skill are user-facing surface; a rename that
# misses them is a broken install command or a skill pointing at nothing.
if [ -s install.sh ]; then
  sh -n install.sh 2>/dev/null && pass "install.sh present and parses" || fail "install.sh has a syntax error"
else
  fail "missing install.sh"
fi
if [ -s skill/albauth/SKILL.md ]; then
  head -1 skill/albauth/SKILL.md | grep -q '^---$' \
    && pass "agent skill present with frontmatter" \
    || fail "skill/albauth/SKILL.md is missing its frontmatter"
  # A skill that does not mention a response field or a tool cannot teach it,
  # and a stale skill is worse than none: it describes a tool that no longer
  # behaves that way.
  for TOOL in http_request auth_login auth_status auth_logout list_domains; do
    grep -q "$TOOL" skill/albauth/SKILL.md \
      || fail "the agent skill never mentions the $TOOL tool"
  done
  for FIELD in body_base64 relogin_performed truncated; do
    grep -q "$FIELD" skill/albauth/SKILL.md \
      || fail "the agent skill never mentions the $FIELD response field"
  done
  pass "agent skill covers every tool and response field"
else
  fail "missing skill/albauth/SKILL.md"
fi
for IMG in docs/img/demo.gif docs/img/login.png; do
  if [ -s "$IMG" ]; then
    grep -q "$IMG" README.md && pass "$IMG present and referenced" \
      || fail "$IMG exists but README does not reference it"
  else
    fail "missing $IMG (regenerate: see demo/README.md)"
  fi
done
for WF in .github/workflows/ci.yml .github/workflows/release.yml scripts/build-release.sh; do
  [ -s "$WF" ] && pass "$WF present" || fail "missing $WF"
done

# ----------------------------- 8. genericity: no organisation-specific refs
section "genericity (no org-specific references)"
# Anything that ties this tool to one company/vendor. example.com/example.org are
# RFC 2606 reserved and therefore allowed; so is the word "OIDC"/"ALB" (protocol/AWS
# service names the tool literally implements).
ORG_PAT='(?i)\b(acme[-. ]?corp|mycompany|internal\.corp|\.corp\.|\.intranet\b|okta\.com|onelogin|pingidentity|jumpcloud|@[a-z0-9-]+\.(?!example\.)(com|io|net)/(?!albauth))'
HITS=$(grep -rPn "$ORG_PAT" --include='*.go' --include='*.md' --include='*.toml' --include='*.yml' --include='*.yaml' \
        --exclude-dir=.git --exclude-dir=.loop --exclude=spec.md . 2>/dev/null | head -20 || true)
if [ -n "$HITS" ]; then fail "org-specific reference(s): $(echo "$HITS" | tr '\n' '|')"; else pass "no org-specific references"; fi
MODLINE=$(head -1 go.mod 2>/dev/null || echo "")
case "$MODLINE" in
  "module albauth") pass "module path is vendor-neutral";;
  "") fail "go.mod missing";;
  *) fail "go.mod module path is not vendor-neutral: $MODLINE";;
esac

# ------------------------------------------------------------- 9. verdict
section "verdict"
if [ ${#FAILURES[@]} -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  touch .loop/DONE          # <-- the ONLY writer of the stop signal (LSC-2)
  printf '%s\n' "" > .loop/failures.txt
  exit 0
fi
printf '%d CHECK(S) FAILED:\n' "${#FAILURES[@]}"
printf '%s\n' "${FAILURES[@]}" | tee .loop/failures.txt
exit 1
