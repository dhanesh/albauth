# Spec: albauth design-review fixes and domain discovery

## Problem
albauth judges an expired session from responses alone, and several of its rules fire on ordinary application answers. An agent calling an API behind a login proxy gets `auth_loop` and a stray browser window instead of the app's real 404, 500, 502, same-host redirect or presigned-download link; a write that met an application error page is sent twice; an application's own 401 behind oauth2-proxy opens a browser. Sessions over about 3 KB cannot be stored in the macOS keychain, refreshed proxy cookies are dropped, and the browser login can capture a CSRF cookie as the session. Non-technical users also cannot add a protected domain without the CLI. The design review of 2026-10-10 (`~/knowledge/albauth/explainer.md`, pinned at 02287ab) verified most of these at runtime.

## Users
- An AI agent (Claude Code, Claude Desktop) calling internal APIs through albauth's MCP tools, which needs the application's real answer and must never cause a duplicate write.
- A non-technical user who installs albauth and asks the agent to reach an API without knowing what a load balancer, proxy or cookie is.
- The maintainer, who needs every behaviour proven against the real binary and real applications before calling it done.

## Goals
- Every application response that is not the login proxy's own "no session" answer reaches the caller unchanged, with no browser login.
- No request reaches the application twice because of albauth.
- A session, once obtained, can be stored on macOS and stays current when the proxy refreshes it.
- A user can go from "call this URL" to a working read-only domain without leaving the chat.

## Non-goals
- Locking the session file across processes (two `serve` processes writing one `sessions.json`).
- Changing CI configuration under `.github/`.
- Removing the client's default `Accept: application/json` header.
- Letting the agent grant write methods to a domain; widening `allow_methods` stays a CLI or config edit by the user.
- Releasing, tagging or merging; a human merges the pull request.

## Constraints
- B1 [goal]: an application's own response reaches the caller unchanged unless it is the proxy's "no session" answer.
- B2 [invariant]: every fix works for both the ALB style and the oauth2-proxy style; nothing may assume an AWS load balancer.
- B3 [invariant]: a session the user logged in for must be storable and usable on macOS whatever its size up to 16 KB.
- T1 [invariant]: stdout carries JSON-RPC only; every log goes to stderr.
- T2 [invariant]: the HTTP client keeps sending `Accept: application/json` by default (`TestDoDefaultsAcceptToJSON` stays) and keeps not following redirects.
- T3 [invariant]: a request with a method other than GET, HEAD or OPTIONS is resent only when the first attempt met a redirect to the identity provider.
- T4 [invariant]: `./scripts/verify.sh` passes at every merged commit, which includes 100% statement coverage per package outside the allowlist.
- T5 [invariant]: no new Go module dependency is added (`go.mod` require list unchanged).
- S1 [invariant]: no session cookie value appears on stdout, on stderr or in any tool result.
- S2 [invariant]: the `add_domain` tool can only create a domain whose `allow_methods` is a subset of GET, HEAD and OPTIONS.
- S3 [invariant]: the discovery probe of an unconfigured host sends one GET with no cookies and no configured headers, and follows no redirect.
- U1 [invariant]: each user-visible change updates `docs/`, `skill/albauth/SKILL.md` and `spec.md` in the same task.
- U2 [goal]: a non-technical user adds a protected domain from the chat in at most 2 tool calls after saying yes.
- O1 [invariant]: `./test/tools/sweep.sh` passes at the head of the run branch, through Colima.
- O2 [boundary]: at most one task is in flight at a time, because the tasks share `detect.go`, `do.go`, the docs and the sweep's fixed ports 8000-8010.
- O3 [invariant]: a misconfigured or unreachable `session_check_path` must fail toward re-login, never toward reusing a dead session.

## Tensions
- TN1 [trade_off]: passing application HTML through (B1) against still catching a proxy's HTML sign-in page (B2) (between: B1, B2; status: resolved; strategy: Partition; decision: D1)
- TN2 [trade_off]: never sending a write twice (T3) against transparent re-authentication for writes (B1) (between: T3, B1; status: resolved; strategy: Partition; decision: D1)
- TN3 [hidden_dependency]: the fix for HTML misjudging (B1) depends on the default JSON Accept header that oauth2-proxy and the probe rely on (T2) (between: B1, T2; status: resolved; strategy: Prioritize)
- TN4 [trade_off]: adding a domain from chat (U2) against failing closed on writes (S2) (between: U2, S2; status: resolved; strategy: Partition; decision: D4)
- TN5 [resource_tension]: one sweep stack on fixed ports (O1) against running tasks in parallel (O2) (between: O1, O2; status: resolved; strategy: Prioritize)
- TN6 [trade_off]: returning the app's 401 behind oauth2-proxy (B1) against never reusing a dead session (O3) (between: B1, O3; status: resolved; strategy: Transform; decision: D3)

## Required truths
- RT1 [SPECIFICATION_READY]: albauth returns application responses unaltered and logs in again only on the proxy's own answers (parent: OUTCOME; maps_to: B1, B2, T2, O3; reqs: R1, R2, R3, R4, R5, R8, R9, R10; confidence: 0.8; check: {python} .claude/skills/verify-albauth/scripts/prove.py html-errors exits 0)
- RT2 [SPECIFICATION_READY]: no request reaches the application twice because of albauth (parent: OUTCOME; maps_to: T3; reqs: R6, R7; confidence: 0.85; check: prove.py write-not-resent shows POST hit count 1)
- RT3 [SPECIFICATION_READY]: a session stays stored and current on macOS (parent: OUTCOME; maps_to: B3; reqs: R11, R12; confidence: 0.75; check: go test ./internal/session -run TestRealKeyringRefusesOversizeBeforeWriting passes on darwin)
- RT4 [SPECIFICATION_READY]: the browser login keeps only a real, fresh proxy session (parent: OUTCOME; maps_to: B2; reqs: R13, R14, R15; confidence: 0.7; check: prove.py signin-page and force exit 0)
- RT5 [SPECIFICATION_READY]: session values never leak, for every cookie family (parent: OUTCOME; maps_to: S1, T1; reqs: R16; confidence: 0.85; check: go test ./internal/logx -run TestRedactTextUsesConfiguredPrefixes passes)
- RT6 [SPECIFICATION_READY]: a non-technical user can add a protected domain from chat, read-only (parent: OUTCOME; maps_to: U2, S2, S3; reqs: R17, R18, R19; confidence: 0.7; check: prove.py discovery exits 0)
- RT7 [SPECIFICATION_READY]: the real-application sweep can assert, and does assert, the negative response shapes (parent: OUTCOME; maps_to: O1, B2; reqs: R20; confidence: 0.75; check: ./test/tools/sweep.sh exits 0 with the new cases listed)
- RT8 [SPECIFICATION_READY]: every merged commit is green under verify.sh with docs in step (parent: OUTCOME; maps_to: T4, T5, U1, T1; reqs: R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15, R16, R17, R18, R19, R20; confidence: 0.85; check: bash scripts/verify.sh exits 0)
- RT9 [SPECIFICATION_READY]: the plan runs serially so tasks never collide on files or ports (parent: RT8; maps_to: O2; reqs: R20; confidence: 0.9; check: spec_to_tasks.py --waves shows one task per wave)

## Requirements
- R1: An application response with a non-2xx status other than 401 and 403 and a `text/html` content type must be returned to the caller as a result with `relogin_performed: false` and no retry. [where: internal/auth/detect.go] [feature: response-passthrough] [proof: http_request to the fixture's /html/404, /html/500, /html/502 and /html/503 returns those statuses and the fixture records one hit each and no login] [parallel-safe]
- R2: A 401 or 403 `text/html` response to a request whose Accept includes application/json must still trigger exactly one re-login and one retry. [where: internal/auth/detect.go] [feature: response-passthrough, session-relogin] [proof: http_request to /html/403 runs one browser login, the fixture records two hits and the result is auth_loop] [after: R1]
- R3: A same-host redirect with status 301, 302, 303, 307 or 308 must be returned to the caller unchanged, with or without a response body. [where: internal/auth/detect.go] [feature: response-passthrough] [proof: http_request to /redirect/same/<code> with and without a body returns that status and Location /json, and no login runs] [after: R2]
- R4: A cross-host redirect whose Location query lacks either `client_id` or `response_type` must be returned to the caller unchanged. [where: internal/auth/detect.go] [feature: response-passthrough] [proof: http_request to /redirect/cross/302, 303 and 307 returns the presigned URL in Location and the fixture records one hit each] [after: R3]
- R5: A cross-host 302 or 303 whose Location query carries both `client_id` and `response_type` must trigger a re-login even when its host is not in `idp_hostnames`. [where: internal/auth/detect.go] [feature: response-passthrough, session-relogin] [proof: after the fixture revokes the session, GET /json on a domain with empty idp_hostnames returns 200 with relogin_performed true] [after: R4]
- R6: A request with a method other than GET, HEAD or OPTIONS that is judged unauthenticated by any rule other than a redirect to the identity provider must reach the application at most once and must end in a `resend_required` error after the re-login. [where: internal/httpx/do.go] [feature: session-relogin] [proof: POST to /html/403 reaches the fixture once and the tool answers resend_required] [after: R5]
- R7: A request with a method other than GET, HEAD or OPTIONS whose first attempt met a redirect to the identity provider must be resent exactly once after the re-login. [where: internal/httpx/do.go] [feature: session-relogin] [proof: with the session revoked, POST /html/500 returns the app's 500 with relogin_performed true and one fixture hit] [after: R6]
- R8: When a domain sets `session_check_path` and a 401 arrives, albauth must call that path with only the session cookies and must return the 401 as a result without a re-login when the check answers 2xx. [where: internal/httpx/do.go] [feature: session-relogin] [proof: on the oauth2 fixture /app401 returns the app's 401 body with relogin_performed false and the stored session unchanged] [after: R7]
- R9: When a domain sets `session_check_path` and the check answers anything but 2xx or fails to answer, a 401 must trigger the re-login. [where: internal/httpx/do.go] [feature: session-relogin] [proof: with the oauth2 session revoked, GET /json returns 200 with relogin_performed true] [after: R8]
- R10: `albauth config add-domain` must write `session_check_path = "/oauth2/auth"` when its probe detects an oauth2-proxy login at /oauth2/start or /oauth2/sign_in. [where: internal/cli/addomain.go] [feature: domain-setup] [proof: add-domain against the oauth2 fixture writes a block with cookie_name_prefix _oauth2_proxy, treat_401_as_expired true and session_check_path /oauth2/auth] [after: R9]
- R11: When the OS keychain refuses a session because it is too big, albauth must store that domain's session in the 0600 file store, warn once on stderr, and read it back on the next request. [where: internal/session] [feature: session-storage] [proof: the real go-keyring refuses a 5.6 KB session before writing and the store then serves it from the 0600 file; a two-chunk import works end to end] [after: R10]
- R12: A response that sets a cookie in the domain's session cookie family must replace the stored session cookie of that name. [where: internal/httpx/jar.go] [feature: session-refresh] [proof: after http_request to /rotate the stored cookie's sha256 changes and the proxy accepts the new value] [after: R11]
- R13: The browser login must not finish while the settled page's HTTP status is 400 or higher. [where: internal/browser] [feature: browser-login] [proof: a login that meets the oauth2 fixture's 403 sign-in page waits, follows on to the IdP and stores the real session] [after: R12]
- R14: The browser login must capture only cookies whose name equals `cookie_name_prefix` or equals it followed by `-<digits>` or `_<digits>`. [where: internal/browser] [feature: browser-login] [proof: after the sign-in page login the only stored cookie name is _oauth2_proxy, never _oauth2_proxy_csrf] [after: R13]
- R15: `auth_login` with `force: true` must delete the domain's session cookies from the browser profile before navigating, so that it stores a session value different from the one held before. [where: internal/auth/login.go] [feature: browser-login] [proof: two forced auth_login calls in a row store two different session values, both accepted by the proxy] [after: R14]
- R16: Free-text redaction must scrub the value of every cookie whose name starts with any configured domain's `cookie_name_prefix`. [where: internal/logx] [feature: log-redaction] [proof: a logged line carrying _oauth2_proxy=<value> renders as <redacted:len=N>, and no stored session value appears on the real binary's stderr] [after: R15]
- R17: An `http_request` to an absolute URL whose host no domain matches must probe that host once and must return `unknown_domain` with a `suggestion` object naming the base URL and what the probe found when the probe sees a login wall. [where: internal/mcpserver] [feature: domain-discovery] [proof: http_request to the unconfigured fixture host returns unknown_domain with a suggestion naming its base URL] [after: R16]
- R18: A new `add_domain` MCP tool must add the domain to the config file and must make it usable in the same server process without a restart. [where: internal/mcpserver] [feature: domain-discovery] [proof: after add_domain, list_domains in the same server lists it read-only and an http_request to it returns 200 after login] [after: R17]
- R19: The `add_domain` tool must refuse any `allow_methods` entry other than GET, HEAD or OPTIONS. [where: internal/mcpserver] [feature: domain-discovery] [proof: add_domain with allow_methods POST is answered with an error and the config file is unchanged] [after: R18]
- R20: The tool sweep must take an expected outcome per check and must pass with checks for an HTML 404, a same-host redirect with a body, a cross-host presigned redirect and an application's own 401 behind oauth2-proxy. [where: test/tools] [feature: response-passthrough] [proof: ./test/tools/sweep.sh on Colima prints each new case with a tick and exits 0] [after: R19]

## Acceptance criteria
- R1: the unit test TestDoReturnsApplicationHTMLErrors (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestDoReturnsApplicationHTMLErrors -count=1]
- R1: the html-errors scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py html-errors]
- R1: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R2: the unit test TestSignInPageStillTriggersRelogin (to be written in internal/auth) passes. [cmd: go test ./internal/auth -run TestSignInPageStillTriggersRelogin -count=1]
- R2: the html-signin scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py html-signin]
- R2: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R3: the unit test TestSameHostRedirectsAreReturned (to be written in internal/auth) passes. [cmd: go test ./internal/auth -run TestSameHostRedirectsAreReturned -count=1]
- R3: the redirects-same scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py redirects-same]
- R3: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R4: the unit test TestCrossHostRedirectWithoutAuthRequestIsReturned (to be written in internal/auth) passes. [cmd: go test ./internal/auth -run TestCrossHostRedirectWithoutAuthRequestIsReturned -count=1]
- R4: the redirect-cross scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py redirect-cross]
- R4: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R5: the unit test TestAuthorizationRequestRedirectTriggersRelogin (to be written in internal/auth) passes. [cmd: go test ./internal/auth -run TestAuthorizationRequestRedirectTriggersRelogin -count=1]
- R5: the relogin-unlisted-idp scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py relogin-unlisted-idp]
- R5: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R6: the unit test TestUnsafeMethodIsNotResentWithoutIdPRedirect (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestUnsafeMethodIsNotResentWithoutIdPRedirect -count=1]
- R6: the write-not-resent scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py write-not-resent]
- R6: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R7: the unit test TestUnsafeMethodIsResentAfterIdPRedirect (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestUnsafeMethodIsResentAfterIdPRedirect -count=1]
- R7: the write-resent-after-idp scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py write-resent-after-idp]
- R7: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R8: the unit test TestSessionCheckReturnsApplicationRefusal (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestSessionCheckReturnsApplicationRefusal -count=1]
- R8: the app-refusal scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py app-refusal]
- R8: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R9: the unit test TestFailedSessionCheckTriggersRelogin (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestFailedSessionCheckTriggersRelogin -count=1]
- R9: the o2-expired scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py o2-expired]
- R9: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R10: the unit test TestAddDomainSetsSessionCheckPathForOAuth2Proxy (to be written in internal/cli) passes. [cmd: go test ./internal/cli -run TestAddDomainSetsSessionCheckPathForOAuth2Proxy -count=1]
- R10: the domain-setup scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py domain-setup]
- R10: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R11: the unit test TestKeyringTooBigFallsBackToFile (to be written in internal/session) passes. [cmd: go test ./internal/session -run TestKeyringTooBigFallsBackToFile -count=1]
- R11: the darwin-only test TestRealKeyringRefusesOversizeBeforeWriting (to be written in internal/session, calling the real go-keyring with an oversize value so nothing is written) passes. [cmd: go test ./internal/session -run TestRealKeyringRefusesOversizeBeforeWriting -count=1]
- R11: the storage scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py storage]
- R11: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R12: the unit test TestRefreshedSessionCookieIsStored (to be written in internal/httpx) passes. [cmd: go test ./internal/httpx -run TestRefreshedSessionCookieIsStored -count=1]
- R12: the rotate scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py rotate]
- R12: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R13: the unit test TestSettleRequiresSuccessStatus (to be written in internal/browser) passes. [cmd: go test ./internal/browser -run TestSettleRequiresSuccessStatus -count=1]
- R13: the signin-page scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py signin-page]
- R13: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R14: the unit test TestSessionCookieNamesMatchExactlyOrAsChunks (to be written in internal/browser) passes. [cmd: go test ./internal/browser -run TestSessionCookieNamesMatchExactlyOrAsChunks -count=1]
- R14: the signin-page scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py signin-page]
- R14: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R15: the unit test TestForceLoginClearsBrowserSession (to be written in internal/auth) passes. [cmd: go test ./internal/auth -run TestForceLoginClearsBrowserSession -count=1]
- R15: the force scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py force]
- R15: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R16: the unit test TestRedactTextUsesConfiguredPrefixes (to be written in internal/logx) passes. [cmd: go test ./internal/logx -run TestRedactTextUsesConfiguredPrefixes -count=1]
- R16: the redaction scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py redaction]
- R16: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R17: the unit test TestUnknownDomainSuggestsLoginWall (to be written in internal/mcpserver) passes. [cmd: go test ./internal/mcpserver -run TestUnknownDomainSuggestsLoginWall -count=1]
- R17: the discovery scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py discovery]
- R17: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R18: the unit test TestAddDomainToolReloadsConfig (to be written in internal/mcpserver) passes. [cmd: go test ./internal/mcpserver -run TestAddDomainToolReloadsConfig -count=1]
- R18: the discovery scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py discovery]
- R18: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R19: the unit test TestAddDomainToolRefusesWriteMethods (to be written in internal/mcpserver) passes. [cmd: go test ./internal/mcpserver -run TestAddDomainToolRefusesWriteMethods -count=1]
- R19: the discovery scenario exits 0. [cmd: {python} .claude/skills/verify-albauth/scripts/prove.py discovery]
- R19: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R20: the acceptance gate passes. [cmd: bash scripts/verify.sh]
- R20: the tool sweep passes on Colima with the new expected-outcome cases. [cmd: bash test/tools/sweep.sh]
- R20: the sweep stack is torn down afterwards. [cmd: bash test/tools/sweep.sh --down]

## Verification
Verify skill: `.claude/skills/verify-albauth`

## Solution options
- OPT-A: one task per requirement in a single serial chain, each proven by a named unit test, a prove.py runtime scenario and verify.sh, with the sweep last (complexity: Medium; reversibility: TWO_WAY; satisfies: RT1, RT2, RT3, RT4, RT5, RT6, RT7, RT8, RT9)
- OPT-B: parallel waves grouped by package (detection, storage, browser, discovery) (complexity: Medium; reversibility: TWO_WAY; satisfies: RT1, RT2, RT3, RT4, RT5, RT6, RT7, RT8)
- OPT-C: one large task covering every requirement (complexity: Low; reversibility: REVERSIBLE_WITH_COST; satisfies: RT1, RT8)

Recommended: OPT-A — the only option that satisfies RT9 (no file or port collisions) while proving each fix on its own commit; OPT-B risks merge conflicts in shared docs and the sweep's fixed ports, and OPT-C cannot show which change proved which requirement.

## Decisions
- D1: How should rule 4 (HTML misjudged as login) and the retry of writes be fixed? -> Narrow rule 4 to 401/403 HTML; resend a non-safe method only when the first attempt met a redirect to the identity provider, else re-login and return resend_required (source: user, AskUserQuestion 2026-10-10; Jev scores 2.68 and 3.12 were below 0.6 confidence)
- D2: Which items beyond F1-F4, F6, F7, F8 are in scope? -> F5 cookie write-back, redaction by configured prefix, force really forces, the rule-3 401 tension, and domain discovery (source: user, AskUserQuestion 2026-10-10)
- D3: How does albauth tell an expired session from the app's own 401? -> A per-domain session_check_path called with only the session cookies; 2xx means the app refused, anything else re-logs in; the probe sets /oauth2/auth for oauth2-proxy (source: user, AskUserQuestion 2026-10-10)
- D4: What may albauth do with an unconfigured host? -> One cookie-less GET probe, a suggestion in the unknown_domain error, and an add_domain MCP tool the agent calls only after the user says yes in chat, GET/HEAD/OPTIONS only, reloaded in place (source: user, AskUserQuestion 2026-10-10)
- D5: How are F3, F4 and F8 fixed? -> F3: rule 2 fires only on an OAuth authorization request (client_id and response_type, RFC 6749 4.1.1); F4: status < 400 check plus exact-or-chunk name match; F8: per-domain fallback to the 0600 file with a one-time warning (source: Jev Score, confidence 0.68, 0.85 and 0.71)
- D6: May the work add dependencies? -> No new Go module dependencies (source: stated default, not overridden by the user)
- D7: Which actions does the grant cover? -> read_only and local_reversible auto; push_branch and open_pr by grant on factory/*; merge, deploy, spend, external_message and delete always ask; expires 24 hours after it is written (source: user, AskUserQuestion 2026-10-10)
- D8: What budget applies? -> wall clock 720 minutes, 2 repairs per task, 1 task in parallel (serial chain), dispatches derived by the conductor (source: stated defaults, wall clock raised from 480 to fit 20 serial tasks, shown in the grant summary)
- D9: May the run consult a System One model? -> Yes, Jev, for low-stakes ranking, classification and yes/no calls, sending code, commands and metadata only, never secrets or session values (source: user instruction "use jev for system one decisions")
- D10: How are browser and keychain behaviours proven unattended? -> Browser: real Chrome against the verify-albauth fixture, whose IdP approves at once; keychain: the real go-keyring refusing an oversize value before any write, never a real keychain write (source: stated default, not overridden)
- D11: What does "landed" mean? -> Merged on the run branch with verify.sh and the sweep green at its head and evidence recorded; merging to main stays human (source: stated default, not overridden)

## Iterations
- I1: drafted from the 2026-10-10 review findings, the user's decision round, and Jev scores; serial chain chosen for RT9

## Open questions
