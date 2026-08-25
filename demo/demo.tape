# ---------------------------------------------------------------------------
# demo/demo.tape — the GIF in the README.
#
#   vhs demo/demo.tape
#
# Every command really runs. The load balancer is a local emulator with a real
# authenticate-oidc rule (see test/ministack/README.md), so the 302, the
# session and the response are all genuine — nothing here is staged.
# ---------------------------------------------------------------------------

Output docs/img/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1180
Set Height 620
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set WindowBar Colorful
Set BorderRadius 8

# Point at the demo environment without putting six exports in the recording.
Hide
Type "export XDG_CONFIG_HOME=/tmp/albauth-demo/config XDG_STATE_HOME=/tmp/albauth-demo/state PATH=/tmp/albauth-demo:$PATH"
Enter
Type "clear"
Enter
Sleep 1s
Show

Sleep 800ms
Type "# The API is behind a load balancer that demands an SSO login."
Enter
Sleep 700ms

Type "curl -si http://albauth.alb.localhost:4566/v1/users | head -2"
Enter
Sleep 2.5s

Type "# A client can't complete that flow. albauth already did, once, in a browser."
Enter
Sleep 700ms

Type "albauth auth status"
Enter
Sleep 2.8s

Type "# So the model just calls the API. Real MCP traffic over stdio:"
Enter
Sleep 700ms

Type `demo/mcp-call.sh http_request '{"url":"/v1/users","domain":"local-alb"}'`
Enter
Sleep 6s

Type "# 200, authenticated, no login prompt. The identity reached the target."
Enter
Sleep 3s
