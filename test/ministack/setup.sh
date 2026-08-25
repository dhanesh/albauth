#!/usr/bin/env bash
# ============================================================================
# Provision a local ALB with an authenticate-oidc listener rule, backed by a
# Cognito user pool, inside a running MiniStack.
#
# This is the closest thing to a real AWS Application Load Balancer that runs
# on a laptop: a genuine redirect to an identity provider, a genuine HTML login
# form, a genuine back-channel code exchange, and a genuine chunked
# AWSELBAuthSessionCookie. It needs MiniStack built from the branch that adds
# the authenticate-oidc action — upstream MiniStack parses the rule but drops
# the config, so an ALB built on it forwards every request unauthenticated.
#
# Writes a fixture JSON describing what it built, for the Go tests to read.
#
#   ./setup.sh [fixture-path]        default: ./fixture.json
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"
FIXTURE="${1:-$PWD/fixture.json}"
ENDPOINT="${MINISTACK_ENDPOINT:-http://localhost:4566}"
CONTAINER="${MINISTACK_CONTAINER:-ministack}"
LB_NAME="albmcp"
ALB_HOST="${LB_NAME}.alb.localhost:4566"

A() { docker exec "$CONTAINER" awslocal "$@"; }
die() { echo "setup.sh: $1" >&2; exit 1; }

curl -sf --max-time 5 "$ENDPOINT/_ministack/health" >/dev/null \
  || die "MiniStack is not answering at $ENDPOINT — start it first (see README)"
docker exec "$CONTAINER" sh -c 'aws configure set cli_follow_urlparam false' 2>/dev/null

echo "provisioning Cognito…"
POOL=$(A cognito-idp create-user-pool --pool-name albmcp --query 'UserPool.Id' --output text | tail -1)
[ -n "$POOL" ] || die "could not create the user pool"
A cognito-idp create-user-pool-domain --domain "albmcp-$RANDOM" --user-pool-id "$POOL" >/dev/null

CLIENT=$(A cognito-idp create-user-pool-client --user-pool-id "$POOL" --client-name albmcp \
  --generate-secret --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile --allowed-o-auth-flows-user-pool-client \
  --callback-urls "http://${ALB_HOST}/oauth2/idpresponse" \
  --supported-identity-providers COGNITO \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --query 'UserPoolClient.ClientId' --output text | tail -1)
SECRET=$(A cognito-idp describe-user-pool-client --user-pool-id "$POOL" --client-id "$CLIENT" \
  --query 'UserPoolClient.ClientSecret' --output text | tail -1)

USERNAME="tester"
PASSWORD='Passw0rd!23'
A cognito-idp admin-create-user --user-pool-id "$POOL" --username "$USERNAME" \
  --user-attributes Name=email,Value=tester@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS >/dev/null
A cognito-idp admin-set-user-password --user-pool-id "$POOL" --username "$USERNAME" \
  --password "$PASSWORD" --permanent >/dev/null

echo "provisioning the target…"
docker exec "$CONTAINER" sh -c 'mkdir -p /tmp/albmcpfn && cat > /tmp/albmcpfn/index.py <<"PY"
import json
def handler(event, context):
    h = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "path": event.get("path"),
                "method": event.get("httpMethod"),
                "oidc_identity": h.get("x-amzn-oidc-identity"),
                "oidc_data_present": bool(h.get("x-amzn-oidc-data")),
                "oidc_accesstoken_present": bool(h.get("x-amzn-oidc-accesstoken")),
            })}
PY
cd /tmp/albmcpfn && python -c "import zipfile;z=zipfile.ZipFile(\"/tmp/albmcpfn.zip\",\"w\");z.write(\"index.py\");z.close()"'
A lambda create-function --function-name albmcp-target --runtime python3.12 \
  --role arn:aws:iam::000000000000:role/lambda --handler index.handler \
  --zip-file fileb:///tmp/albmcpfn.zip >/dev/null 2>&1

echo "provisioning the load balancer…"
LB=$(A elbv2 create-load-balancer --name "$LB_NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text | tail -1)
TG=$(A elbv2 create-target-group --name albmcp-tg --target-type lambda \
  --query 'TargetGroups[0].TargetGroupArn' --output text | tail -1)
A elbv2 register-targets --target-group-arn "$TG" \
  --targets Id=arn:aws:lambda:us-east-1:000000000000:function:albmcp-target >/dev/null

A elbv2 create-listener --load-balancer-arn "$LB" --protocol HTTP --port 80 \
  --default-actions "[
    {\"Type\":\"authenticate-oidc\",\"Order\":1,\"AuthenticateOidcConfig\":{
      \"Issuer\":\"https://cognito-idp.us-east-1.amazonaws.com/$POOL\",
      \"AuthorizationEndpoint\":\"$ENDPOINT/oauth2/authorize\",
      \"TokenEndpoint\":\"$ENDPOINT/oauth2/token\",
      \"UserInfoEndpoint\":\"$ENDPOINT/oauth2/userInfo\",
      \"ClientId\":\"$CLIENT\",\"ClientSecret\":\"$SECRET\",
      \"Scope\":\"openid email profile\",\"SessionTimeout\":3600,
      \"OnUnauthenticatedRequest\":\"authenticate\"}},
    {\"Type\":\"forward\",\"Order\":2,\"TargetGroupArn\":\"$TG\"}
  ]" >/dev/null || die "could not create the listener — is MiniStack patched with authenticate-oidc?"

STATUS=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${ALB_HOST}/v1/users")
[ "$STATUS" = "302" ] || die "expected an unauthenticated request to redirect, got $STATUS
  (upstream MiniStack answers 200 here because it drops AuthenticateOidcConfig)"

cat > "$FIXTURE" <<JSON
{
  "base_url": "http://${ALB_HOST}",
  "alb_host": "${ALB_HOST}",
  "idp_host": "$(echo "$ENDPOINT" | sed 's|https\{0,1\}://||')",
  "login_path": "/v1/users",
  "username": "${USERNAME}",
  "password": "${PASSWORD}",
  "user_pool_id": "${POOL}",
  "client_id": "${CLIENT}"
}
JSON
echo "ready: $FIXTURE"
echo "  ALB   http://${ALB_HOST}  (unauthenticated -> 302)"
echo "  login ${USERNAME} / ${PASSWORD}"
