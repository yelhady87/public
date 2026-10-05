#!/usr/bin/env bash
# Get an Incorta OAuth access token and print it.
#
#   JWT=$(./get_oauth_token.sh)            # refresh if possible, else sign in in the browser
#   JWT=$(./get_oauth_token.sh --login)    # always sign in in the browser
#
# The refresh token is kept in $REFRESH_FILE (mode 600) and used first on the next run.
# Refresh tokens rotate: each refresh returns a new one, which replaces the old in the file.
#
# The OAuth client is obtained once via OpenID Connect Dynamic Client Registration
# (RFC 7591) against the discovery document's registration_endpoint, and cached in
# $CLIENT_FILE (mode 600) so we don't register a new client on every run.
set -euo pipefail

CLUSTER=${CLUSTER:-https://cop-am-mcp.cloudstaging.incortalabs.com}
TENANT=${TENANT:-default}
AS="$CLUSTER/incorta/oauth/$TENANT"
PORT=8765
REDIRECT="http://127.0.0.1:$PORT/callback"
REFRESH_FILE=${REFRESH_FILE:-$HOME/.incorta_oauth_refresh_${TENANT}}
CLIENT_FILE=${CLIENT_FILE:-$HOME/.incorta_oauth_client_${TENANT}}
CLIENT_NAME=${CLIENT_NAME:-Incorta OAuth CLI ($(whoami)@$(hostname -s 2>/dev/null || hostname))}

# Discovery document: source of truth for the authorize/token/registration endpoints.
DISCOVERY=$(curl -fsS "$AS/.well-known/openid-configuration")
read -r AUTHORIZE_EP TOKEN_EP REGISTRATION_EP <<EOF
$(python3 -c '
import sys, json
doc = json.load(sys.stdin)
for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
    if key not in doc:
        sys.exit(f"discovery document missing {key}")
print(doc["authorization_endpoint"], doc["token_endpoint"], doc["registration_endpoint"])
' <<<"$DISCOVERY")
EOF

# Dynamically register a public, PKCE-only client (RFC 7591), caching the result so
# subsequent runs reuse the same client_id instead of registering a new one each time.
if [ -s "$CLIENT_FILE" ]; then
  CLIENT_ID=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["client_id"])' <"$CLIENT_FILE")
else
  REGISTRATION_BODY=$(REDIRECT="$REDIRECT" CLIENT_NAME="$CLIENT_NAME" python3 -c '
import json, os
print(json.dumps({
    "redirect_uris": [os.environ["REDIRECT"]],
    "client_name": os.environ["CLIENT_NAME"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "application_type": "native",
}))
')
  REGISTRATION=$(curl -fsS -X POST "$REGISTRATION_EP" \
    -H "Content-Type: application/json" \
    -d "$REGISTRATION_BODY")
  CLIENT_ID=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["client_id"])' <<<"$REGISTRATION")
  : > "$CLIENT_FILE"
  chmod 600 "$CLIENT_FILE"
  printf '%s' "$REGISTRATION" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps({"client_id": d["client_id"]}))' >"$CLIENT_FILE"
fi

# Print the access token from a /token reply and store its refresh token. Fails if the
# reply has no access token.
take_tokens() {
  python3 -c '
import sys, json, os
reply = json.load(sys.stdin)
if "access_token" not in reply:
    sys.exit(1)
refresh = reply.get("refresh_token")
if refresh:
    path = sys.argv[1]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(refresh)
print(reply["access_token"])
' "$REFRESH_FILE"
}

if [ "${1:-}" != "--login" ] && [ -s "$REFRESH_FILE" ]; then
  if curl -sS -X POST "$TOKEN_EP" \
      -d grant_type=refresh_token \
      --data-urlencode "refresh_token=$(cat "$REFRESH_FILE")" \
      -d "client_id=$CLIENT_ID" | take_tokens; then
    echo "Refreshed without the browser." >&2
    exit 0
  fi
  echo "Refresh token refused (used, expired or revoked); signing in again." >&2
fi

VERIFIER=$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n')
STATE=$(openssl rand -hex 8)

URL="$AUTHORIZE_EP?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT&scope=openid%20profile%20email&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
echo "Opening the browser to sign in. If it does not open, visit:" >&2
echo "  $URL" >&2
open "$URL" 2>/dev/null || true

# Wait for the redirect and take the code off it. The code is good for 60 s.
CODE=$(python3 - "$PORT" "$STATE" <<'EOF'
import sys, http.server, urllib.parse
port, state = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        ok = q.get("state", [""])[0] == state and "code" in q
        self.send_response(200); self.end_headers()
        self.wfile.write(b"Signed in. You can close this tab." if ok else b"No code in the redirect.")
        if ok:
            print(q["code"][0]); sys.stdout.flush()
            raise SystemExit
    def log_message(self, *a): pass
try:
    http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
except SystemExit:
    pass
EOF
)

curl -fsS -X POST "$TOKEN_EP" \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER" | take_tokens || {
  echo "The token endpoint returned no access token." >&2
  exit 1
}
[ -s "$REFRESH_FILE" ] && echo "Refresh token saved to $REFRESH_FILE." >&2 || true
