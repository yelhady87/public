#!/usr/bin/env bash
# Get an Incorta OAuth access token and print it.
#
#   JWT=$(./get_oauth_token.sh)            # refresh if possible, else sign in in the browser
#   JWT=$(./get_oauth_token.sh --login)    # always sign in in the browser
#
# The refresh token is kept in $REFRESH_FILE (mode 600) and used first on the next run.
# Refresh tokens rotate: each refresh returns a new one, which replaces the old in the file.
set -euo pipefail

CLUSTER=${CLUSTER:-https://cop-am-mcp.cloudstaging.incortalabs.com}
TENANT=${TENANT:-default}
AS="$CLUSTER/incorta/oauth/$TENANT"
PORT=8765
REDIRECT="http://127.0.0.1:$PORT/callback"
REFRESH_FILE=${REFRESH_FILE:-$HOME/.incorta_oauth_refresh_${TENANT}}

# The cluster's ready-made public client (redirects to 127.0.0.1:8765-8769/callback).
CLIENT_ID=$(curl -fsS "$AS/cli-client" | python3 -c 'import sys,json; print(json.load(sys.stdin)["client_id"])')

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
  if curl -sS -X POST "$AS/token" \
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

URL="$AS/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT&scope=openid%20profile%20email&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
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

curl -fsS -X POST "$AS/token" \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER" | take_tokens || {
  echo "The token endpoint returned no access token." >&2
  exit 1
}
[ -s "$REFRESH_FILE" ] && echo "Refresh token saved to $REFRESH_FILE." >&2 || true
