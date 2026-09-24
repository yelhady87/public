#!/usr/bin/env bash
# Ask the smart agent a question over the public API with an OAuth token, poll until it
# finishes, and dump the final response.
#
#   ./ask_smart_agent.sh                                  # default question
#   ./ask_smart_agent.sh "top 5 products by revenue"      # your own question
#   LOGIN=1 ./ask_smart_agent.sh "..."                    # sign in again, skip the refresh
#
# Needs get_oauth_token.sh beside it, curl, jq and uuidgen.
set -euo pipefail

CLUSTER=${CLUSTER:-https://cop-am-mcp.cloudstaging.incortalabs.com}
TENANT=${TENANT:-default}
QUESTION=${1:-total sales per city html report}
OUT=${OUT:-smart_agent_response.json}

B="$CLUSTER/incorta/api/v2/$TENANT/copilot/a2a/agent/smart-agent"
EXT='https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/task_metadata,https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/nexus_parts,https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/intermediate-output,https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/conversation_context'

HERE=$(cd "$(dirname "$0")" && pwd)
JWT=$(CLUSTER=$CLUSTER TENANT=$TENANT "$HERE/get_oauth_token.sh" ${LOGIN:+--login})
[ "$(printf %s "$JWT" | tr -cd . | wc -c | tr -d ' ')" = 2 ] || { echo "not a JWT: $JWT" >&2; exit 1; }

H=(-H "Authorization: Bearer $JWT" -H "X-A2A-Extensions: $EXT" -H 'Content-Type: application/json')

SEND=$(jq -n --arg q "$QUESTION" --arg id "$(uuidgen)" --arg now "$(date '+%Y-%m-%d %H:%M:%S')" '{
  jsonrpc: "2.0", method: "message/send", id: 1,
  params: {
    message: {
      messageId: $id, role: "user", kind: "message",
      parts: [{kind: "text", text: $q}],
      metadata: {conversation_context: {client: "dashboards_v2", current_date: $now,
        client_context: {enable_summary: true, verbosity: "detailed"}}}
    },
    configuration: {blocking: false}
  }
}')

echo "Asking: $QUESTION" >&2
SENT=$(curl -sS "$B" "${H[@]}" --data "$SEND")
TASK=$(jq -r '.result.id // empty' <<<"$SENT" 2>/dev/null || true)
[ -n "$TASK" ] || { echo "send failed:" >&2; echo "$SENT"; exit 1; }
echo "task: $TASK" >&2

POLL=$(jq -n --arg t "$TASK" '{jsonrpc: "2.0", method: "tasks/get", id: 2, params: {id: $t}}')
while :; do
  R=$(curl -sS "$B" "${H[@]}" --data "$POLL")
  S=$(jq -r '.result.status.state // empty' <<<"$R" 2>/dev/null || true)
  [ -n "$S" ] || { echo "poll failed:" >&2; break; }
  echo "$(date +%T) $S" >&2
  case $S in completed|failed|canceled|rejected|input-required|auth-required) break ;; esac
  sleep 5
done

printf '%s\n' "$R" > "$OUT"
echo "final response saved to $OUT" >&2
jq . "$OUT" 2>/dev/null || cat "$OUT"
