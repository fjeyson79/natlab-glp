#!/usr/bin/env bash
# Zoe live-opener smoke test: search -> register -> open -> print command id.
# Requires: curl, jq.
#
# Usage:
#   ./scripts/zoe-viewer-smoketest.sh                  # defaults: localhost + natlab + query "TOUCAN"
#   BASE=https://portal.example.com WS=natlab Q="SOP" ./scripts/zoe-viewer-smoketest.sh

set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
WS="${WS:-natlab}"
Q="${Q:-TOUCAN}"
TOKEN="${TOKEN:-smoketest-$(date +%s)-$RANDOM}"

echo "base=$BASE  ws=$WS  q=$Q  token=$TOKEN"

echo "-> files/search"
FILE_ID=$(curl -fsS "$BASE/api/assistant/files/search?ws=$WS&q=$(printf %s "$Q" | jq -sRr @uri)&limit=1" \
          | jq -r '.best_match.file_id // empty')
if [ -z "$FILE_ID" ]; then
    echo "   no match for q='$Q' in ws='$WS' — aborting" >&2
    exit 1
fi
echo "   file_id=$FILE_ID"

echo "-> sessions/register"
CS_ID=$(curl -fsS -X POST "$BASE/api/assistant/sessions/register" \
        -H 'Content-Type: application/json' \
        -d "{\"ws\":\"$WS\",\"session_token\":\"$TOKEN\",\"mode\":\"viewer\"}" \
      | jq -r '.control_session_id // empty')
if [ -z "$CS_ID" ]; then
    echo "   register failed" >&2
    exit 1
fi
echo "   control_session_id=$CS_ID"

echo "-> viewer/open"
OPEN_RESP=$(curl -fsS -X POST "$BASE/api/assistant/viewer/open" \
            -H 'Content-Type: application/json' \
            -d "{\"ws\":\"$WS\",\"control_session_id\":\"$CS_ID\",\"file_id\":\"$FILE_ID\",\"mode\":\"viewer\"}")
echo "   $OPEN_RESP"

echo "-> viewer/debug (latest command)"
CMD_ID=$(curl -fsS "$BASE/api/assistant/viewer/debug?ws=$WS" \
         | jq -r '.commands[0].id // empty')
echo "   command_id=$CMD_ID"
