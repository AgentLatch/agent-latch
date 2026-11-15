#!/usr/bin/env bash
# Container test for the sealed audit store. Needs Docker running. Run from the repository root:
#   bash docs/audit-trail-dev/docker-test.sh
#
# What it proves, each as a PASS or FAIL line:
#   1. the store and the anchor sit in two Docker volumes, owned by user 10001, mode 0600
#   2. another user (uid 10002) with both volumes mounted read-write cannot read, write, chmod
#      or delete either file
#   3. the read-only audit tool, started the way an agent's app starts it (docker run -i), refuses
#      every write over a real MCP session, and the store is unchanged afterwards
#   4. someone who does get at the file (root, on a COPY of the store) can change it, and verify
#      reports TAMPERED while the original stays INTACT
#
# Settings (environment): IMAGE (default agent-latch-runtime:local), SKIP_BUILD=1 to reuse an
# image you already built. It creates and removes volumes named agentlatch-test-*; it never touches
# agentlatch-data or agentlatch-anchor.
set -u
IMG="${IMAGE:-agent-latch-runtime:local}"
DATA=agentlatch-test-data; ANCHOR=agentlatch-test-anchor; COPY=agentlatch-test-copy
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass + 1)); }
bad() { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      $2"; fail=$((fail + 1)); }
cleanup() { docker volume rm -f "$DATA" "$ANCHOR" "$COPY" >/dev/null 2>&1; }
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker not found"; exit 2; }
docker info >/dev/null 2>&1 || { echo "Docker is not running"; exit 2; }

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "== building $IMG (the runtime image)"
  docker build --target runtime -t "$IMG" . >/tmp/agentlatch-docker-build.log 2>&1 \
    || { echo "build failed; see /tmp/agentlatch-docker-build.log"; exit 2; }
fi

cleanup
docker volume create "$DATA" >/dev/null; docker volume create "$ANCHOR" >/dev/null
# A new volume belongs to root; give the anchor volume to the image's user (10001) once.
docker run --rm -u root --entrypoint chown -v "$ANCHOR:/anchor" "$IMG" 10001:10001 /anchor

echo "== seal a demo store"
docker run --rm -v "$DATA:/data" "$IMG" demo >/dev/null 2>&1
docker run --rm -v "$DATA:/data" -v "$ANCHOR:/anchor" "$IMG" import-logs \
  --dir runtime-logs/demo --database /data/audit.db --anchor /anchor/store-anchors.jsonl \
  --once --quiet >/dev/null 2>&1
verify() { # volume-for-data volume-for-anchor
  docker run --rm -v "$1:/data:ro" -v "$2:/anchor:ro" "$IMG" verify \
    --database /data/audit.db --anchor /anchor/store-anchors.jsonl 2>&1
}
out=$(verify "$DATA" "$ANCHOR"); code=$?
[ $code -eq 0 ] && echo "$out" | grep -q "AUDIT TRAIL INTACT" \
  && ok "a sealed store verifies INTACT against its anchor" || bad "sealed store did not verify" "$out"

echo "== 1. ownership and mode"
ls=$(docker run --rm --entrypoint ls -v "$DATA:/data" -v "$ANCHOR:/anchor" "$IMG" -ln /data/audit.db /anchor/store-anchors.jsonl)
echo "$ls" | grep -c -- "-rw------- 1 10001 10001" | grep -q 2 \
  && ok "store and anchor are owned by 10001 with mode 0600" || bad "unexpected owner or mode" "$ls"

echo "== 2. another user (uid 10002) with both volumes mounted read-write"
res=$(docker run --rm -u 10002:10002 --entrypoint python -v "$DATA:/data" -v "$ANCHOR:/anchor" "$IMG" -I -c "
import os, sqlite3
def t(fn):
    try: fn(); return 'ALLOWED'
    except PermissionError: return 'denied'
    except sqlite3.OperationalError: return 'denied'
for name, fn in [
  ('read store',    lambda: open('/data/audit.db','rb').read(1)),
  ('write store',   lambda: open('/data/audit.db','r+b').close()),
  ('chmod store',   lambda: os.chmod('/data/audit.db', 0o666)),
  ('delete store',  lambda: os.unlink('/data/audit.db')),
  ('sql delete',    lambda: sqlite3.connect('/data/audit.db').execute('DELETE FROM events')),
  ('read anchor',   lambda: open('/anchor/store-anchors.jsonl').read(1)),
  ('append anchor', lambda: open('/anchor/store-anchors.jsonl','a').close()),
  ('delete anchor', lambda: os.unlink('/anchor/store-anchors.jsonl')),
  ('chmod anchor',  lambda: os.chmod('/anchor/store-anchors.jsonl', 0o666))]:
    print(name + ': ' + t(fn))")
echo "$res" | sed 's/^/      /'
[ "$(echo "$res" | grep -c ': denied')" -eq 9 ] \
  && ok "all 9 attempts by another user were denied by the operating system" \
  || bad "another user got through" "$res"
out=$(verify "$DATA" "$ANCHOR")
echo "$out" | grep -q "AUDIT TRAIL INTACT" && ok "store still INTACT after those attempts" || bad "store changed" "$out"

echo "== 3. the read-only audit tool over a real MCP session (docker run -i)"
# Send the requests, then keep stdin open until every reply has arrived (or 30 seconds pass), so
# closing it never cancels a call that is still running.
rpc() { # outfile expected-replies request...
  local out="$1" expected="$2"; shift 2
  printf '%s\n' \
   '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}' \
   '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$@"
  local waited=0
  while [ "$(grep -c '"id":' "$out" 2>/dev/null)" -lt "$expected" ] && [ "$waited" -lt 60 ]; do
    sleep 0.5; waited=$((waited + 1))
  done
}
call() { # id sql
  printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"query_audit_log","arguments":{"sql":"%s"}}}' "$1" "$2"; }
attacks=("DELETE FROM events" "UPDATE events SET name='x'" "DROP TABLE events" "DROP TRIGGER events_no_update"
         "ALTER TABLE events ADD COLUMN x TEXT" "ATTACH DATABASE '/tmp/o.db' AS o" "PRAGMA query_only = OFF"
         "VACUUM INTO '/tmp/copy.db'" "WITH x AS (SELECT 1) DELETE FROM events")
lines=("$(call 2 'SELECT COUNT(*) AS n FROM events')"); id=3
for sql in "${attacks[@]}"; do lines+=("$(call $id "$sql")"); id=$((id + 1)); done
outfile=$(mktemp); : > "$outfile"
rpc "$outfile" $((id - 1)) "${lines[@]}" | docker run -i --rm --network none --read-only --cap-drop=ALL \
  --security-opt no-new-privileges -v "$DATA:/data:ro" "$IMG" audit-tool --database /data/audit.db \
  > "$outfile" 2>/dev/null
reply=$(cat "$outfile"); rm -f "$outfile"
echo "$reply" | grep -q '"id":2' && echo "$reply" | grep '"id":2' | grep -q '"isError":false' \
  && ok "the tool answers a read (SELECT COUNT)" || bad "the read did not work" "$reply"
refused=$(echo "$reply" | grep -E '"id":([3-9]|1[0-1])[,}]' | grep -c '"isError":true')
[ "$refused" -eq "${#attacks[@]}" ] \
  && ok "all ${#attacks[@]} write attempts were refused by the tool" \
  || bad "only $refused of ${#attacks[@]} writes were refused" "$reply"
out=$(verify "$DATA" "$ANCHOR")
echo "$out" | grep -q "AUDIT TRAIL INTACT" && ok "store still INTACT after the tool session" || bad "store changed" "$out"

echo "== 4. root, on a COPY of the store, edits a row (agent with Docker access)"
docker volume create "$COPY" >/dev/null
docker run --rm -u root --entrypoint cp -v "$DATA:/from:ro" -v "$COPY:/to" "$IMG" -a /from/audit.db /to/audit.db
docker run --rm -u root --entrypoint python -v "$COPY:/data" "$IMG" -I -c "
import sqlite3; c = sqlite3.connect('/data/audit.db')
c.execute('DROP TRIGGER events_no_update')
c.execute(\"UPDATE events SET name = 'nothing to see' WHERE event_order = 2\"); c.commit()"
out=$(verify "$COPY" "$ANCHOR"); code=$?
[ $code -eq 1 ] && echo "$out" | grep -q "AUDIT TRAIL TAMPERED" \
  && ok "the edited copy is reported TAMPERED (exit 1)" || bad "tampering was not caught" "$out"
out=$(verify "$DATA" "$ANCHOR")
echo "$out" | grep -q "AUDIT TRAIL INTACT" && ok "the original store is still INTACT" || bad "original changed" "$out"

echo
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
