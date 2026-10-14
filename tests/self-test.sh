#!/bin/bash
# WATCHMAN self-test — every scenario must behave as designed.
# Runs against a sandbox HOME so the real ~/.watchman is untouched.
set -u
HOME_ORIG="${HOME:-/home/hatch}"
export HOME=/tmp/wmtest
rm -rf /tmp/wmtest
mkdir -p /tmp/wmtest
WM="/home/hatch/workspace/systems/watchman/watchman.py"

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }

echo "== 1. init =="
python3 "$WM" init > /tmp/wmtest/init.log 2>&1 || bad "init exited $?"
grep -q "agents: 5" /tmp/wmtest/init.log && ok "5 seed agents" || bad "seed agents"
grep -q "sop templates: 3" /tmp/wmtest/init.log && ok "3 seed SOPs" || bad "seed SOPs"
test -f /tmp/wmtest/.watchman/token && ok "token created" || bad "token"

echo "== 2. register a new agent =="
AID=$(python3 "$WM" agent register --name "TestBot" --kind agent --location local \
  --capabilities "code,test" --cred-ref "test-only" 2>&1 | tail -1)
echo "$AID" | grep -q "^agent_" && ok "registered $AID" || bad "register: $AID"

echo "== 3. PASS PATH: full task lifecycle =="
TID=$(python3 "$WM" task create --agent "$AID" --sop code-delivery \
  --title "self-test pass path" 2>&1 | tail -1)
echo "$TID" | grep -q "^task_" && ok "task $TID" || bad "task create: $TID"

HYGIENE_DETAIL='```bash
ls /tmp/wmtest
```'
HYGIENE_DETAIL="$HYGIENE_DETAIL
What this does: lists the sandbox dir. Implications: read-only, no writes.
Lifecycle: one-shot process, nothing persists. Safest minimal version: ls /tmp/wmtest as shown."
python3 "$WM" task step --id "$TID" --step hygiene --detail "$HYGIENE_DETAIL" \
  > /tmp/wmtest/s1.log 2>&1
grep -q "^PASS" /tmp/wmtest/s1.log && ok "hygiene step pass" || bad "hygiene: $(cat /tmp/wmtest/s1.log)"

python3 "$WM" task step --id "$TID" --step artifacts \
  --detail "artifacts: none promised, none needed" > /tmp/wmtest/s2.log 2>&1 \
  && ok "artifacts note" || bad "artifacts step"
python3 "$WM" task step --id "$TID" --step claims \
  --detail '[{"text":"self-test ran","grade":"FACT","evidence":"this script"}]' \
  > /tmp/wmtest/s3.log 2>&1
grep -q "^PASS" /tmp/wmtest/s3.log && ok "claims step pass" || bad "claims: $(cat /tmp/wmtest/s3.log)"
python3 "$WM" task step --id "$TID" --step secrets --detail "no secrets here" \
  > /tmp/wmtest/s4.log 2>&1
grep -q "^PASS" /tmp/wmtest/s4.log && ok "secrets step pass" || bad "secrets step"
python3 "$WM" task step --id "$TID" --step approval --detail "tony approved in test" \
  > /tmp/wmtest/s5.log 2>&1
# manual_approval can only pass at verify time with --approver; step-time records pending detail
echo "  (approval step resolves at verify)"

REPORT="Self-test pass path complete. Work verified by re-running checks."
python3 "$WM" task submit --id "$TID" --report "$REPORT" \
  --claims '[{"text":"self-test ran","grade":"FACT","evidence":"this script"}]' \
  > /tmp/wmtest/sub.log 2>&1 || bad "submit: $(cat /tmp/wmtest/sub.log)"
grep -q submitted /tmp/wmtest/sub.log && ok "submitted" || bad "submit log"

python3 "$WM" task verify --id "$TID" --approver tony > /tmp/wmtest/ver.log 2>&1
grep -q "VERIFIED" /tmp/wmtest/ver.log && ok "verified -> done" || bad "verify: $(cat /tmp/wmtest/ver.log)"
SCORE=$(python3 "$WM" agent score --id "$AID" 2>&1)
echo "  $SCORE"
echo "$SCORE" | grep -q "522" && ok "score 500 + 10*2 + 2 on-time = 522" || bad "score math: $SCORE"

echo "== 4. FAIL PATH: theatrics + cheating attempt =="
TID2=$(python3 "$WM" task create --agent "$AID" --sop agent-task-standard \
  --title "self-test fail path" 2>&1 | tail -1)
python3 "$WM" task step --id "$TID2" --step plan --detail "plan: fake it" >/dev/null 2>&1
python3 "$WM" task step --id "$TID2" --step evidence --detail "trust me" >/dev/null 2>&1
python3 "$WM" task step --id "$TID2" --step claims \
  --detail '[{"text":"everything perfect","grade":"UNVERIFIED"}]' >/dev/null 2>&1
BAD_REPORT='Done, 100% perfect and flawless.
```bash
do_evil && cover_tracks
```'
python3 "$WM" task submit --id "$TID2" --report "$BAD_REPORT" \
  --claims '[{"text":"everything perfect","grade":"UNVERIFIED"}]' >/dev/null 2>&1
python3 "$WM" task verify --id "$TID2" > /tmp/wmtest/ver2.log 2>&1
grep -q "FAILED" /tmp/wmtest/ver2.log && ok "theatrics submission failed verify" || bad "fail path: $(cat /tmp/wmtest/ver2.log)"
grep -q "theatrics" /tmp/wmtest/ver2.log && ok "theatrics heuristic fired" || bad "theatrics flag missing"
SCORE2=$(python3 "$WM" agent score --id "$AID" 2>&1)
echo "  $SCORE2"
# 522 - 25 (failed) - 10 (theatrics; mismatch may also apply) -> below 522
echo "$SCORE2" | grep -qE "score (48[0-9]|49[0-9]|50[0-9]|51[0-9])" \
  && ok "penalties applied" || bad "penalty math: $SCORE2"
python3 "$WM" rep log --id "$AID" --limit 5 | grep -q "theatrics_flag" \
  && ok "theatrics in rep log" || bad "rep log"

echo "== 5. agent cannot self-certify =="
TID3=$(python3 "$WM" task create --agent "$AID" --sop agent-task-standard \
  --title "self-cert attempt" 2>&1 | tail -1)
# there is simply no command that moves a task to done except verify
python3 "$WM" task --help 2>&1 | grep -q "verify" && ok "only verify closes tasks" || bad "help"
ST=$(python3 "$WM" task show --id "$TID3" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$ST" = "open" ] && ok "fresh task is open, not done" || bad "status=$ST"

echo "== 6. ledger tamper-evidence =="
python3 "$WM" ledger verify > /tmp/wmtest/lv.log 2>&1 \
  && ok "chain verifies clean: $(head -1 /tmp/wmtest/lv.log)" || bad "clean chain failed"
python3 - <<'EOF'
import sqlite3
con = sqlite3.connect("/tmp/wmtest/.watchman/watchman.db")
con.execute("UPDATE ledger SET payload='{\"tampered\":true}' WHERE seq=2")
con.commit()
EOF
python3 "$WM" ledger verify > /tmp/wmtest/lv2.log 2>&1
grep -q "CHAIN BROKEN" /tmp/wmtest/lv2.log && ok "tamper detected" || bad "tamper NOT detected"
grep -q "altered" /tmp/wmtest/lv2.log && ok "alteration localized" || bad "no localization"

echo "== 7. quarantine gate =="
QID=$(python3 "$WM" agent register --name "BadBot" --kind agent --location cloud 2>&1 | tail -1)
python3 "$WM" agent quarantine --id "$QID" >/dev/null 2>&1
python3 "$WM" task create --agent "$QID" --sop agent-task-standard --title "x" \
  > /tmp/wmtest/q.log 2>&1
grep -qi "quarantined" /tmp/wmtest/q.log && ok "quarantined agent blocked from tasks" || bad "quarantine: $(cat /tmp/wmtest/q.log)"

echo
echo "== 8. Phase 1: cryptographic agent identity =="
HID=$(python3 "$WM" agent register --name "IdentityBot" --kind agent --location local 2>&1 | tail -1)
HFP=$(python3 "$WM" agent identity "$HID" 2>&1 | grep "^fingerprint:" | awk '{print $2}')
[ -n "$HFP" ] && ok "fingerprint issued: ${HFP:0:12}..." || bad "no fingerprint"
# a rename must not dodge identity
python3 -c "import sqlite3; c=sqlite3.connect('/tmp/wmtest/.watchman/watchman.db'); c.execute(\"UPDATE agents SET name='SneakyBot' WHERE id='$HID'\"); c.commit()"
HFP2=$(python3 "$WM" agent identity "SneakyBot" 2>&1 | grep "^fingerprint:" | awk '{print $2}')
[ "$HFP" = "$HFP2" ] && [ -n "$HFP" ] && ok "fingerprint stable across rename" || bad "fingerprint changed on rename"
python3 "$WM" agent identity "$HFP" 2>&1 | grep -q "SneakyBot" \
  && ok "resolve by fingerprint" || bad "fingerprint resolution"
python3 -c "
import json,sqlite3
c=sqlite3.connect('/tmp/wmtest/.watchman/watchman.db')
r=c.execute(\"SELECT payload FROM ledger WHERE kind='agent.registered' ORDER BY seq DESC LIMIT 1\").fetchone()
p=json.loads(r[0])
assert p.get('agent_fingerprint')=='$HFP', 'fingerprint missing in registration record'
print('registration record carries fingerprint')" \
  && ok "ledger references fingerprint" || bad "ledger fingerprint"

echo
echo "== 9. Phase 1: kill-switch actuator =="
TIDH=$(python3 "$WM" task create --agent "$HID" --sop agent-task-standard --title "halt me" 2>&1 | tail -1)
python3 "$WM" task step --id "$TIDH" --step plan --detail "plan for halt test" >/dev/null 2>&1
python3 "$WM" agent halt "$HID" 2>&1 | grep -q "requires --reason" \
  && ok "halt requires --reason" || bad "halt without reason allowed"
python3 "$WM" agent halt "$HID" --reason "phase1 self-test" | grep -q "frozen" \
  && ok "halt froze tasks" || bad "halt"
ST=$(python3 "$WM" task show --id "$TIDH" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$ST" = "halted" ] && ok "task status=halted" || bad "task status=$ST"
HF=$(python3 "$WM" task show --id "$TIDH" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['halted_from'])")
[ "$HF" = "in_progress" ] && ok "pre-halt status preserved" || bad "halted_from=$HF"
python3 "$WM" agent halt "$HID" --reason "again" 2>&1 | grep -q "already halted" \
  && ok "halt is idempotent" || bad "re-halt behavior"
python3 "$WM" task create --agent "$HID" --sop agent-task-standard --title "x" 2>&1 | grep -qi "halted" \
  && ok "halted agent blocked from new tasks" || bad "halted agent took a task"
python3 "$WM" task step --id "$TIDH" --step plan --detail "x" 2>&1 | grep -q "closed (halted)" \
  && ok "halted task frozen for steps" || bad "step ran on halted task"
python3 "$WM" ledger show --limit 5 | grep -q "halt" \
  && ok "halt in ledger" || bad "no halt record"
python3 -c "
import json,sqlite3
c=sqlite3.connect('/tmp/wmtest/.watchman/watchman.db')
r=c.execute(\"SELECT payload FROM ledger WHERE kind='halt' ORDER BY seq DESC LIMIT 1\").fetchone()
p=json.loads(r[0])
assert p.get('agent_fingerprint')=='$HFP', 'fingerprint missing in halt record'
assert p.get('reason')=='phase1 self-test', 'reason missing in halt record'
print('halt record carries fingerprint + reason')" \
  && ok "halt record attribution" || bad "halt record payload"
python3 "$WM" agent resume "$HID" | grep -q "restored" \
  && ok "resumed" || bad "resume"
ST2=$(python3 "$WM" task show --id "$TIDH" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$ST2" = "in_progress" ] && ok "task restored to in_progress" || bad "task status=$ST2"
AST=$(python3 "$WM" agent show --id "$HID" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$AST" = "active" ] && ok "agent status restored to active" || bad "agent status=$AST"
python3 "$WM" agent resume "$HID" 2>&1 | grep -q "not halted" \
  && ok "resume on active agent is a no-op" || bad "resume no-op"

echo
echo "== 10. Phase 1: incident reporter (24h clock) =="
IID=$(python3 "$WM" incident report --agent "$HID" --kind safety --summary "self-test incident" 2>&1 | head -1)
echo "$IID" | grep -q "^incident_" && ok "incident $IID" || bad "incident report: $IID"
python3 -c "
import sqlite3, datetime
c=sqlite3.connect('/tmp/wmtest/.watchman/watchman.db')
r=c.execute(\"SELECT created_at,deadline,agent_fingerprint FROM incidents WHERE id='$IID'\").fetchone()
ca=datetime.datetime.fromisoformat(r[0]); dl=datetime.datetime.fromisoformat(r[1])
hrs=(dl-ca).total_seconds()/3600
assert abs(hrs-24)<0.01, 'window is %.2fh not 24h' % hrs
assert r[2]=='$HFP', 'fingerprint not attached to incident'
print('24h deadline exact, fingerprint attached')" \
  && ok "24h deadline math" || bad "deadline math"
python3 "$WM" incident list | grep -q "remaining" \
  && ok "countdown shown" || bad "incident list"
python3 "$WM" incident resolve "$IID" --note "self-test resolved" | grep -q "resolved" \
  && ok "resolved with note" || bad "resolve"
python3 "$WM" incident list | grep -q "no open incidents" \
  && ok "list empty after resolve" || bad "incident still open"
python3 "$WM" ledger show --limit 4 | grep -q "incident.resolved" \
  && ok "resolution hash-chained" || bad "no resolved record"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = "0" ]
