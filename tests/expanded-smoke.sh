#!/bin/bash
# WATCHMAN expanded smoke tests 1-6 (from watchman-smoke-test-plan-2026-10-07.md)
# Sandboxed HOME per test; the real ~/.watchman is untouched.
set -u
WM="/home/hatch/workspace/systems/watchman/watchman.py"
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  PASS: $1"; }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
DB()  { echo "$1/.watchman/watchman.db"; }

echo "== T1. rename-dodge under halt =="
export HOME=/tmp/wmexp1; rm -rf /tmp/wmexp1; mkdir -p /tmp/wmexp1
python3 "$WM" init >/dev/null 2>&1
AID=$(python3 "$WM" agent register --name "DodgeBot" --kind agent --location local 2>&1 | tail -1)
FP=$(python3 "$WM" agent identity "$AID" 2>/dev/null | grep "^fingerprint:" | awk '{print $2}')
python3 "$WM" agent halt "DodgeBot" --reason "t1 halt" >/dev/null 2>&1
# adversary renames the row behind the registry's back (no CLI rename exists)
python3 -c "
import sqlite3
con=sqlite3.connect('$(DB /tmp/wmexp1)')
con.execute(\"UPDATE agents SET name='InnocentBot' WHERE id='$AID'\")
con.commit()
"
ST=$(python3 "$WM" agent show --id "$AID" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$ST" = "halted" ] && ok "halt still binds after rename (status=$ST)" || bad "status after rename: $ST"
FP2=$(python3 "$WM" agent identity "$AID" 2>/dev/null | grep "^fingerprint:" | awk '{print $2}')
[ "$FP" = "$FP2" ] && ok "fingerprint unchanged by rename" || bad "fingerprint changed: $FP -> $FP2"
RES=$(python3 "$WM" agent halt "$FP" --reason "t1 again" 2>&1)
echo "$RES" | grep -q "already halted" && ok "halt by fingerprint targets same halted agent" || bad "fingerprint halt: $RES"
RES2=$(python3 "$WM" agent halt "InnocentBot" --reason "t1 new name" 2>&1)
echo "$RES2" | grep -q "already halted" && ok "halt by NEW name resolves to same agent" || bad "new-name halt: $RES2"

echo "== T2. halt during verify (submitted task must freeze, not slip through) =="
export HOME=/tmp/wmexp2; rm -rf /tmp/wmexp2; mkdir -p /tmp/wmexp2
python3 "$WM" init >/dev/null 2>&1
AID2=$(python3 "$WM" agent register --name "VerifyBot" --kind agent --location local 2>&1 | tail -1)
TID=$(python3 "$WM" task create --agent "$AID2" --sop code-delivery --title "t2 verify race" 2>&1 | tail -1)
python3 "$WM" task step --id "$TID" --step hygiene --detail "x" >/dev/null 2>&1
python3 "$WM" task step --id "$TID" --step artifacts --detail "none" >/dev/null 2>&1
python3 "$WM" task step --id "$TID" --step claims --detail '[{"text":"t2","grade":"FACT","evidence":"t2"}]' >/dev/null 2>&1
python3 "$WM" task step --id "$TID" --step secrets --detail "none" >/dev/null 2>&1
python3 "$WM" task step --id "$TID" --step approval --detail "tony approved in test" >/dev/null 2>&1
python3 "$WM" task submit --id "$TID" --report "r" --claims '[]' --artifacts '[]' >/tmp/wmexp2-sub.log 2>&1 || echo "SUBMIT FAILED: $(cat /tmp/wmexp2-sub.log)"
python3 "$WM" agent halt "$AID2" --reason "t2 halt mid-verify" >/dev/null 2>&1
TST=$(python3 "$WM" task show --id "$TID" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['status'], d.get('halted_from',''))")
echo "$TST" | grep -q "^halted submitted" && ok "submitted task froze (halted_from=submitted)" || bad "task state: $TST"
VRF=$(python3 "$WM" task verify --id "$TID" 2>&1)
echo "$VRF" | grep -q "not verifiable" && ok "verify gate refuses halted task" || bad "verify output: $VRF"

echo "== T3. double-halt / double-resume race: ledger stays consistent =="
export HOME=/tmp/wmexp3; rm -rf /tmp/wmexp3; mkdir -p /tmp/wmexp3
python3 "$WM" init >/dev/null 2>&1
AID3=$(python3 "$WM" agent register --name "RaceBot" --kind agent --location local 2>&1 | tail -1)
H1=$(python3 "$WM" agent halt "$AID3" --reason "t3 first" 2>&1)
H2=$(python3 "$WM" agent halt "$AID3" --reason "t3 second" 2>&1)
R1=$(python3 "$WM" agent resume "$AID3" 2>&1)
R2=$(python3 "$WM" agent resume "$AID3" 2>&1)
echo "$H2" | grep -q "already halted" && ok "double halt idempotent" || bad "halt2: $H2"
echo "$R2" | grep -q "not halted" && ok "double resume no-op" || bad "resume2: $R2"
python3 "$WM" ledger verify 2>&1 | grep -q "chain OK" && ok "ledger chain consistent after race" || bad "ledger verify failed"
AST=$(python3 "$WM" agent show --id "$AID3" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$AST" = "active" ] && ok "agent converged back to active" || bad "final status: $AST"

echo "== T4. incident overdue path (clock-skew simulation) =="
export HOME=/tmp/wmexp4; rm -rf /tmp/wmexp4; mkdir -p /tmp/wmexp4
python3 "$WM" init >/dev/null 2>&1
AID4=$(python3 "$WM" agent register --name "IncidentBot" --kind agent --location local 2>&1 | tail -1)
IID=$(python3 "$WM" incident report --agent "$AID4" --kind safety --summary "t4 overdue" 2>&1 | head -1)
python3 -c "
import sqlite3
con=sqlite3.connect('$(DB /tmp/wmexp4)')
con.execute(\"UPDATE incidents SET deadline='2026-10-01T00:00:00+00:00' WHERE id='$IID'\")
con.commit()
"
LST=$(python3 "$WM" incident list 2>&1)
echo "$LST" | grep -q "OVERDUE" && ok "overdue status fires on expired deadline" || bad "incident list: $LST"
python3 "$WM" incident resolve "$IID" --note "t4 resolved late" >/dev/null 2>&1
python3 "$WM" ledger verify 2>&1 | grep -q "chain OK" && ok "late resolution stays chained" || bad "ledger after resolve"

echo "== T5. ledger tamper after halt records: break must localize =="
export HOME=/tmp/wmexp5; rm -rf /tmp/wmexp5; mkdir -p /tmp/wmexp5
python3 "$WM" init >/dev/null 2>&1
AID5=$(python3 "$WM" agent register --name "TamperBot" --kind agent --location local 2>&1 | tail -1)
python3 "$WM" agent halt "$AID5" --reason "t5 halt" >/dev/null 2>&1
python3 "$WM" agent resume "$AID5" >/dev/null 2>&1
cp "$(DB /tmp/wmexp5)" /tmp/wmexp5/tampered.db
python3 -c "
import sqlite3
con=sqlite3.connect('/tmp/wmexp5/tampered.db')
r=con.execute(\"SELECT seq,payload FROM ledger WHERE kind='halt'\").fetchone()
con.execute('UPDATE ledger SET payload=? WHERE seq=?', (r[1].replace('t5 halt','forged'), r[0]))
con.commit()
"
OUT=$(HOME=/tmp/wmexp5 WATCHMAN_TAMPER=1 python3 -c "
import sqlite3, sys
sys.path.insert(0,'/home/hatch/workspace/systems/watchman')
import watchman
con=sqlite3.connect('/tmp/wmexp5/tampered.db'); con.row_factory=sqlite3.Row
ok,probs=watchman.ledger_verify(con)
print('OK' if ok else 'BROKEN')
for p in probs: print(p)
" 2>&1)
echo "$OUT" | grep -q "BROKEN" && ok "tamper detected" || bad "tamper not detected: $OUT"
echo "$OUT" | grep -qE "payload was altered|record hash invalid" && ok "break localized to the altered record" || bad "localization: $OUT"
GOOD=$(python3 "$WM" ledger verify 2>&1 | grep -c "chain OK")
[ "$GOOD" = "1" ] && ok "untampered original chain still OK" || bad "original chain"

echo "== T6. halt scope honesty: a halt governs only its own registry =="
export HOME=/tmp/wmexp6a; rm -rf /tmp/wmexp6a /tmp/wmexp6b; mkdir -p /tmp/wmexp6a /tmp/wmexp6b
python3 "$WM" init >/dev/null 2>&1
AIDA=$(HOME=/tmp/wmexp6a python3 "$WM" agent register --name "ScopeBot" --kind agent --location local 2>&1 | tail -1)
HOME=/tmp/wmexp6b python3 "$WM" init >/dev/null 2>&1
AIDB=$(HOME=/tmp/wmexp6b python3 "$WM" agent register --name "ScopeBot" --kind agent --location local 2>&1 | tail -1)
HOME=/tmp/wmexp6a python3 "$WM" agent halt "$AIDA" --reason "t6 scope" >/dev/null 2>&1
STB=$(HOME=/tmp/wmexp6b python3 "$WM" agent show --id "$AIDB" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[ "$STB" = "active" ] && ok "same-named agent in another registry untouched" || bad "registry B status: $STB"
NB=$(HOME=/tmp/wmexp6b python3 "$WM" ledger show 2>/dev/null | grep -c "halt")
[ "$NB" = "0" ] && ok "no halt record leaked into the other registry's ledger" || bad "halt records in B: $NB"
grep -q "UPDATE tasks SET status='halted'" /home/hatch/workspace/systems/watchman/watchman.py \
  && grep -q "WHERE agent_id=?" /home/hatch/workspace/systems/watchman/watchman.py \
  && ok "code assertion: halt updates only WHERE agent_id matches (registry-local)" || bad "code assertion"

echo ""
echo "RESULT: $pass passed, $fail failed"
exit $((fail>0))
