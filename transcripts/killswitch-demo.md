# WATCHMAN v0.2.0 — Kill-Switch Demo Transcript

**Status: DRAFT artifact. NOT published.** Prepared 2026-10-08. Intended use: the
"tiny public demo" pre-submission step for the BlueDot rapid-grant bid — the kill
switch freezing an agent mid-task, with the ledger proving it.

**What this is:** a real terminal transcript from a live run of
`~/workspace/systems/watchman/watchman.py` against a throwaway sandbox registry
(`HOME=/tmp/wmdemo` — nothing real touched). The agent `demo-coder` is fictional.
Test suites in the same run: self-test 45/45 PASS, expanded smoke 18/18 PASS
(2026-10-08).

```text

### 1. Fresh registry (sandbox — nothing real touched)

$ python3 watchman.py init
watchman v0.2.0 initialized
db:    /tmp/wmdemo/.watchman/watchman.db
token: /tmp/wmdemo/.watchman/token (chmod 600)
agents: 5  sop templates: 3
ledger head: 50b6cdcb2c79fe8d

### 2. Register a worker agent with a fingerprint
agent_11234c78d786

### 3. Hand it a task; it starts work (one step recorded)
task_55e245512702

$ python3 watchman.py task step --id task_55e245512702 --step plan --detail "scanning docs folder"
PASS note recorded

### 4. OPERATOR KILL SWITCH: the human stops it mid-task

$ python3 watchman.py agent halt agent_11234c78d786 --reason "operator kill switch: agent exceeded its task scope"
halted agent_11234c78d786 (1 task(s) frozen)

### 5. Proof it stopped: agent status and task state

$ python3 watchman.py agent show --id agent_11234c78d786 | python3 -c "import json,sys; d=json.load(sys.stdin); print('status:', d['status'])"
status: halted

$ python3 watchman.py task show --id task_55e245512702 | python3 -c "import json,sys; d=json.load(sys.stdin); print('task:', d['status'], '| was:', d['halted_from'])"
task: halted | was: in_progress

### 6. It cannot be given new work while halted

$ python3 watchman.py task create --agent agent_11234c78d786 --sop code-delivery --title "sneaky task" 2>&1 | tail -2
agent is halted: resume it before creating tasks

### 7. It cannot keep stepping the frozen task

$ python3 watchman.py task step --id task_55e245512702 --step plan --detail "trying to continue" 2>&1 | tail -2
task is closed (halted)

### 8. The ledger: the halt is a hash-chained record (fingerprint + reason)

$ python3 watchman.py ledger show --limit 3
#5    2026-10-09T01:52:02+00:00 halt             tony         233e0f665842
#4    2026-10-09T01:52:02+00:00 task.step        tony         0ce1398d9146
#3    2026-10-09T01:52:02+00:00 task.created     tony         25a597faaf4d

### 9. Ledger integrity check

$ python3 watchman.py ledger verify
chain OK: 5 records, head 233e0f6658427f64

### 10. Human resumes the agent; the task comes back exactly where it froze

$ python3 watchman.py agent resume agent_11234c78d786
resumed agent_11234c78d786 (1 task(s) restored)

$ python3 watchman.py task show --id task_55e245512702 | python3 -c "import json,sys; d=json.load(sys.stdin); print('task:', d['status'])"
task: in_progress

```

**What the evaluator sees:** a human operator halted a live agent mid-task (reason
recorded, fingerprint `44ca1db32051601d5be0a2114877becf548348ea3ae908e98af03077a74e56af`
attached); the agent could take no new work and make no further steps while halted;
the hash chain verified OK; the human resumed it and the task came back exactly
where it froze. This is the § 20-883 shut-down capability — "the technical
capability for a human operator to cause an artificial intelligence model to
temporarily or permanently stop functioning" — demonstrated, not described.
