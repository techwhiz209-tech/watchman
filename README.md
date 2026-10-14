# WATCHMAN

**On-device agent registry and accountability for personal AI systems.**

WATCHMAN keeps a single registry of every AI agent, tool, and API you use —
local or cloud — and holds their work to account: tasks can't be marked done
unless they pass verification, and every step, score change, and stop order is
recorded in a hash-chained ledger you can audit.

## What it is

Five subsystems in one small tool (a single Python file, standard library only):

- **Registry** — every agent, API, tool, platform, or app in one place, each
  with a cryptographic identity (a fingerprint, so a renamed agent can't dodge
  its record).
- **SOP engine** — tasks are bound to standing operating procedures: the checks
  run *now*, as the work happens, not after.
- **Completion gate** — the only path to done is `verify`. Checks re-run fresh
  every time; recorded passes mean nothing until reproduced. Deterministic
  checks cover command hygiene, attachment existence, absolute-language claims,
  claim grading (FACT / CLAIM / INFERENCE / UNKNOWN), and secret scanning.
- **Reputation** — agents carry a score from 0 to 1000 and an autonomy tier
  (`observed` → `supervised` → `trusted`); verified work raises it, failed
  verifications and theatrics lower it.
- **Hash-chained ledger** — every record carries the hash of the one before it.
  `ledger verify` recomputes the whole chain: tampering shows up immediately.

Phase 1 adds the enforcement half:

- **Kill switch (operator-only)** — `agent halt` freezes every live task
  (open / in-progress / submitted → halted), blocks new tasks, and chains a
  halt record with the reason, the actor, and the agent's fingerprint. `agent
  resume` restores everything to its pre-halt state. Deliberately CLI-only: no
  HTTP endpoint, no agent-facing command.
- **Incident reporter** — a 24-hour reporting clock, on the record: `incident
  report` stamps a computed deadline, `incident list` shows live countdowns.

Also included: a browser extension (Chrome/Arc) that shows live agents, scores,
open tasks, and a Verify button over a token-gated localhost API.

## Honest limits

- This stops theatrics, corner-cutting, and self-certification. It does **not**
  stop a frontier model competently scheming against the registry itself.
- The chain proves nothing was *altered*; it can't prove nothing was
  *omitted*. Copy the head hash somewhere the agent can't reach (`ledger
  checkpoint`).
- The kill switch stops registry-gated work. It can't reach into model weights
  or stop an agent running outside this registry.
- Agent identity crypto is a labeled placeholder (stdlib has no Ed25519): a
  unique, stable, unpredictable fingerprint — not real asymmetric crypto. The
  swap seam is documented in DESIGN.md.
- The theatrics flag is a heuristic (certainty-language + failed checks). It
  prices a behavior; it doesn't prove intent. Appeals exist for exactly this.

## Quickstart

One Python file, standard library only — no installs, no Docker, no network.

```bash
# 1. Copy the project somewhere convenient (no build step)
cp -r /path/to/cloned/watchman ~/watchman

# 2. Initialize: creates the registry database and seed SOPs
python3 ~/watchman/watchman.py init

# 3. Register an agent and give it work
python3 ~/watchman/watchman.py agent register --name "my-agent" --kind agent --location local
python3 ~/watchman/watchman.py task create --agent agent_my-agent --sop agent-task-standard --title "Research X"

# 4. The gate: only this moves a task to done
python3 ~/watchman/watchman.py task verify --id <task> --approver your-name

# 5. Verify the chain yourself
python3 ~/watchman/watchman.py ledger verify
```

Data lives in `~/.watchman/watchman.db` (SQLite) and the token in
`~/.watchman/token` (chmod 600). Secrets are never stored — only pointers to
where they live (e.g. a keychain reference). If a secret is pasted into any
field, the secrets scan fails the task.

## The demo

`transcripts/killswitch-demo.md` is a real terminal transcript of the kill
switch freezing a live agent mid-task: the agent goes halted, can take no new
work and make no further steps, the ledger records the halt with reason and
fingerprint, `ledger verify` returns "chain OK", and a resume restores the task
exactly where it froze. Self-test 45/45 and expanded smoke 18/18 pass in the
same run (`tests/self-test.sh`, `tests/expanded-smoke.sh`).

## Docs

- `DESIGN.md` — the unified design doc: the accountability model, the five
  subsystems, Phase 1, honest limits, and what each piece is for.
- `extension/` — the Chrome/Arc extension source (popup, options, background).

## Author

WATCHMAN was designed and built by **Anthony Logan Hernandez**.

## License

MIT — see `LICENSE`.
