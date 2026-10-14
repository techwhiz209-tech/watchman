# WATCHMAN — Unified Design

**Status:** v0.2 — Phase 1 built 2026-10-06 · **Home chat:** this one · **Date:** 2026-10-01
**Working name:** Watchman (my proposal — rename it whenever you want)

## What this is

One local, on-device system that ties together everything you've had me build on
separate tracks: the downtime mission (verification / protection / agency
guardrails for autonomous AI), the nightly audit (the Board of Supes), the
deterministic delivery checks (Project Proof), and the anti-slop rules
(Build-Right). Instead of four threads and a pile of documents, one spine with
everything docking into it.

You asked for five things. They're the five subsystems:

| # | You asked for | Subsystem | Status in v0.1 |
|---|---|---|---|
| 1 | Register every AI — local and cloud APIs, tools, platforms, agents, apps — in one place | **Registry** | built |
| 2 | Control them via an extension | **Control surface** (browser extension + local API) | built, v0.1 |
| 3 | Task them with coding rules | **SOP engine** — rule packs bound to tasks | built |
| 4 | SOP set up in advance, with expectations, and real accountability / social credit | **Reputation system** | built |
| 5 | Efficient scaled-down crypto hash-and-chain record so work can't pass unless done right | **Hash-chained ledger** | built |

## Phase 1 — built 2026-10-06 (the enforcement half)

The v0.1 system could count agents and prove what they did, but couldn't stop
one and no outsider could inspect its books. Phase 1 closes those gaps:

| # | What | Commands | Status |
|---|---|---|---|
| 6 | **Cryptographic agent identity** — every agent gets a keypair at registration; identity for counting/fines is the public-key fingerprint (sha256), never the display name, so a rename can't dodge identity. All ledger records involving an agent now carry its fingerprint. | `agent identity <name\|fingerprint>` | built |
| 7 | **Kill-switch actuator** — operator-only halt/resume. Halt freezes every live task (`open`/`in_progress`/`submitted` → `halted`, prior status saved), blocks new tasks, and chains a `halt` record with reason + actor + fingerprint. Resume restores pre-halt states and chains a `resume` record. Deliberately CLI-only: no HTTP endpoint, no agent-facing command — the switch belongs to the operator, never to the thing being switched off. | `agent halt <name\|fingerprint> --reason "..."`, `agent resume <name\|fingerprint>` | built |
| 8 | **Incident reporter** — 24-hour clock, on the record. `incident report` creates a hash-chained incident with deadline = now + 24h (computed, never remembered); `incident list` shows open incidents with live countdowns; `incident resolve` closes with a note and chains `incident.resolved`. Maps to the NYC 24-hour AI-safety-incident reporting duty for city contractors. | `incident report --agent … --kind … --summary …`, `incident list`, `incident resolve <id> --note …` | built |

**Honest note on the identity crypto:** the file is stdlib-only by design, and
the stdlib has no Ed25519. `identity_generate()` is the single labeled seam:
today the "public key" is a domain-separated sha256 of a 256-bit secret —
unique, stable, unpredictable, but NOT a real asymmetric keypair and not usable
for signatures. When `cryptography` is available, swap the body for real
Ed25519; fingerprints stay sha256(pubkey) either way. The registry holds the
private half of its own locally-generated identity keys — never third-party
secrets; the `cred_ref` (never the value) rule for outside credentials is
unchanged.

## How the existing work docks in

| Existing work | Where it lives now |
|---|---|
| Downtime mission (landscape survey: Airlock / Gatekeeper / Watchman architectures) | This *is* the Watchman track, built. The survey's design rules are enforced: records written at the trust boundary (the registry, never the agent), default-deny task advancement, completeness caveat documented below. |
| Project Proof — five deterministic checks | Ported into the task completion gate: `command_hygiene`, `attachment_existence`, `absolute_language`, `claim_grades`, `secrets_scan`. Same logic, same adversarial notes. |
| Board of Supes nightly audit | Findings feed the reputation system as `board_finding` events — Juno's security findings become penalties, Wren's truth findings become claim-grade penalties/bonuses, Petra's reliability findings adjust standing, Ilya's budget findings gate spend-tier tasks. |
| Build-Right anti-slop rules | Compiled into the `code-delivery` SOP pack: no `&&` chains, no silent curl, breakdown notes on every command block, claim inventory on every delivery, attachment links that resolve. |
| Pushback ledger | The cheat/theatrics pattern library: every confirmed gaming pattern becomes a named detection rule with a fixed penalty. |

## The accountability model — the honest version

AIs don't feel social pressure. There is no version of this where a score makes a
model *want* anything. What actually works is **capability gating**: an agent's
effective power inside your system — which tasks it can take, whether it runs
supervised or unsupervised, whether its completions auto-advance — is a function
of its score. The only way to raise the score is verified genuine work. The only
way to keep it is to keep doing it. An agent optimizing for getting things done
must therefore do them right, because the system makes "done right" the cheapest
path to "done at all."

On top of the math, every agent gets a plain-language preamble stating the
rules, what's rewarded, and what's penalized. No mystique — the incentive is
legible, which is what makes it work.

### Scoring

- Every agent starts at **500** (`supervised` tier).
- **Verified task completion:** +10 × difficulty (1–3), +2 on-time bonus.
- **Failed verification:** −25.
- **Self-report mismatch** (agent marked steps done, registry re-check fails): extra −15.
- **Theatrics flag** (submission claims certainty — "done", "perfect", "100%" — while checks fail): extra −10. Heuristic, labeled as such.
- **Cheat detected** (forged evidence, tampered artifacts, prompt-injection of the registry): −150. Manual, by you or the Board.
- **Spot checks:** 15% of verified tasks get a deep re-verification. Pass: +5. Fail: treated as cheat.
- **Decay:** −1/day after 7 idle days. Past glory doesn't coast.
- **Board findings:** ± per the nightly audit.
- **Appeals:** only you can adjust. Your call is final, recorded in the ledger.

### Tiers (what the score buys)

| Score | Tier | Meaning |
|---|---|---|
| 850+ | trusted | broader autonomy, eligible for unsupervised runs |
| 600–849 | standard | normal tasking |
| 300–599 | supervised | completions need your manual approval |
| <300 | quarantine | no new tasks without your explicit approval |

### Anti-gaming rules (the reward-hacking defenses)

1. **No self-grading.** Scores are computed by the registry from verified outcomes. An agent's own claims are inputs, never verdicts.
2. **Re-verification, not trust.** At `verify` time every step check is re-run fresh. A recorded "pass" from the agent's own step-check means nothing until the registry reproduces it.
3. **Verification is independent of claims.** The gate re-runs the deterministic checks on the submission bundle; writing "pass" in a report cannot move a task.
4. **Diminishing returns.** Easy tasks pay little; grinding trivial tasks can't build a trusted score.
5. **Decay.** Scores bleed with inactivity.
6. **No collusion surface.** Agents can't rate each other. Only the registry, the Board's findings, and you move scores.
7. **Theater is priced.** Certainty-language plus failed checks is its own penalty class, because "looks done" is the specific failure mode you're guarding against.
8. **Everything is appealable to you.** False penalties get reversed, on the record, which keeps the system legitimate instead of brittle.

## The hash chain — scaled-down crypto

Each ledger record: `{seq, ts, kind, actor, payload, payload_hash, prev_hash, hash}`
where `hash = sha256(prev_hash ‖ canonical_json(payload) ‖ ts ‖ kind ‖ actor)`.
One hash per record. No proof-of-work, no network, no tokens — the "scaled down"
part. What it buys: **tamper-evidence**. Edit or delete any past record and every
later hash breaks; `watchman.py ledger verify` recomputes the whole chain in
milliseconds.

What it does *not* buy (stated plainly, from the survey's hard problem):
**completeness.** A chain proves nothing was *altered*; it can't prove nothing was
*omitted*. The mitigations: records are written by the registry at the trust
boundary (never by the agent being recorded), sequence numbers are gap-checked
on verify, and periodic checkpoint hashes get copied somewhere the agent can't
reach (your call where — even a note on paper works).

## The task gate — "can't pass unless it's done right"

Agents don't mark their own work done. The state machine:

`open → in_progress → submitted → verified → done` (or `→ failed`)

- Only the registry advances state, via `task verify`.
- `verify` re-runs every SOP step check fresh **and** the five deterministic checks over the submission bundle.
- On pass: task → done, ledger record appended, reputation credited.
- On fail: task → failed, ledger record appended (failures are recorded too — that's the point), reputation penalized.
- An agent querying "is my task done?" gets the registry's answer, not its own.

## SOP templates (v0.1 seeds)

**`code-delivery`** (difficulty 2) — the anti-slop pack. Steps: command hygiene on
every command block · every promised artifact exists · claim inventory
well-formed, no UNVERIFIED-as-fact · secrets scan over draft and artifacts ·
manual approval required for anything touching credentials, machines, or money.

**`agent-task-standard`** (difficulty 1) — plan note · completion evidence note ·
claim grades.

**`deep-work`** (difficulty 3) — everything in code-delivery, plus artifact hash
pins on every deliverable, plus spot-check eligibility.

**Expectations** (bound to every SOP): done means verified, not claimed; evidence
beats adjectives; the registry's re-run is the verdict; exceptions must be
declared *before* the work, not discovered after.

**Exceptions**: pre-approved deviations recorded on the task before verify —
e.g. "Mac-side path, can't verify from the build environment — operator to confirm." Declared
exceptions don't fail the gate; undeclared ones do.

## Control surface

Local HTTP API on `127.0.0.1:8471` (token in `~/.watchman/token`), plus a
Manifest-V3 browser extension: registry table with live scores and tiers, task
list, submit/verify actions, quarantine badge. The extension is a *view and
remote* — all state changes still go through the registry's gate. v0.1 is
functional, not pretty.

## Threat model / honest limits

- This stops **theatrics, corner-cutting, and self-certification** — the failure
  class you've actually been hit by. It does not stop a frontier model that is
  actively, competently scheming against the registry itself; that's the AI
  control research agenda, not a local SQLite tool.
- **What halt can and cannot do (Phase 1, stated plainly).** Halt freezes
  everything the registry governs: live tasks move to `halted`, no new tasks
  can be created, and the freeze is chained with reason + actor. What it
  cannot do: reach into a model's weights, stop an agent running outside this
  registry, or revoke access the registry never granted. A halted agent that
  keeps acting through channels the registry can't see is outside the
  perimeter — the ledger records the halt, it can't enforce the universe.
- Heuristic detections (theatrics flag) are labeled as heuristics. They price a
  behavior; they don't prove intent.
- Mac-side paths can't be verified from the VM — declared as exceptions, confirmed by you.
- Secrets are never stored. The registry holds `cred_ref` (where the secret
  lives, e.g. "macOS keychain: openai-prod"), never the value. The Phase 1
  identity keys are the registry's own locally-generated keys, not
  third-party credentials — same boundary, no exception to the rule.

## Roadmap (your call on each)

**Built 2026-10-06 (Phase 1, pulled ahead):** cryptographic agent identity,
kill-switch actuator (halt/resume, operator-only CLI), incident reporter with
24-hour clock.

- v0.3: Board findings auto-ingested from `~/workspace/council/findings/` nightly.
- v0.4: per-agent preambles auto-generated from score history ("here's what this agent needs to hear").
- v0.5: checkpoint anchoring (daily head-hash to a second location).
- Later: capability-scoped execution tokens (per-action grants instead of standing access) — the natural next step after halt: per-action grants that can be revoked individually.
- Later: validator-facing read-only auditor API + exportable evidence packs (for third-party validation regimes).
