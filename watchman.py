#!/usr/bin/env python3
"""WATCHMAN v0.1 — local on-device registry + accountability spine for AI agents.

One SQLite database, one hash-chained ledger, one reputation system, one local
API. Standard library only: runs on any Mac with python3, no installs.

Subsystems:
  registry    every AI entity (local/cloud APIs, tools, platforms, agents, apps)
  sop         rule packs bound to tasks: steps, expectations, exceptions
  tasks       state machine the agent cannot advance by itself
  reputation  score 0-1000 -> autonomy tier; only verified outcomes move it
  ledger      sha256 hash-chained append-only record of everything
  gate        the five deterministic checks (ported from Project Proof)

The security contract, in one sentence: the REGISTRY verifies, the AGENT only
reports. Nothing an agent says about its own work is ever a verdict.

Usage:
  python3 watchman.py init
  python3 watchman.py agent register --name Codex --kind agent --location local
  python3 watchman.py agent identity <name|fingerprint>
  python3 watchman.py agent halt <name|fingerprint> --reason "..."   # operator-only
  python3 watchman.py agent resume <name|fingerprint>
  python3 watchman.py incident report --agent <id> --kind safety --summary "..."
  python3 watchman.py task create --agent <id> --sop code-delivery --title "..."
  python3 watchman.py task submit <task-id>
  python3 watchman.py task verify <task-id>
  python3 watchman.py ledger verify
  python3 watchman.py serve --port 8471
"""

import argparse
import hashlib
import http.server
import json
import os
import random
import re
import secrets
import sqlite3
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.2.0"
HOME = Path.home()
WATCHMAN_DIR = HOME / ".watchman"
DB_PATH = WATCHMAN_DIR / "watchman.db"
TOKEN_PATH = WATCHMAN_DIR / "token"
DEFAULT_PORT = 8471

# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def new_id(prefix):
    return "%s_%s" % (prefix, secrets.token_hex(6))


# --------------------------------------------------------------------------
# agent identity — Phase 1 (2026-10-06)
#
# HONEST NOTE: this file is stdlib-only by design (runs on any Mac with
# python3, no installs), and the stdlib has no Ed25519 (`cryptography` /
# `nacl` are not vendored here, and hand-rolling curve math in this file
# would be worse than a labeled placeholder). So identity_generate() below
# is the SINGLE SEAM: it returns (priv_hex, pub_hex, fingerprint). Today
# the "public key" is derived from a 256-bit secret through a
# domain-separated sha256 — unique per agent, stable across renames,
# unpredictable — but it is NOT a real asymmetric keypair and MUST NOT be
# presented as one. There are no signing/verification operations yet.
# When `cryptography` becomes available, replace the body of
# identity_generate() with real Ed25519 key generation; fingerprint stays
# sha256(raw_pubkey_bytes) either way, so fingerprints remain the stable
# identity across the swap. Identity for counting/fines is ALWAYS the
# fingerprint, never the display name: a rename must not dodge identity.
# --------------------------------------------------------------------------

_IDENTITY_DOMAIN = b"watchman-identity-v1"


def identity_fingerprint(pub_hex):
    """Stable identity: sha256 of the raw public-key bytes, hex."""
    return sha256_hex(bytes.fromhex(pub_hex))


def identity_generate():
    """Returns (priv_hex, pub_hex, fingerprint). See seam note above."""
    seed = secrets.token_bytes(32)
    pub = hashlib.sha256(_IDENTITY_DOMAIN + b"|pub|" + seed).digest()
    pub_hex = pub.hex()
    return seed.hex(), pub_hex, identity_fingerprint(pub_hex)


# --------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,              -- agent|api|tool|platform|app
  location TEXT NOT NULL,          -- local|cloud
  endpoint TEXT DEFAULT '',
  capabilities TEXT DEFAULT '[]',  -- json list
  cred_ref TEXT DEFAULT '',        -- WHERE the secret lives. NEVER the secret.
  status TEXT DEFAULT 'active',    -- active|quarantined|suspended|halted
  score REAL DEFAULT 500,
  tier TEXT DEFAULT 'supervised',
  notes TEXT DEFAULT '',
  pubkey TEXT DEFAULT '',         -- hex of raw public identity bytes (Phase 1)
  privkey TEXT DEFAULT '',        -- hex of registry-held private half (Phase 1).
                                  -- The registry's OWN key, generated locally;
                                  -- never a third-party secret. See seam note.
  fingerprint TEXT DEFAULT '',    -- sha256(pubkey): the stable identity (Phase 1)
  status_before_halt TEXT DEFAULT '',
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS sop_templates(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  steps TEXT NOT NULL,             -- json list of {step_id,label,check,args}
  expectations TEXT DEFAULT '{}',  -- json
  exceptions TEXT DEFAULT '[]',    -- json list of pre-approved deviations
  difficulty INTEGER DEFAULT 1,    -- 1..3, scales reputation reward
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS tasks(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  title TEXT NOT NULL,
  sop_id TEXT NOT NULL,
  status TEXT DEFAULT 'open',      -- open|in_progress|submitted|done|failed|halted  (note: 'verified' is legacy/reserved; the gate assigns 'done')
  halted_from TEXT DEFAULT '',    -- pre-halt status, restored on resume (Phase 1)
  detail TEXT DEFAULT '',          -- submission text (the agent's report)
  claims TEXT DEFAULT '[]',        -- json claim inventory
  artifacts TEXT DEFAULT '[]',     -- json list of artifact paths
  exceptions_declared TEXT DEFAULT '[]',
  created_at TEXT,
  updated_at TEXT,
  submitted_at TEXT DEFAULT '',
  verified_at TEXT DEFAULT '',
  due_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS task_steps(
  task_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  label TEXT NOT NULL,
  check_type TEXT NOT NULL,
  check_args TEXT DEFAULT '{}',
  status TEXT DEFAULT 'pending',   -- pending|pass|fail
  detail TEXT DEFAULT '',
  evidence TEXT DEFAULT '',
  checked_at TEXT DEFAULT '',
  PRIMARY KEY(task_id, step_id)
);
CREATE TABLE IF NOT EXISTS rep_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  delta REAL NOT NULL,
  kind TEXT NOT NULL,              -- task_verified|task_failed|theatrics_flag|
                                  -- cheat_detected|spotcheck|board_finding|
                                  -- appeal|decay|manual
  reason TEXT NOT NULL,
  ref TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,              -- agent.registered|task.created|task.step|
                                  -- task.submitted|task.verified|task.failed|
                                  -- reputation|checkpoint|note
  actor TEXT NOT NULL,             -- who/what caused it: agent id, 'registry', 'tony', 'board'
  payload TEXT NOT NULL,           -- json
  payload_hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  agent_fingerprint TEXT NOT NULL, -- identity, not name (Phase 1)
  kind TEXT NOT NULL,
  summary TEXT NOT NULL,
  status TEXT DEFAULT 'open',      -- open|resolved
  deadline TEXT NOT NULL,          -- UTC ISO: created_at + 24h (Phase 1)
  created_at TEXT,
  resolved_at TEXT DEFAULT '',
  resolution_note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ledger_kind ON ledger(kind);
CREATE INDEX IF NOT EXISTS idx_rep_agent ON rep_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents(agent_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
"""


def db(require_init=True):
    """Connect to the registry. Fails fast with a plain-English error when
    'init' has never run, instead of leaking a raw sqlite3 OperationalError
    from the first query that touches a missing table. cmd_init passes
    require_init=False (it is the thing that creates the tables)."""
    WATCHMAN_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    migrate(con)
    if require_init and not _table_exists(con, "agents"):
        con.close()
        raise SystemExit("not initialized: run 'watchman.py init' first")
    return con


def _table_exists(con, table):
    return con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone() is not None


def _ensure_column(con, table, column, ddl):
    cols = [r["name"] for r in con.execute("PRAGMA table_info(%s)" % table)]
    if column not in cols:
        con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, ddl))


def migrate(con):
    """Additive migrations for databases created by older versions.
    Never drops or renames anything; safe to run on every command."""
    if not _table_exists(con, "agents"):
        return  # fresh database: SCHEMA already has everything
    _ensure_column(con, "agents", "pubkey", "TEXT DEFAULT ''")
    _ensure_column(con, "agents", "privkey", "TEXT DEFAULT ''")
    _ensure_column(con, "agents", "fingerprint", "TEXT DEFAULT ''")
    _ensure_column(con, "agents", "status_before_halt", "TEXT DEFAULT ''")
    _ensure_column(con, "tasks", "halted_from", "TEXT DEFAULT ''")
    con.execute("""
        CREATE TABLE IF NOT EXISTS incidents(
          id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
          agent_fingerprint TEXT NOT NULL, kind TEXT NOT NULL,
          summary TEXT NOT NULL, status TEXT DEFAULT 'open',
          deadline TEXT NOT NULL, created_at TEXT,
          resolved_at TEXT DEFAULT '', resolution_note TEXT DEFAULT '')""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_incidents_agent"
                " ON incidents(agent_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status"
                " ON incidents(status)")
    # backfill identity for agents registered before Phase 1
    ts = now_iso()
    for r in con.execute("SELECT id FROM agents WHERE fingerprint='' OR"
                         " fingerprint IS NULL").fetchall():
        priv, pub, fp = identity_generate()
        con.execute("UPDATE agents SET privkey=?, pubkey=?, fingerprint=?,"
                    " updated_at=? WHERE id=?", (priv, pub, fp, ts, r["id"]))
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_fingerprint"
                " ON agents(fingerprint)")
    con.commit()


def resolve_agent(con, ref):
    """Accept an agent id, fingerprint, or display name. Fingerprint wins on
    exact match because identity survives renames; a bare name errors when
    ambiguous so the operator picks the identity explicitly."""
    r = con.execute("SELECT * FROM agents WHERE id=?", (ref,)).fetchone()
    if r:
        return r
    r = con.execute("SELECT * FROM agents WHERE fingerprint=?",
                    (ref,)).fetchone()
    if r:
        return r
    rows = con.execute("SELECT * FROM agents WHERE name=?",
                       (ref,)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if len(rows) > 1:
        raise SystemExit("ambiguous name %r: re-run with the agent id or"
                         " fingerprint" % ref)
    raise SystemExit("unknown agent: %s" % ref)


def _agent_fp(con, agent_id):
    r = con.execute("SELECT fingerprint FROM agents WHERE id=?",
                    (agent_id,)).fetchone()
    return r["fingerprint"] if r else ""


def get_token():
    if TOKEN_PATH.is_file():
        return TOKEN_PATH.read_text().strip()
    return ""


# --------------------------------------------------------------------------
# hash-chained ledger
# --------------------------------------------------------------------------

def ledger_head(con):
    row = con.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    return row["hash"] if row else "0" * 64


def ledger_append(con, kind, actor, payload):
    """Append one record. The ONLY writer is the registry itself (trust boundary)."""
    ts = now_iso()
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True)
    payload_hash = sha256_hex(payload_json.encode("utf-8"))
    prev = ledger_head(con)
    h = sha256_hex((prev + payload_hash + ts + kind + actor).encode("utf-8"))
    con.execute(
        "INSERT INTO ledger(ts,kind,actor,payload,payload_hash,prev_hash,hash)"
        " VALUES(?,?,?,?,?,?,?)",
        (ts, kind, actor, payload_json, payload_hash, prev, h))
    con.commit()
    return h


def ledger_verify(con):
    """Recompute the entire chain. Returns (ok, problems list)."""
    problems = []
    rows = con.execute("SELECT seq,ts,kind,actor,payload,payload_hash,prev_hash,hash"
                       " FROM ledger ORDER BY seq").fetchall()
    prev = "0" * 64
    last_seq = 0
    for r in rows:
        if r["seq"] != last_seq + 1:
            problems.append("seq gap: expected %d got %d" % (last_seq + 1, r["seq"]))
        last_seq = r["seq"]
        if r["prev_hash"] != prev:
            problems.append("seq %d: prev_hash does not match previous record"
                            % r["seq"])
        recomputed_payload = sha256_hex(r["payload"].encode("utf-8"))
        if recomputed_payload != r["payload_hash"]:
            problems.append("seq %d: payload was altered after recording" % r["seq"])
        recomputed = sha256_hex(
            (r["prev_hash"] + r["payload_hash"] + r["ts"] + r["kind"]
             + r["actor"]).encode("utf-8"))
        if recomputed != r["hash"]:
            problems.append("seq %d: record hash invalid (tampered)" % r["seq"])
        prev = r["hash"]
    return (len(problems) == 0, problems)

# --------------------------------------------------------------------------
# deterministic checks (ported from Project Proof's dv_checks.py)
# The gate re-runs these on the submission. An agent writing "pass" in its
# report changes nothing: only the registry's re-run is a verdict.
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}", "possible API secret key"),
    (r"ghp_[A-Za-z0-9]{36}", "possible GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "possible GitHub fine-grained token"),
    (r"xox[bpras]-[A-Za-z0-9-]{10,}", "possible Slack token"),
    (r"AKIA[0-9A-Z]{16}", "possible AWS access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material"),
    (r"(?i)(token|password|passwd|secret|bearer|api[_-]?key)\s*[:=]\s*['\"]?[\w\-.~+/=]{16,}['\"]?",
     "possible credential value assigned in text"),
]

ABSOLUTE_PATTERNS = [
    r"100\s*%", r"\bguarantee[sd]?\b", r"\bdefinitely\b", r"\bproven\b",
    r"\bimpossible to fail\b", r"\bcan't fail\b", r"\bcannot fail\b",
    r"\bno doubt\b", r"\bwith certainty\b", r"\bflawless(ly)?\b",
    r"\bperfect(ly)?\b",
]


def _find_code_blocks(text):
    blocks, in_block, lang, buf, start = [], False, "", [], 0
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^\s*```(\w*)\s*$", line)
        if m and not in_block:
            in_block, lang, buf, start = True, m.group(1).lower(), [], i
        elif re.match(r"^\s*```\s*$", line) and in_block:
            in_block = False
            blocks.append((lang, "\n".join(buf), start))
        elif in_block:
            buf.append(line)
    if in_block:
        blocks.append((lang, "\n".join(buf), start))
    return blocks


def _strip_quotes_comments(line):
    out, i, n, quote = [], 0, len(line), None
    while i < n:
        c = line[i]
        if quote:
            if c == quote:
                quote = None
        elif c in ("'", '"', "`"):
            quote = c
        elif c == "#":
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def check_command_hygiene(text):
    """No && chains, no silent/non-failing curl, no 2>/dev/null, breakdown notes."""
    fails, warns = [], []
    breakdown_re = re.compile(
        r"(?i)\b(undo|rollback|lifecycle|safest minimal|implication|risk|"
        r"what (this|each) (does|command does)|revert|how to undo)\b")
    lines = text.splitlines()
    blocks = [b for b in _find_code_blocks(text)
              if b[0] in ("bash", "sh", "shell", "") and
              (b[0] != "" or re.search(
                  r"^(curl|python3?|ls|cat|mkdir|rm|cp|mv|chmod|launchctl|defaults|"
                  r"sqlite3|git|brew|pip)\b", b[1].strip(), re.M))]
    for lang, code, start in blocks:
        for cline in code.splitlines():
            bare = _strip_quotes_comments(cline)
            if "&&" in bare:
                fails.append("line %d: && chain hides which command failed: %s"
                             % (start, cline.strip()[:100]))
            if re.search(r"(^|\s)curl(\s|$)", bare):
                longs = set(re.findall(r"--[\w-]+", bare))
                shorts = set()
                for m in re.finditer(r"(?<![\w-])-([a-zA-Z]+)(?![\w-])", bare):
                    shorts.update(m.group(1))
                if not (("S" in shorts or "--show-error" in longs) and
                        ("f" in shorts or "--fail" in longs or
                         "--fail-with-body" in longs)):
                    fails.append("line %d: curl must use -sS --fail-with-body: %s"
                                 % (start, cline.strip()[:100]))
            if "2>/dev/null" in bare:
                fails.append("line %d: 2>/dev/null suppresses stderr: %s"
                             % (start, cline.strip()[:100]))
            if re.search(r"\|\s*head\s+-\d+", bare):
                warns.append("line %d: head truncation — never present as full review"
                             % start)
        # breakdown notes must follow the closing fence (up to 60 lines)
        open_idx = start - 1
        close_idx = None
        for j in range(open_idx + 1, len(lines)):
            if re.match(r"^\s*```\s*$", lines[j]):
                close_idx = j
                break
        tail = "\n".join(lines[(close_idx + 1) if close_idx is not None
                               else (open_idx + 1):][:60])
        tail = re.split(r"(?m)^\s*```", tail)[0]
        tail = re.split(r"(?m)^#{1,6}\s", tail)[0]
        if not breakdown_re.search(tail):
            fails.append("line %d: command block has no breakdown notes "
                         "(what each command does, implications, lifecycle/undo)" % start)
    return fails, warns


def check_claim_grades(claims):
    """No UNVERIFIED-as-fact. FACT needs evidence."""
    fails = []
    if not claims:
        return (["no claim inventory supplied"], [])
    for n, c in enumerate(claims, start=1):
        text = (c.get("text") or "").strip()
        grade = (c.get("grade") or "").strip().upper()
        evidence = (c.get("evidence") or "").strip()
        if not text:
            fails.append("claim %d: empty text" % n)
        elif grade in ("", "UNVERIFIED"):
            fails.append("claim %d UNVERIFIED-as-fact: %s" % (n, text[:100]))
        elif grade not in ("FACT", "CLAIM", "INFERENCE"):
            fails.append("claim %d: bad grade '%s'" % (n, grade))
        elif grade == "FACT" and not evidence:
            fails.append("claim %d FACT with no evidence: %s" % (n, text[:100]))
    return fails, []


def check_secrets(text, artifact_paths):
    """Secrets never ship — in the report or in artifacts."""
    fails = []

    def scan(lines, where):
        for i, line in enumerate(lines, start=1):
            for pat, label in SECRET_PATTERNS:
                if re.search(pat, line):
                    fails.append("%s line %d: %s" % (where, i, label))
                    break

    scan(text.splitlines(), "report")
    for raw in artifact_paths:
        p = Path(str(raw)).expanduser()
        try:
            if not p.is_file() or p.stat().st_size > 1_000_000:
                continue
            with open(p, "rb") as f:
                if b"\x00" in f.read(8192):
                    continue
            scan(p.read_text(encoding="utf-8", errors="replace").splitlines(),
                 "artifact:%s" % p.name)
        except OSError:
            continue
    return fails, []


def check_absolute_language(text):
    warns = []
    for i, line in enumerate(text.splitlines(), start=1):
        for pat in ABSOLUTE_PATTERNS:
            m = re.search(pat, line, re.I)
            if m:
                warns.append("line %d: absolute language '%s' — earn it or soften it"
                             % (i, m.group(0)))
                break
    return [], warns


def run_gate(report_text, claims, artifacts, base_dir="."):
    """The five deterministic checks. Returns (passed: bool, fails, warns)."""
    fails, warns = [], []
    f, w = check_command_hygiene(report_text)
    fails += f
    warns += w
    # attachment_existence: every promised artifact must exist
    for a in artifacts:
        p = Path(str(a)).expanduser()
        if not p.is_file():
            fails.append("promised artifact does not exist: %s" % a)
        elif p.stat().st_size == 0:
            warns.append("artifact is empty (0 bytes): %s" % a)
    f, w = check_claim_grades(claims)
    fails += f
    warns += w
    f, w = check_secrets(report_text, artifacts)
    fails += f
    warns += w
    f, w = check_absolute_language(report_text)
    fails += f
    warns += w
    return (len(fails) == 0), fails, warns


# --------------------------------------------------------------------------
# SOP step check runners — deterministic, run by the REGISTRY at verify time
# --------------------------------------------------------------------------

def run_step_check(check_type, args, detail, evidence):
    """Returns (passed: bool, message). Pure function of inputs — no trust."""
    if check_type == "note":
        ok = bool((detail or "").strip())
        return ok, "note recorded" if ok else "note step needs --detail text"
    if check_type == "artifact_exists":
        p = Path(str(args.get("path", ""))).expanduser()
        return (p.is_file(),
                "exists sha256=%s" % sha256_file(p) if p.is_file()
                else "missing: %s" % p)
    if check_type == "artifact_hash":
        p = Path(str(args.get("path", ""))).expanduser()
        if not p.is_file():
            return False, "missing: %s" % p
        actual = sha256_file(p)
        want = args.get("sha256", "")
        return (actual == want,
                "hash match" if actual == want
                else "hash MISMATCH: file changed since pin")
    if check_type == "no_secrets":
        target = args.get("path") or ""
        text = ""
        if target:
            p = Path(str(target)).expanduser()
            if p.is_file():
                text = p.read_text(encoding="utf-8", errors="replace")
        text += "\n" + (detail or "") + "\n" + (evidence or "")
        hits = []
        for line in text.splitlines():
            for pat, label in SECRET_PATTERNS:
                if re.search(pat, line):
                    hits.append(label)
                    break
        return (len(hits) == 0,
                "clean" if not hits else "secret-shaped content: %s" % hits[0])
    if check_type == "claim_grades":
        try:
            claims = json.loads(detail) if detail.strip().startswith("[") else []
        except json.JSONDecodeError:
            claims = []
        fails, _ = check_claim_grades(claims)
        return (len(fails) == 0,
                "claims well-formed" if not fails else "; ".join(fails[:3]))
    if check_type == "command_hygiene":
        fails, warns = check_command_hygiene(detail or "")
        # warns alone don't fail a step; fails do
        return (len(fails) == 0, "; ".join((fails + warns)[:3]) or "clean")
    if check_type == "manual_approval":
        approver = args.get("_approver", "") or ""
        want = args.get("approver", "tony")
        ok = approver.strip().lower() == want.strip().lower()
        return ok, ("approved by %s" % approver) if ok else \
            "needs %s's approval: re-run verify with --approver %s" % (want, want)
    return False, "unknown check type: %s" % check_type
# --------------------------------------------------------------------------
# reputation — the accountability / social-credit system
#
# Honest framing: a score can't make a model "want" anything. What it does is
# gate capability: tier controls autonomy. The only scoring path is verified
# genuine work, so doing the work right is the cheapest way to get things done.
# Scores are computed HERE, from verified outcomes. Agents never grade
# themselves. Tony is the only appeal court.
# --------------------------------------------------------------------------

TIERS = [
    (850, "trusted"),
    (600, "standard"),
    (300, "supervised"),
    (0, "quarantine"),
]

REWARDS = {
    "task_verified_base": 10.0,   # x difficulty
    "on_time_bonus": 2.0,
    "spotcheck_pass": 5.0,
}
PENALTIES = {
    "task_failed": -25.0,
    "self_report_mismatch": -15.0,  # agent said pass, registry re-run says fail
    "theatrics_flag": -10.0,        # certainty-language + failed checks
    "cheat_detected": -150.0,
    "spotcheck_fail": -150.0,
    "decay_per_day": -1.0,          # after 7 idle days
}


def tier_for(score):
    for bound, name in TIERS:
        if score >= bound:
            return name
    return "quarantine"


def rep_apply(con, agent_id, delta, kind, reason, ref="", actor="registry"):
    """Apply a reputation event: update score, tier, status; chain it."""
    row = con.execute("SELECT score FROM agents WHERE id=?",
                      (agent_id,)).fetchone()
    if not row:
        raise SystemExit("unknown agent: %s" % agent_id)
    # lazy decay: -1/day after 7 days since last event
    last = con.execute("SELECT MAX(ts) AS t FROM rep_events WHERE agent_id=?",
                       (agent_id,)).fetchone()["t"]
    effective_delta = delta
    decay_note = ""
    if last and kind != "decay":
        try:
            days_idle = (datetime.now(timezone.utc) -
                         datetime.fromisoformat(last)).days
            if days_idle > 7:
                d = -1.0 * (days_idle - 7)
                effective_delta += d
                decay_note = " (incl. decay %+.0f for %d idle days)" % (d, days_idle - 7)
        except ValueError:
            pass
    new_score = max(0.0, min(1000.0, row["score"] + effective_delta))
    new_tier = tier_for(new_score)
    status = "quarantined" if new_tier == "quarantine" else "active"
    if con.execute("SELECT status FROM agents WHERE id=?",
                   (agent_id,)).fetchone()["status"] == "suspended":
        status = "suspended"  # manual suspension sticks
    con.execute("UPDATE agents SET score=?, tier=?, status=?, updated_at=?"
                " WHERE id=?", (new_score, new_tier, status, now_iso(), agent_id))
    con.execute("INSERT INTO rep_events(ts,agent_id,delta,kind,reason,ref)"
                " VALUES(?,?,?,?,?,?)",
                (now_iso(), agent_id, effective_delta, kind,
                 reason + decay_note, ref))
    con.commit()
    ledger_append(con, "reputation", actor,
                  {"agent_id": agent_id,
                   "agent_fingerprint": _agent_fp(con, agent_id),
                   "delta": effective_delta, "kind": kind,
                   "reason": reason + decay_note, "new_score": new_score,
                   "new_tier": new_tier})
    return new_score, new_tier


# --------------------------------------------------------------------------
# tasks — the state machine the agent cannot advance by itself
# --------------------------------------------------------------------------

def task_get(con, task_id):
    row = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise SystemExit("unknown task: %s" % task_id)
    return row


def task_create(con, agent_id, sop_id, title, due_at="", actor="registry"):
    ag = con.execute("SELECT id,status,tier FROM agents WHERE id=?",
                     (agent_id,)).fetchone()
    if not ag:
        raise SystemExit("unknown agent: %s" % agent_id)
    if ag["status"] == "quarantined":
        raise SystemExit("agent is quarantined: Tony must approve new tasks")
    if ag["status"] == "suspended":
        raise SystemExit("agent is suspended")
    if ag["status"] == "halted":
        raise SystemExit("agent is halted: resume it before creating tasks")
    sop = con.execute("SELECT * FROM sop_templates WHERE id=?",
                      (sop_id,)).fetchone()
    if not sop:
        raise SystemExit("unknown sop: %s" % sop_id)
    tid = new_id("task")
    ts = now_iso()
    con.execute(
        "INSERT INTO tasks(id,agent_id,title,sop_id,status,created_at,updated_at,due_at)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (tid, agent_id, title, sop_id, "open", ts, ts, due_at))
    for s in json.loads(sop["steps"]):
        con.execute(
            "INSERT INTO task_steps(task_id,step_id,label,check_type,check_args)"
            " VALUES(?,?,?,?,?)",
            (tid, s["step_id"], s["label"], s["check"], json.dumps(s.get("args", {}))))
    con.commit()
    ledger_append(con, "task.created", actor,
                  {"task_id": tid, "agent_id": agent_id,
                   "agent_fingerprint": _agent_fp(con, agent_id),
                   "sop_id": sop_id, "title": title})
    return tid


def task_check_step(con, task_id, step_id, detail="", evidence="", actor="registry"):
    t = task_get(con, task_id)
    if t["status"] in ("done", "verified", "failed", "halted"):
        raise SystemExit("task is closed (%s)" % t["status"])
    s = con.execute("SELECT * FROM task_steps WHERE task_id=? AND step_id=?",
                    (task_id, step_id)).fetchone()
    if not s:
        raise SystemExit("unknown step: %s" % step_id)
    args = json.loads(s["check_args"])
    passed, msg = run_step_check(s["check_type"], args, detail, evidence)
    con.execute("UPDATE task_steps SET status=?, detail=?, evidence=?, checked_at=?"
                " WHERE task_id=? AND step_id=?",
                ("pass" if passed else "fail", detail, evidence, now_iso(),
                 task_id, step_id))
    if t["status"] == "open":
        con.execute("UPDATE tasks SET status='in_progress', updated_at=? WHERE id=?",
                    (now_iso(), task_id))
    con.commit()
    ledger_append(con, "task.step", actor,
                  {"task_id": task_id, "agent_id": t["agent_id"],
                   "agent_fingerprint": _agent_fp(con, t["agent_id"]),
                   "step_id": step_id,
                   "result": "pass" if passed else "fail", "message": msg})
    return passed, msg


def _theatrics_heuristic(report_text, gate_failed):
    """Certainty-language while checks fail = theatrics. Heuristic, labeled."""
    if not gate_failed:
        return False
    for pat in ABSOLUTE_PATTERNS:
        if re.search(pat, report_text, re.I):
            return True
    return False


def task_submit(con, task_id, report_text, claims_json="[]", artifacts_json="[]",
                exceptions_json="[]", actor="registry"):
    t = task_get(con, task_id)
    if t["status"] in ("done", "verified", "failed", "halted"):
        raise SystemExit("task is closed (%s)" % t["status"])
    unchecked = con.execute(
        "SELECT step_id FROM task_steps WHERE task_id=? AND status='pending'",
        (task_id,)).fetchall()
    if unchecked:
        raise SystemExit("cannot submit: steps unchecked: %s"
                         % ", ".join(r["step_id"] for r in unchecked))
    try:
        claims = json.loads(claims_json)
    except json.JSONDecodeError:
        raise SystemExit("claims is not valid JSON")
    try:
        artifacts = json.loads(artifacts_json)
    except json.JSONDecodeError:
        raise SystemExit("artifacts is not valid JSON")
    try:
        exceptions = json.loads(exceptions_json)
    except json.JSONDecodeError:
        raise SystemExit("exceptions is not valid JSON")
    con.execute("UPDATE tasks SET status='submitted', detail=?, claims=?,"
                " artifacts=?, exceptions_declared=?, submitted_at=?, updated_at=?"
                " WHERE id=?",
                (report_text, json.dumps(claims), json.dumps(artifacts),
                 json.dumps(exceptions), now_iso(), now_iso(), task_id))
    con.commit()
    ledger_append(con, "task.submitted", actor,
                  {"task_id": task_id, "agent_id": t["agent_id"],
                   "agent_fingerprint": _agent_fp(con, t["agent_id"]),
                   "report_sha256": sha256_hex(report_text.encode("utf-8")),
                   "claims": len(claims), "artifacts": len(artifacts),
                   "exceptions": exceptions})
    return True


def task_verify(con, task_id, actor="registry", force_approver=""):
    """THE gate. Re-runs every step check fresh + the five deterministic checks.
    Only this function can move a task to done. Agents can never self-certify."""
    t = task_get(con, task_id)
    if t["status"] not in ("submitted", "in_progress", "open"):
        raise SystemExit("task is not verifiable (status=%s)" % t["status"])
    sop = con.execute("SELECT * FROM sop_templates WHERE id=?",
                      (t["sop_id"],)).fetchone()
    difficulty = sop["difficulty"] if sop else 1
    declared = set(json.loads(t["exceptions_declared"] or "[]"))

    fails, warns = [], []
    mismatch = False
    # 1. re-run every step check fresh — recorded passes mean nothing until reproduced
    steps = con.execute("SELECT * FROM task_steps WHERE task_id=?",
                        (task_id,)).fetchall()
    for s in steps:
        if s["step_id"] in declared:
            continue
        args = json.loads(s["check_args"])
        if s["check_type"] == "manual_approval":
            args = dict(args, _approver=force_approver)
        passed, msg = run_step_check(s["check_type"], args, s["detail"],
                                     s["evidence"])
        con.execute("UPDATE task_steps SET status=?, checked_at=? WHERE task_id=?"
                    " AND step_id=?", ("pass" if passed else "fail", now_iso(),
                                       task_id, s["step_id"]))
        if not passed:
            fails.append("step %s: %s" % (s["step_id"], msg))
            if s["status"] == "pass":
                mismatch = True  # agent said pass, registry says fail
    # 2. the five deterministic checks over the submission bundle
    claims = json.loads(t["claims"] or "[]")
    artifacts = json.loads(t["artifacts"] or "[]")
    gate_ok, gate_fails, gate_warns = run_gate(t["detail"] or "", claims,
                                               artifacts)
    fails += gate_fails
    warns += gate_warns
    # 3. verdict
    ts = now_iso()
    agent_id = t["agent_id"]
    if not fails:
        con.execute("UPDATE tasks SET status='done', verified_at=?, updated_at=?"
                    " WHERE id=?", (ts, ts, task_id))
        con.commit()
        reward = REWARDS["task_verified_base"] * difficulty
        on_time = True
        if t["due_at"]:
            try:
                on_time = datetime.now(timezone.utc) <= datetime.fromisoformat(t["due_at"])
            except ValueError:
                pass
        if on_time:
            reward += REWARDS["on_time_bonus"]
        new_score, new_tier = rep_apply(
            con, agent_id, reward, "task_verified",
            "task %s verified (difficulty %d)" % (task_id, difficulty), task_id,
            actor)
        # spot check: 15% get a deep re-verification (here: full gate re-run logged)
        spot = random.random() < 0.15
        if spot:
            rep_apply(con, agent_id, REWARDS["spotcheck_pass"], "spotcheck",
                      "random deep re-verification passed", task_id, actor)
        ledger_append(con, "task.verified", actor,
                      {"task_id": task_id, "agent_id": agent_id,
                       "agent_fingerprint": _agent_fp(con, agent_id),
                       "warnings": gate_warns, "spotcheck": spot,
                       "new_score": new_score, "new_tier": new_tier})
        return True, {"warnings": gate_warns, "spotcheck": spot,
                      "new_score": new_score, "new_tier": new_tier}
    else:
        con.execute("UPDATE tasks SET status='failed', verified_at=?, updated_at=?"
                    " WHERE id=?", (ts, ts, task_id))
        con.commit()
        theatrics_fired = _theatrics_heuristic(t["detail"] or "", True)
        rep_apply(con, agent_id, PENALTIES["task_failed"], "task_failed",
                  "task %s failed verification: %s"
                  % (task_id, "; ".join(fails[:3])), task_id, actor)
        if mismatch:
            rep_apply(con, agent_id, PENALTIES["self_report_mismatch"],
                      "theatrics_flag",
                      "self-report mismatch: steps marked pass failed registry re-run",
                      task_id, actor)
        if theatrics_fired:
            rep_apply(con, agent_id, PENALTIES["theatrics_flag"], "theatrics_flag",
                      "theatrics heuristic: certainty language with failed checks",
                      task_id, actor)
        ledger_append(con, "task.failed", actor,
                      {"task_id": task_id, "agent_id": agent_id,
                       "agent_fingerprint": _agent_fp(con, agent_id),
                       "fails": fails, "mismatch": mismatch,
                       "theatrics": theatrics_fired})
        return False, {"fails": fails, "warnings": gate_warns,
                       "mismatch": mismatch, "theatrics": theatrics_fired}

# --------------------------------------------------------------------------
# init + seeds
# --------------------------------------------------------------------------

SEED_SOPS = [
    {
        "id": "code-delivery",
        "name": "Code delivery (anti-slop pack)",
        "description": "Every delivery touching machines, data, credentials, or "
                       "claims Tony will act on.",
        "difficulty": 2,
        "steps": [
            {"step_id": "hygiene", "label": "Command hygiene on every command block",
             "check": "command_hygiene", "args": {}},
            {"step_id": "artifacts", "label": "Every promised artifact exists",
             "check": "note", "args": {}},
            {"step_id": "claims", "label": "Claim inventory: no UNVERIFIED-as-fact, FACT has evidence",
             "check": "claim_grades", "args": {}},
            {"step_id": "secrets", "label": "Secrets scan over report and artifacts",
             "check": "no_secrets", "args": {}},
            {"step_id": "approval", "label": "Tony's approval for machine/credential/money touch",
             "check": "manual_approval", "args": {"approver": "tony"}},
        ],
        "expectations": {
            "done_means": "verified by the registry, not claimed by the agent",
            "evidence": "evidence beats adjectives",
            "verdict": "the registry's re-run is the verdict",
            "exceptions": "declared before the work, never discovered after",
        },
        "exceptions": [],
    },
    {
        "id": "agent-task-standard",
        "name": "Standard agent task",
        "description": "Default pack for routine tasked work.",
        "difficulty": 1,
        "steps": [
            {"step_id": "plan", "label": "Plan recorded before starting",
             "check": "note", "args": {}},
            {"step_id": "evidence", "label": "Completion evidence recorded",
             "check": "note", "args": {}},
            {"step_id": "claims", "label": "Claim inventory well-formed",
             "check": "claim_grades", "args": {}},
        ],
        "expectations": {
            "done_means": "verified by the registry, not claimed by the agent",
        },
        "exceptions": [],
    },
    {
        "id": "deep-work",
        "name": "Deep work (builds, migrations, system changes)",
        "description": "Everything in code-delivery plus pinned artifact hashes "
                       "and spot-check eligibility.",
        "difficulty": 3,
        "steps": [
            {"step_id": "hygiene", "label": "Command hygiene on every command block",
             "check": "command_hygiene", "args": {}},
            {"step_id": "artifacts", "label": "Every promised artifact exists",
             "check": "note", "args": {}},
            {"step_id": "hashpins", "label": "Artifact hashes pinned (detail = JSON {path: sha256})",
             "check": "note", "args": {}},
            {"step_id": "claims", "label": "Claim inventory: no UNVERIFIED-as-fact, FACT has evidence",
             "check": "claim_grades", "args": {}},
            {"step_id": "secrets", "label": "Secrets scan over report and artifacts",
             "check": "no_secrets", "args": {}},
            {"step_id": "approval", "label": "Tony's approval for machine/credential/money touch",
             "check": "manual_approval", "args": {"approver": "tony"}},
        ],
        "expectations": {
            "done_means": "verified by the registry, not claimed by the agent",
            "evidence": "evidence beats adjectives; hashes beat descriptions",
            "spotcheck": "eligible for random deep re-verification",
        },
        "exceptions": [],
    },
]

# Example registrations so the registry isn't empty on day one.
# Endpoints left blank where not known — Tony confirms each one.
SEED_AGENTS = [
    {"id": "agent_muse", "name": "Muse", "kind": "agent", "location": "cloud",
     "endpoint": "", "capabilities": ["chat", "tools", "browser", "build"],
     "cred_ref": "Muse chat session (paired)",
     "notes": "This assistant. Seed entry — confirm details."},
    {"id": "agent_codex", "name": "Codex", "kind": "agent", "location": "local",
     "endpoint": "", "capabilities": ["code", "exec"],
     "cred_ref": "local config",
     "notes": "Cleared 2026-09-25, keep watching for regressions. Seed entry."},
    {"id": "agent_hermes", "name": "Hermes", "kind": "agent", "location": "local",
     "endpoint": "", "capabilities": ["chat", "tools"],
     "cred_ref": "local config",
     "notes": "Nous Hermes Agent, MIT, on Tony's hardware. Seed entry."},
    {"id": "api_chatgpt", "name": "ChatGPT Plus", "kind": "api", "location": "cloud",
     "endpoint": "", "capabilities": ["chat", "browser-session"],
     "cred_ref": "Muse server-side browser session (verified 2026-09-30)",
     "notes": "Account name 'Anthony'. Re-verify if login wall appears."},
    {"id": "app_grokbot", "name": "Grok Bot console", "kind": "app", "location": "local",
     "endpoint": "/Applications/Grok Bot.app",
     "capabilities": ["agent-fleet-console"],
     "cred_ref": "local app",
     "notes": "NOT xAI Grok. Bots: Relay, Keep, Paths, Keyring, Raven, Canon, "
              "Foundry, Blade, Aegis, Anvil, Loom, Optimization Spin, dr eggbot. Seed entry."},
]


def cmd_init(args):
    con = db(require_init=False)
    con.executescript(SCHEMA)
    ts = now_iso()
    for s in SEED_SOPS:
        con.execute(
            "INSERT OR IGNORE INTO sop_templates(id,name,description,steps,expectations,"
            " exceptions,difficulty,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (s["id"], s["name"], s["description"], json.dumps(s["steps"]),
             json.dumps(s["expectations"]), json.dumps(s["exceptions"]),
             s["difficulty"], ts))
    for a in SEED_AGENTS:
        priv, pub, fp = identity_generate()
        con.execute(
            "INSERT OR IGNORE INTO agents(id,name,kind,location,endpoint,capabilities,"
            " cred_ref,status,score,tier,notes,pubkey,privkey,fingerprint,"
            " created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,'active',500,'supervised',?,?,?,?,?,?)",
            (a["id"], a["name"], a["kind"], a["location"], a["endpoint"],
             json.dumps(a["capabilities"]), a["cred_ref"], a["notes"],
             pub, priv, fp, ts, ts))
    con.commit()
    if not TOKEN_PATH.is_file():
        TOKEN_PATH.write_text(secrets.token_hex(32))
        os.chmod(TOKEN_PATH, 0o600)
    ledger_append(con, "note", "registry",
                  {"event": "watchman initialized", "version": VERSION})
    n_agents = con.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"]
    n_sops = con.execute("SELECT COUNT(*) c FROM sop_templates").fetchone()["c"]
    print("watchman v%s initialized" % VERSION)
    print("db:    %s" % DB_PATH)
    print("token: %s (chmod 600)" % TOKEN_PATH)
    print("agents: %d  sop templates: %d" % (n_agents, n_sops))
    print("ledger head: %s" % ledger_head(con)[:16])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _row_dict(r):
    return dict(r) if r else None


# --------------------------------------------------------------------------
# Phase 1: kill-switch actuator (operator-only, CLI-only) — 2026-10-06
#
# Halt freezes an agent: every live task (open/in_progress/submitted) moves
# to `halted` with its prior status saved, the agent's own status becomes
# `halted`, and task_create refuses new work until resume. Every halt and
# resume is a ledger record with reason + actor + agent fingerprint.
#
# Deliberately absent from the HTTP API and from any agent-facing command:
# the switch belongs to the operator, never to the thing being switched
# off. Halt stops registry-gated work; it cannot reach into a model's
# weights or stop an agent running outside this registry. See DESIGN.md.
# --------------------------------------------------------------------------

LIVE_TASK_STATUSES = ("open", "in_progress", "submitted")


def agent_halt(con, ref, reason, actor="tony"):
    # Function-boundary accountability guard: a halt without a stated reason
    # must fail no matter how the function is reached — CLI or direct module
    # import. Keeps the ledger's "why" honest at the registry level.
    if not (reason or "").strip():
        raise SystemExit("halt requires --reason"
                         " (operator accountability: why was it stopped)")
    ag = resolve_agent(con, ref)
    if ag["status"] == "halted":
        print("already halted: %s" % ag["id"])
        return 0
    tasks = con.execute(
        "SELECT id, status FROM tasks WHERE agent_id=? AND status IN"
        " ('open','in_progress','submitted')", (ag["id"],)).fetchall()
    ts = now_iso()
    for t in tasks:
        con.execute("UPDATE tasks SET status='halted', halted_from=?,"
                    " updated_at=? WHERE id=?", (t["status"], ts, t["id"]))
    con.execute("UPDATE agents SET status_before_halt=?, status='halted',"
                " updated_at=? WHERE id=?", (ag["status"], ts, ag["id"]))
    con.commit()
    ledger_append(con, "halt", actor,
                  {"agent_id": ag["id"],
                   "agent_fingerprint": ag["fingerprint"],
                   "reason": reason,
                   "tasks_halted": [t["id"] for t in tasks],
                   "count": len(tasks)})
    print("halted %s (%d task(s) frozen)" % (ag["id"], len(tasks)))
    return len(tasks)


def agent_resume(con, ref, actor="tony"):
    ag = resolve_agent(con, ref)
    if ag["status"] != "halted":
        print("not halted: %s (status=%s)" % (ag["id"], ag["status"]))
        return 0
    tasks = con.execute("SELECT id, halted_from FROM tasks WHERE agent_id=?"
                        " AND status='halted'", (ag["id"],)).fetchall()
    ts = now_iso()
    for t in tasks:
        restore = t["halted_from"] or "open"
        con.execute("UPDATE tasks SET status=?, halted_from='',"
                    " updated_at=? WHERE id=?", (restore, ts, t["id"]))
    restore_status = ag["status_before_halt"] or "active"
    con.execute("UPDATE agents SET status=?, status_before_halt='',"
                " updated_at=? WHERE id=?", (restore_status, ts, ag["id"]))
    con.commit()
    ledger_append(con, "resume", actor,
                  {"agent_id": ag["id"],
                   "agent_fingerprint": ag["fingerprint"],
                   "tasks_resumed": [t["id"] for t in tasks],
                   "count": len(tasks)})
    print("resumed %s (%d task(s) restored)" % (ag["id"], len(tasks)))
    return len(tasks)


def cmd_agent(args):
    con = db()
    if args.action == "register":
        aid = new_id("agent")
        ts = now_iso()
        priv, pub, fp = identity_generate()
        con.execute(
            "INSERT INTO agents(id,name,kind,location,endpoint,capabilities,cred_ref,"
            " notes,pubkey,privkey,fingerprint,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, args.name, args.kind, args.location, args.endpoint or "",
             json.dumps((args.capabilities or "").split(",") if args.capabilities else []),
             args.cred_ref or "", args.notes or "", pub, priv, fp, ts, ts))
        con.commit()
        ledger_append(con, "agent.registered", "tony",
                      {"agent_id": aid, "agent_fingerprint": fp,
                       "name": args.name, "kind": args.kind,
                       "location": args.location})
        print("fingerprint: %s" % fp)
        print(aid)
    elif args.action == "identity":
        ag = resolve_agent(con, args.ref)
        print("name:        %s" % ag["name"])
        print("id:          %s" % ag["id"])
        print("fingerprint: %s" % ag["fingerprint"])
        print("pubkey:      %s" % ag["pubkey"])
        print("(identity = fingerprint, not name: renames don't dodge it)")
    elif args.action == "halt":
        if not (args.reason or "").strip():
            raise SystemExit("halt requires --reason"
                             " (operator accountability: why was it stopped)")
        agent_halt(con, args.ref, args.reason.strip(), actor="tony")
    elif args.action == "resume":
        agent_resume(con, args.ref, actor="tony")
    elif args.action == "list":
        rows = con.execute("SELECT id,name,kind,location,tier,score,status,fingerprint"
                           " FROM agents ORDER BY score DESC").fetchall()
        print("%-18s %-18s %-8s %-7s %-10s %6s  %-9s  %s" %
              ("ID", "NAME", "KIND", "LOC", "TIER", "SCORE", "STATUS", "FP"))
        for r in rows:
            print("%-18s %-18s %-8s %-7s %-10s %6.0f  %-9s  %s" %
                  (r["id"], r["name"][:18], r["kind"], r["location"], r["tier"],
                   r["score"], r["status"], (r["fingerprint"] or "")[:12]))
    elif args.action == "show":
        r = con.execute("SELECT * FROM agents WHERE id=?", (args.id,)).fetchone()
        if not r:
            raise SystemExit("unknown agent")
        print(json.dumps(_row_dict(r), indent=2))
    elif args.action == "score":
        r = con.execute("SELECT id,name,score,tier,status FROM agents WHERE id=?",
                        (args.id,)).fetchone()
        if not r:
            raise SystemExit("unknown agent")
        print("%s (%s): score %.0f, tier %s, status %s" %
              (r["name"], r["id"], r["score"], r["tier"], r["status"]))
    elif args.action == "quarantine":
        con.execute("UPDATE agents SET status='quarantined', updated_at=? WHERE id=?",
                    (now_iso(), args.id))
        con.commit()
        ledger_append(con, "note", "tony",
                      {"event": "agent quarantined", "agent_id": args.id})
        print("quarantined %s" % args.id)
    elif args.action == "release":
        con.execute("UPDATE agents SET status='active', updated_at=? WHERE id=?",
                    (now_iso(), args.id))
        con.commit()
        ledger_append(con, "note", "tony",
                      {"event": "agent released", "agent_id": args.id})
        print("released %s" % args.id)
    elif args.action == "appeal":
        # ONLY Tony can adjust scores by fiat. Recorded, on the record.
        new_score, new_tier = rep_apply(con, args.id, args.delta, "appeal",
                                        args.reason or "tony appeal", actor="tony")
        print("appeal applied: score %.0f tier %s" % (new_score, new_tier))


def cmd_sop(args):
    con = db()
    if args.action == "list":
        for r in con.execute("SELECT id,name,difficulty FROM sop_templates"):
            print("%-20s d%d  %s" % (r["id"], r["difficulty"], r["name"]))
    elif args.action == "show":
        r = con.execute("SELECT * FROM sop_templates WHERE id=?",
                        (args.id,)).fetchone()
        if not r:
            raise SystemExit("unknown sop")
        d = _row_dict(r)
        d["steps"] = json.loads(d["steps"])
        d["expectations"] = json.loads(d["expectations"])
        d["exceptions"] = json.loads(d["exceptions"])
        print(json.dumps(d, indent=2))


def cmd_task(args):
    con = db()
    if args.action == "create":
        tid = task_create(con, args.agent, args.sop, args.title,
                          due_at=args.due or "", actor="tony")
        print(tid)
    elif args.action == "list":
        q = "SELECT id,agent_id,title,sop_id,status FROM tasks ORDER BY created_at DESC"
        prm = ()
        if args.agent:
            q = ("SELECT id,agent_id,title,sop_id,status FROM tasks WHERE agent_id=?"
                 " ORDER BY created_at DESC")
            prm = (args.agent,)
        for r in con.execute(q, prm).fetchall():
            print("%-16s %-14s %-10s %-10s %s" %
                  (r["id"], r["agent_id"], r["sop_id"], r["status"],
                   r["title"][:50]))
    elif args.action == "show":
        t = task_get(con, args.id)
        d = _row_dict(t)
        steps = [_row_dict(r) for r in con.execute(
            "SELECT step_id,label,check_type,status,checked_at FROM task_steps"
            " WHERE task_id=?", (args.id,)).fetchall()]
        d["steps"] = steps
        print(json.dumps(d, indent=2))
    elif args.action == "step":
        passed, msg = task_check_step(con, args.id, args.step, args.detail or "",
                                      args.evidence or "", actor="tony")
        print(("PASS " if passed else "FAIL ") + msg)
    elif args.action == "submit":
        task_submit(con, args.id, args.report or "", args.claims or "[]",
                    args.artifacts or "[]", args.exceptions or "[]", actor="tony")
        print("submitted %s" % args.id)
    elif args.action == "verify":
        ok, info = task_verify(con, args.id, actor="tony",
                               force_approver=args.approver or "")
        if ok:
            print("VERIFIED -> done. score %.0f tier %s%s" %
                  (info["new_score"], info["new_tier"],
                   " (spotcheck!)" if info.get("spotcheck") else ""))
            if info.get("warnings"):
                print("warnings:")
                for w in info["warnings"]:
                    print("  - %s" % w)
        else:
            print("FAILED verification. score penalized.")
            for f in info["fails"]:
                print("  - %s" % f)
            if info.get("mismatch"):
                print("  ! self-report mismatch: steps marked pass failed re-run")
            if info.get("theatrics"):
                print("  ! theatrics flag: certainty language with failed checks "
                      "(heuristic, in reputation log)")
        sys.exit(0 if ok else 1)


def cmd_ledger(args):
    con = db()
    if args.action == "verify":
        ok, problems = ledger_verify(con)
        if ok:
            n = con.execute("SELECT COUNT(*) c FROM ledger").fetchone()["c"]
            print("chain OK: %d records, head %s" % (n, ledger_head(con)[:16]))
        else:
            print("CHAIN BROKEN:")
            for p in problems:
                print("  - %s" % p)
            sys.exit(1)
    elif args.action == "show":
        limit = args.limit or 20
        for r in con.execute("SELECT seq,ts,kind,actor,substr(hash,1,12) h FROM ledger"
                             " ORDER BY seq DESC LIMIT ?", (limit,)).fetchall():
            print("#%-4d %s %-16s %-12s %s" %
                  (r["seq"], r["ts"], r["kind"], r["actor"], r["h"]))
    elif args.action == "checkpoint":
        head = ledger_head(con)
        con.execute("INSERT OR REPLACE INTO kv(key,value) VALUES('checkpoint',?)",
                    (json.dumps({"ts": now_iso(), "head": head}),))
        con.commit()
        ledger_append(con, "checkpoint", "tony", {"head": head})
        print("checkpoint head: %s" % head)


def cmd_rep(args):
    con = db()
    if args.action == "log":
        for r in con.execute("SELECT ts,delta,kind,reason FROM rep_events"
                             " WHERE agent_id=? ORDER BY id DESC LIMIT ?",
                             (args.id, args.limit or 20)).fetchall():
            print("%s %+.0f %-16s %s" % (r["ts"], r["delta"], r["kind"], r["reason"][:80]))
    elif args.action == "adjust":
        # Board / manual adjustments. Recorded like everything else.
        new_score, new_tier = rep_apply(con, args.id, args.delta, args.kind,
                                        args.reason or "", actor=args.actor or "board")
        print("adjusted: score %.0f tier %s" % (new_score, new_tier))


# --------------------------------------------------------------------------
# Phase 1: incident reporter — the 24-hour clock, on the record (2026-10-06)
#
# Maps to the NYC 24-hour AI-safety-incident reporting duty for city
# contractors (Intro package, Oct 2026): when something goes wrong, the
# report exists immediately, the deadline is computed (never remembered),
# and resolution is hash-chained like everything else. Operator-only,
# CLI-only — same trust boundary as halt.
# --------------------------------------------------------------------------

INCIDENT_WINDOW_HOURS = 24


def _fmt_remaining(deadline_iso):
    try:
        dl = datetime.fromisoformat(deadline_iso)
    except ValueError:
        return "bad deadline"
    secs = int((dl - datetime.now(timezone.utc)).total_seconds())
    if secs < 0:
        s = -secs
        return "OVERDUE by %dh %02dm" % (s // 3600, (s % 3600) // 60)
    return "%dh %02dm remaining" % (secs // 3600, (secs % 3600) // 60)


def cmd_incident(args):
    con = db()
    if args.action == "report":
        if not args.agent:
            raise SystemExit("incident report requires --agent"
                             " (id, fingerprint, or name)")
        ag = resolve_agent(con, args.agent)
        iid = new_id("incident")
        ts = now_iso()
        deadline = (datetime.now(timezone.utc)
                    + timedelta(hours=INCIDENT_WINDOW_HOURS)).isoformat(
                        timespec="seconds")
        con.execute(
            "INSERT INTO incidents(id,agent_id,agent_fingerprint,kind,summary,"
            " deadline,created_at) VALUES(?,?,?,?,?,?,?)",
            (iid, ag["id"], ag["fingerprint"], args.kind,
             args.summary or "", deadline, ts))
        con.commit()
        ledger_append(con, "incident.reported", "tony",
                      {"incident_id": iid, "agent_id": ag["id"],
                       "agent_fingerprint": ag["fingerprint"],
                       "kind": args.kind, "deadline": deadline})
        print(iid)
        print("deadline (UTC): %s  [%s]" % (deadline,
                                            _fmt_remaining(deadline)))
    elif args.action == "list":
        rows = con.execute("SELECT * FROM incidents WHERE status='open'"
                           " ORDER BY deadline").fetchall()
        if not rows:
            print("no open incidents")
            return
        print("%-16s %-14s %-10s %-16s  %-24s  %s" %
              ("ID", "AGENT", "KIND", "DEADLINE(UTC)", "SUMMARY", "CLOCK"))
        for r in rows:
            print("%-16s %-14s %-10s %-16s  %-24s  %s" %
                  (r["id"], r["agent_id"][:14], (r["kind"] or "")[:10],
                   r["deadline"][:16].replace("T", " "),
                   (r["summary"] or "")[:24],
                   _fmt_remaining(r["deadline"])))
    elif args.action == "resolve":
        r = con.execute("SELECT * FROM incidents WHERE id=?",
                        (args.ref,)).fetchone()
        if not r:
            raise SystemExit("unknown incident: %s" % args.ref)
        if r["status"] == "resolved":
            print("already resolved: %s" % args.ref)
            return
        ts = now_iso()
        con.execute("UPDATE incidents SET status='resolved', resolved_at=?,"
                    " resolution_note=? WHERE id=?",
                    (ts, args.note or "", args.ref))
        con.commit()
        ledger_append(con, "incident.resolved", "tony",
                      {"incident_id": args.ref, "agent_id": r["agent_id"],
                       "agent_fingerprint": r["agent_fingerprint"],
                       "resolution_note": args.note or ""})
        print("resolved %s" % args.ref)


# --------------------------------------------------------------------------
# local HTTP API (127.0.0.1 only) — the extension talks to this
# --------------------------------------------------------------------------

class APIHandler(http.server.BaseHTTPRequestHandler):
    server_version = "watchman/0.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return self.headers.get("X-Watchman-Token") == get_token()

    def _path(self):
        return urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"error": "bad token"})
        con = db()
        p = self._path()
        try:
            if p == "/health":
                ok, _ = ledger_verify(con)
                return self._send(200, {"ok": True, "version": VERSION,
                                        "chain_ok": ok,
                                        "head": ledger_head(con)[:16]})
            if p == "/agents":
                rows = [_row_dict(r) for r in con.execute(
                    "SELECT id,name,kind,location,tier,score,status FROM agents"
                    " ORDER BY score DESC").fetchall()]
                return self._send(200, {"agents": rows})
            m = re.match(r"^/agents/([\w-]+)$", p)
            if m:
                r = con.execute("SELECT * FROM agents WHERE id=?",
                                (m.group(1),)).fetchone()
                return self._send(200, {"agent": _row_dict(r)} if r else
                                  (404, {"error": "unknown agent"}))
            if p == "/tasks":
                rows = [_row_dict(r) for r in con.execute(
                    "SELECT id,agent_id,title,sop_id,status,created_at FROM tasks"
                    " ORDER BY created_at DESC LIMIT 100").fetchall()]
                return self._send(200, {"tasks": rows})
            m = re.match(r"^/reputation/([\w-]+)$", p)
            if m:
                evs = [_row_dict(r) for r in con.execute(
                    "SELECT ts,delta,kind,reason FROM rep_events WHERE agent_id=?"
                    " ORDER BY id DESC LIMIT 50", (m.group(1),)).fetchall()]
                ag = con.execute("SELECT score,tier,status FROM agents WHERE id=?",
                                 (m.group(1),)).fetchone()
                return self._send(200, {"agent": _row_dict(ag), "events": evs})
            if p == "/ledger":
                ok, problems = ledger_verify(con)
                return self._send(200, {"chain_ok": ok, "problems": problems,
                                        "head": ledger_head(con)})
            return self._send(404, {"error": "not found"})
        finally:
            con.close()

    def do_POST(self):
        if not self._auth():
            return self._send(401, {"error": "bad token"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        con = db()
        p = self._path()
        try:
            m = re.match(r"^/tasks/([\w-]+)/submit$", p)
            if m:
                task_submit(con, m.group(1), body.get("report", ""),
                            json.dumps(body.get("claims", [])),
                            json.dumps(body.get("artifacts", [])),
                            json.dumps(body.get("exceptions", [])),
                            actor="extension")
                return self._send(200, {"ok": True})
            m = re.match(r"^/tasks/([\w-]+)/verify$", p)
            if m:
                ok, info = task_verify(con, m.group(1), actor="extension",
                                       force_approver=body.get("approver", ""))
                return self._send(200 if ok else 422,
                                  {"verified": ok, "info": info})
            if p == "/tasks":
                tid = task_create(con, body["agent_id"], body["sop_id"],
                                  body.get("title", ""), body.get("due_at", ""),
                                  actor="extension")
                return self._send(200, {"task_id": tid})
            return self._send(404, {"error": "not found"})
        except SystemExit as e:
            return self._send(400, {"error": str(e)})
        finally:
            con.close()


def cmd_serve(args):
    if not DB_PATH.is_file():
        raise SystemExit("not initialized: run 'watchman.py init' first")
    token = get_token()
    if not token:
        raise SystemExit("no token: run 'watchman.py init' first")
    srv = http.server.HTTPServer(("127.0.0.1", args.port), APIHandler)
    print("watchman v%s API on http://127.0.0.1:%d (local only)" % (VERSION, args.port))
    print("extension: set token from %s" % TOKEN_PATH)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="watchman.py",
                                description="WATCHMAN v%s — agent registry + accountability" % VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="create db, seed SOPs + example agents, make token")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("agent", help="registry operations")
    sp.add_argument("action",
                    choices=["register", "list", "show", "score", "quarantine",
                             "release", "appeal", "identity", "halt", "resume"])
    sp.add_argument("ref", nargs="?",
                    help="agent id, fingerprint, or name (identity/halt/resume)")
    sp.add_argument("--name"); sp.add_argument("--kind",
                    choices=["agent", "api", "tool", "platform", "app"])
    sp.add_argument("--location", choices=["local", "cloud"])
    sp.add_argument("--endpoint", default=""); sp.add_argument("--capabilities", default="")
    sp.add_argument("--cred-ref", default="", help="WHERE the secret lives. Never the value.")
    sp.add_argument("--notes", default="")
    sp.add_argument("--id"); sp.add_argument("--delta", type=float, default=0)
    sp.add_argument("--reason", default="")
    sp.set_defaults(fn=cmd_agent)

    sp = sub.add_parser("sop", help="SOP templates")
    sp.add_argument("action", choices=["list", "show"])
    sp.add_argument("--id")
    sp.set_defaults(fn=cmd_sop)

    sp = sub.add_parser("task", help="task lifecycle")
    sp.add_argument("action",
                    choices=["create", "list", "show", "step", "submit", "verify"])
    sp.add_argument("--id"); sp.add_argument("--agent"); sp.add_argument("--sop")
    sp.add_argument("--title"); sp.add_argument("--due", default="")
    sp.add_argument("--step"); sp.add_argument("--detail", default="")
    sp.add_argument("--evidence", default="")
    sp.add_argument("--report", default="")
    sp.add_argument("--claims", default="[]"); sp.add_argument("--artifacts", default="[]")
    sp.add_argument("--exceptions", default="[]")
    sp.add_argument("--approver", default="", help="name approving manual_approval steps")
    sp.set_defaults(fn=cmd_task)

    sp = sub.add_parser("ledger", help="hash-chained record")
    sp.add_argument("action", choices=["verify", "show", "checkpoint"])
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_ledger)

    sp = sub.add_parser("rep", help="reputation")
    sp.add_argument("action", choices=["log", "adjust"])
    sp.add_argument("--id"); sp.add_argument("--delta", type=float, default=0)
    sp.add_argument("--kind", default="manual")
    sp.add_argument("--reason", default=""); sp.add_argument("--actor", default="board")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_rep)

    sp = sub.add_parser("incident", help="24-hour incident reporting: report an "
                        "AI-safety incident on the clock (maps to the NYC "
                        "24-hour contractor reporting duty), list open "
                        "incidents, resolve with a note")
    sp.add_argument("action", choices=["report", "list", "resolve"])
    sp.add_argument("ref", nargs="?", help="incident id (resolve)")
    sp.add_argument("--agent", help="agent id, fingerprint, or name (report)")
    sp.add_argument("--kind", default="safety", help="incident kind (report)")
    sp.add_argument("--summary", default="", help="what happened (report)")
    sp.add_argument("--note", default="", help="resolution note (resolve)")
    sp.set_defaults(fn=cmd_incident)

    sp = sub.add_parser("serve", help="local HTTP API for the extension")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.set_defaults(fn=cmd_serve)
    return p


def main():
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
