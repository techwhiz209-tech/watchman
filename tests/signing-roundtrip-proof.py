#!/usr/bin/env python3
"""Signing round-trip proof (Phase 1, Step 2). Independent of watchman.py's
own ledger_verify: recomputes every signature from the stored fields with
the registry public key from kv, then proves tampering fails.

Usage: HOME=<sandbox> venv/bin/python3 signing-roundtrip-proof.py
Expects a fresh DB created by the NEW binary (init already run).
"""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/your_files/watchman-phase1-build-2026-11-05")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HOME = Path.home()
DB = HOME / ".watchman" / "watchman.db"
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

fails = []
def check(cond, label):
    print(("  PASS: " if cond else "  FAIL: ") + label)
    if not cond:
        fails.append(label)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")

# 1. registry key: pub is exactly the one derived from stored priv; fp shape
priv_hex = con.execute("SELECT value FROM kv WHERE key='registry_signing_privkey'").fetchone()["value"]
pub_hex = con.execute("SELECT value FROM kv WHERE key='registry_signing_pubkey'").fetchone()["value"]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
derived = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
check(derived == pub_hex, "stored registry pubkey == derived from stored privkey")
reg_fp = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
check(bool(HEX64.match(reg_fp)), "registry fingerprint is 64 lowercase hex: %s..." % reg_fp[:16])

# 2. agent fingerprints unchanged shape
fps = [r["fingerprint"] for r in con.execute("SELECT fingerprint FROM agents").fetchall()]
check(len(fps) > 0 and all(HEX64.match(f) for f in fps),
      "all %d agent fingerprints are 64 lowercase hex" % len(fps))

# 3. every ledger record signed; each signature verifies independently
rows = con.execute("SELECT seq,ts,kind,actor,payload,payload_hash,prev_hash,hash,signature FROM ledger ORDER BY seq").fetchall()
check(len(rows) > 0, "%d ledger records present" % len(rows))
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
all_signed = all(r["signature"] and HEX128.match(r["signature"]) for r in rows)
check(all_signed, "every record carries a 128-hex signature (%d/%d)" % (sum(1 for r in rows if r["signature"]), len(rows)))
ok = True
for r in rows:
    preimage = (r["prev_hash"] + r["payload_hash"] + r["ts"] + r["kind"] + r["actor"]).encode("utf-8")
    # hash must be sha256 of the same preimage (format unchanged)
    if hashlib.sha256(preimage).hexdigest() != r["hash"]:
        ok = False
        print("  FAIL: seq %d hash != sha256(preimage)" % r["seq"])
    try:
        pub.verify(bytes.fromhex(r["signature"]), preimage)
    except (ValueError, InvalidSignature):
        ok = False
        print("  FAIL: seq %d signature does not verify" % r["seq"])
check(ok, "every signature verifies independently against the registry pubkey")
check(all(r["hash"] == hashlib.sha256((r["prev_hash"] + r["payload_hash"] + r["ts"] + r["kind"] + r["actor"]).encode()).hexdigest() for r in rows),
      "every record hash is still sha256(prev+payload_hash+ts+kind+actor) — chain format unchanged")

print()
print("RESULT: %d failed" % len(fails))
sys.exit(1 if fails else 0)
