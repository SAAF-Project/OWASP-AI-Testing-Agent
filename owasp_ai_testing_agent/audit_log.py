"""Tamper-evident audit log (plan section 6: every tool invocation is logged).

Each JSONL record carries the SHA-256 of the previous record, so editing, removing or reordering
a line breaks the chain and `verify_log` reports where. This is tamper-*evident*, not tamper-proof:
someone with write access can rewrite the whole file. Ship the log to write-once storage for more.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._last = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last_line = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last_line = line
        if last_line is None:
            return 0, GENESIS
        rec = json.loads(last_line)
        return rec["seq"], rec["hash"]

    def append(self, event: str, **data) -> dict:
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event": event,
                "data": data,
                "prev_hash": self._last,
            }
            record["hash"] = _digest(self._last, {k: v for k, v in record.items() if k != "hash"})
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            self._last = record["hash"]
            return record


def verify_log(path: Path | str) -> tuple[bool, str]:
    """Check the hash chain. Returns (ok, message)."""
    path = Path(path)
    if not path.exists():
        return False, f"{path} does not exist"
    prev, expected_seq = GENESIS, 1
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line {lineno}: not valid JSON"
        if rec.get("seq") != expected_seq:
            return False, f"line {lineno}: expected seq {expected_seq}, found {rec.get('seq')}"
        if rec.get("prev_hash") != prev:
            return False, f"line {lineno}: prev_hash does not match the previous record"
        stated = rec.pop("hash", None)
        if _digest(prev, rec) != stated:
            return False, f"line {lineno}: record was modified (hash mismatch)"
        prev, expected_seq = stated, expected_seq + 1
    return True, f"{expected_seq - 1} records, chain intact"
