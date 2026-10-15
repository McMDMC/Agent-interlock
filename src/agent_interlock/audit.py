"""Tamper-evident audit trail.

Every record carries the SHA-256 of the previous record, so editing or
deleting a line anywhere breaks the chain from that point on. This is
tamper-evident, not tamper-proof: ship the log off the box (Cloud Logging,
a WORM bucket) if an attacker could rewrite the whole file.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from .decision import Decision

GENESIS = "0" * 64


def _digest(prev: str, body: dict[str, Any]) -> str:
    payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL log. Pass path=None to keep it in memory."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path and self.path.exists():
            # Resume the chain from the last line of an existing log.
            last = None
            with self.path.open() as f:
                for line in f:
                    if line.strip():
                        last = line
            if last:
                self._prev = json.loads(last)["hash"]

    def event(self, kind: str, **fields: Any) -> dict[str, Any]:
        body = {"ts": time.time(), "kind": kind, **fields}
        with self._lock:
            record = {**body, "prev": self._prev, "hash": _digest(self._prev, body)}
            self._prev = record["hash"]
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(record, default=str) + "\n")
            else:
                self.records.append(record)
        return record

    def decision(self, d: Decision) -> dict[str, Any]:
        return self.event(
            "decision",
            agent=d.call.agent,
            tool=d.call.tool,
            args=d.call.args,
            verdict=d.verdict.value,
            rule=d.rule,
            reason=d.reason,
            enforced=d.enforced,
        )


class NullAudit(AuditLog):
    """Discards everything. For benchmarks only."""

    def event(self, kind: str, **fields: Any) -> dict[str, Any]:
        return {}


def verify(records: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Check the hash chain. Returns (ok, index of first bad record or None)."""
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
        if rec.get("prev") != prev or rec.get("hash") != _digest(prev, body):
            return False, i
        prev = rec["hash"]
    return True, None


def load(path: str | Path) -> list[dict[str, Any]]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]
