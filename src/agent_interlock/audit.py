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
from typing import IO, Any

from .decision import Decision

GENESIS = "0" * 64


def _digest(prev: str, body: dict[str, Any]) -> str:
    payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL log. Pass path=None to keep it in memory.

    ``stream=`` writes to an open text stream instead (e.g. ``sys.stdout`` on
    Cloud Run, where each JSON line becomes a structured Cloud Logging entry).
    A stream starts a fresh chain and is never closed by the log.
    """

    def __init__(self, path: str | Path | None = None, stream: IO[str] | None = None) -> None:
        if path and stream:
            raise ValueError("give path or stream, not both")
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._stream = stream
        if stream is not None:
            self._file: IO[str] | None = stream
            return
        if self.path and self.path.exists():
            # Resume the chain from the last line of an existing log.
            last = None
            with self.path.open() as f:
                for line in f:
                    if line.strip():
                        last = line
            if last:
                self._prev = json.loads(last)["hash"]
        # Line-buffered: each record reaches the OS as soon as it is written.
        self._file = self.path.open("a", buffering=1, encoding="utf-8") if self.path else None

    def event(self, kind: str, **fields: Any) -> dict[str, Any]:
        body = {"ts": time.time(), "kind": kind, **fields}
        with self._lock:
            record = {**body, "prev": self._prev, "hash": _digest(self._prev, body)}
            self._prev = record["hash"]
            if self._file:
                self._file.write(json.dumps(record, default=str) + "\n")
                if self._stream is not None:
                    self._file.flush()
            else:
                self.records.append(record)
        return record

    def close(self) -> None:
        if self._file and self._stream is None:
            self._file.close()
        self._file = None

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

    def __init__(self) -> None:
        super().__init__(None)

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
