"""Latch state that must survive restarts and be shared: agent lockouts and the E-stop.

A real E-stop stays latched through a power cycle and stops every drive on
the circuit. Same here:

* Lockouts and the E-stop are written to a JSON file, so a crashed or
  deliberately restarted agent host comes back still latched.
* Every Interlock pointing at the same file sees changes made by the others
  (or by ``interlock estop`` from a shell) on its next check. One E-stop
  stops all gateways on the host.
* An unreadable file latches the E-stop. Fail safe, not fail open.

Updates are read-modify-write under an exclusive file lock (POSIX), so two
processes latching at the same time do not overwrite each other.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no cross-process lock, single writer assumed
    fcntl = None  # type: ignore[assignment]

UNREADABLE = "state file unreadable; latched for safety"

Latches = tuple[dict[str, str], str | None]  # (locked_out agent -> reason, estop reason)


class LatchStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lockfile = self.path.with_name(self.path.name + ".lock")
        self._sig: tuple[int, int, int] | None = None

    def _stat(self) -> tuple[int, int, int] | None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def load(self) -> Latches:
        self._sig = self._stat()
        if self._sig is None:
            return {}, None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            locked = data.get("locked_out", {})
            estop = data.get("estop")
            if not isinstance(locked, dict) or not (estop is None or isinstance(estop, str)):
                raise ValueError("bad shape")
            return {str(k): str(v) for k, v in locked.items()}, estop
        except (OSError, ValueError):
            return {}, UNREADABLE

    def refresh(self) -> Latches | None:
        """Return the file's state if another writer changed it since we last looked.

        A file that disappears keeps the in-memory latches (returns None):
        deleting the file must not be a way to clear an E-stop.
        """
        sig = self._stat()
        if sig is None or sig == self._sig:
            return None
        return self.load()

    def update(self, fn: Callable[[dict[str, str], str | None], Latches]) -> Latches:
        """Apply fn to the current on-disk state and write the result atomically."""
        with self._exclusive():
            locked, estop = fn(*self.load())
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".latch-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({"locked_out": locked, "estop": estop}, f, indent=1)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)  # a crash never leaves a half-written file
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            self._sig = self._stat()
            return locked, estop

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        if fcntl is None:
            yield
            return
        self._lockfile.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lockfile, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
