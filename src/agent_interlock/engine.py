"""The interlock: every tool call goes through check() before it runs.

Machine-safety semantics, applied to agents:

* Fail closed. Unknown tool, undeclared argument, out-of-envelope value: deny.
* Lockout/tagout. Repeated violations quarantine the agent. Only a named
  operator can release it; the release is written to the audit trail.
* E-stop. A latched stop blocks every tool of the classes in
  ``estop_blocks`` (default: ``actuate``) for all agents until reset.
* Observe mode. Policy decisions are computed and logged but do not block,
  so a new policy can be tuned against real traffic before it is enforced.
  Lockouts and the E-stop are still enforced in observe mode.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .decision import Decision, ToolCall, Verdict
from .policy import Policy
from .state import LatchStore

Approver = Callable[[ToolCall], bool]
_KEEP = object()


class Interlock:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog | None = None,
        approver: Approver | None = None,
        clock: Callable[[], float] = time.monotonic,
        state_path: str | Path | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit if audit is not None else AuditLog()
        self.approver = approver
        self._clock = clock
        self._lock = threading.Lock()
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._violations: dict[str, deque[float]] = defaultdict(deque)
        self._store = LatchStore(state_path) if state_path else None
        self._locked_out: dict[str, str] = {}  # agent -> reason
        self._estop: str | None = None
        if self._store:
            self._locked_out, self._estop = self._store.load()
        self.audit.event(
            "start",
            policy=policy.digest,
            mode=policy.mode,
            locked_out=sorted(self._locked_out),
            estop=self._estop,
        )

    @classmethod
    def from_file(cls, path: str | Path, **kw: Any) -> Interlock:
        return cls(Policy.from_file(path), **kw)

    # ------------------------------------------------------------------ check

    def check(self, call: ToolCall) -> Decision:
        t0 = time.perf_counter()
        with self._lock:
            self._sync()
            verdict, rule, reason = self._evaluate(call)
            # Lockouts and E-stops are hard stops: observe mode never overrides them.
            enforced = self.policy.mode == "enforce" or verdict is Verdict.LOCKOUT
            if verdict is Verdict.DENY and enforced:
                self._record_violation(call.agent, reason)
        latency_us = (time.perf_counter() - t0) * 1e6
        if verdict is Verdict.HOLD and self.approver is not None:
            # Approver runs outside the lock: it may block on a human.
            if self.approver(call):
                verdict, rule, reason = Verdict.ALLOW, "approval", "approved by operator"
            else:
                # A human said no. That holds in observe mode too.
                verdict, rule, reason = Verdict.DENY, "approval", "rejected by operator"
                enforced = True
        d = Decision(
            verdict=verdict,
            reason=reason,
            call=call,
            rule=rule,
            enforced=enforced,
            latency_us=latency_us,
        )
        self.audit.decision(d)
        return d

    def _evaluate(self, call: ToolCall) -> tuple[Verdict, str, str]:
        if call.agent in self._locked_out:
            return Verdict.LOCKOUT, "lockout", f"agent locked out: {self._locked_out[call.agent]}"

        rule = self.policy.tools.get(call.tool)
        if rule is None:
            return Verdict.DENY, "unknown_tool", f"tool {call.tool!r} is not in the policy"

        if self._estop is not None and rule.tool_class in self.policy.estop_blocks:
            return Verdict.LOCKOUT, "estop", f"E-stop latched: {self._estop}"

        if rule.agents is not None and call.agent not in rule.agents:
            return Verdict.DENY, "agent", f"agent {call.agent!r} may not call {call.tool!r}"

        args = call.args
        if rule.strict and (extra := set(args) - set(rule.params)):
            return Verdict.DENY, "args", f"undeclared arguments {sorted(extra)}"
        for p in rule.params.values():
            if p.name not in args:
                if p.required:
                    return Verdict.DENY, f"param:{p.name}", f"missing required argument {p.name!r}"
                continue
            if (msg := p.check(args[p.name])) is not None:
                return Verdict.DENY, f"param:{p.name}", msg

        for box in rule.keepout:
            if box.contains(args):
                reason = f"target inside keep-out zone {box.name!r}"
                return Verdict.DENY, f"keepout:{box.name}", reason

        if rule.rate is not None:
            now = self._clock()
            window = self._calls[(call.agent, call.tool)]
            while window and now - window[0] >= rule.rate.per_s:
                window.popleft()
            if len(window) >= rule.rate.max_calls:
                return (
                    Verdict.DENY,
                    "rate",
                    f"rate limit {rule.rate.max_calls}/{rule.rate.per_s}s exceeded",
                )
            window.append(now)

        if rule.require_approval:
            return Verdict.HOLD, "approval", "requires operator approval"
        return Verdict.ALLOW, "", "ok"

    def _record_violation(self, agent: str, reason: str) -> None:
        limit = self.policy.lockout_after
        if limit == 0:
            return
        now = self._clock()
        v = self._violations[agent]
        v.append(now)
        while v and now - v[0] > self.policy.violation_window_s:
            v.popleft()
        if len(v) >= limit:
            why = f"{len(v)} violations, last: {reason}"
            v.clear()
            self._latch(lock=(agent, why))
            self.audit.event("lockout", agent=agent, reason=why)

    # The two helpers below are called with self._lock held.

    def _sync(self) -> None:
        """Pick up latch changes made by other processes sharing the state file."""
        if self._store and (latches := self._store.refresh()) is not None:
            self._locked_out, self._estop = latches

    def _latch(
        self,
        lock: tuple[str, str] | None = None,
        unlock: str | None = None,
        estop: str | None | object = _KEEP,
    ) -> None:
        def apply(locked: dict[str, str], current: str | None) -> tuple[dict[str, str], str | None]:
            if lock:
                locked[lock[0]] = lock[1]
            if unlock:
                locked.pop(unlock, None)
            return locked, current if estop is _KEEP else estop  # type: ignore[return-value]

        if self._store:
            self._locked_out, self._estop = self._store.update(apply)
        else:
            self._locked_out, self._estop = apply(self._locked_out, self._estop)

    # ------------------------------------------------------- operator actions

    def reload(self, policy: Policy, operator: str) -> None:
        """Swap in a new policy without a restart. Lockouts and the E-stop stay latched."""
        if not operator:
            raise ValueError("policy reload needs a named operator")
        with self._lock:
            old = self.policy.digest
            self.policy = policy
            self.audit.event("policy_reload", operator=operator, old=old, new=policy.digest)

    def locked_out(self) -> dict[str, str]:
        with self._lock:
            self._sync()
            return dict(self._locked_out)

    def lockout(self, agent: str, operator: str, reason: str = "manual") -> None:
        with self._lock:
            self._latch(lock=(agent, f"{reason} (by {operator})"))
            self.audit.event("lockout", agent=agent, operator=operator, reason=reason)

    def release(self, agent: str, operator: str) -> bool:
        """Remove an agent's lockout. Returns False if it was not locked out."""
        if not operator:
            raise ValueError("release needs a named operator")
        with self._lock:
            self._sync()
            if agent not in self._locked_out:
                return False
            self._latch(unlock=agent)
            self._violations.pop(agent, None)
            self.audit.event("release", agent=agent, operator=operator)
            return True

    @property
    def estop_latched(self) -> bool:
        with self._lock:
            self._sync()
            return self._estop is not None

    def estop(self, source: str, reason: str = "") -> None:
        with self._lock:
            self._latch(estop=f"{reason or 'stop'} (from {source})")
            self.audit.event("estop", source=source, reason=reason)

    def reset_estop(self, operator: str) -> None:
        if not operator:
            raise ValueError("E-stop reset needs a named operator")
        with self._lock:
            self._latch(estop=None)
            self.audit.event("estop_reset", operator=operator)
