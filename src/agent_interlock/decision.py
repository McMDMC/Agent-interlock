"""Core value types: a tool call going in, a decision coming out."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"  # this call breaks policy
    HOLD = "hold"  # needs a human to approve before it runs
    LOCKOUT = "lockout"  # agent is quarantined or the E-stop is latched


@dataclass(frozen=True, slots=True)
class ToolCall:
    agent: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    reason: str
    call: ToolCall
    rule: str = ""  # which check produced the verdict, e.g. "param:speed"
    enforced: bool = True  # False in observe mode: logged but not blocked
    latency_us: float = 0.0

    @property
    def allowed(self) -> bool:
        """True if the tool may run. Observe mode always lets calls through."""
        return self.verdict is Verdict.ALLOW or not self.enforced
