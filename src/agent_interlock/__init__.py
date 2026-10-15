"""agent-interlock: a safety interlock for AI agent tool calls."""

from .audit import AuditLog, verify
from .decision import Decision, ToolCall, Verdict
from .engine import Interlock
from .guard import InterlockBlocked, guarded
from .policy import Policy, PolicyError

__all__ = [
    "AuditLog",
    "Decision",
    "Interlock",
    "InterlockBlocked",
    "Policy",
    "PolicyError",
    "ToolCall",
    "Verdict",
    "guarded",
    "verify",
]
__version__ = "0.1.0"
