"""Framework-agnostic wrapper: put the interlock in front of any Python callable."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from .decision import Decision, ToolCall
from .engine import Interlock

F = TypeVar("F", bound=Callable[..., Any])


class InterlockBlocked(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(f"[{decision.verdict.value}] {decision.call.tool}: {decision.reason}")
        self.decision = decision


def guarded(interlock: Interlock, agent: str, name: str | None = None) -> Callable[[F], F]:
    """Decorator. Raises InterlockBlocked instead of running the tool when not allowed.

    Positional arguments are mapped to parameter names, so the policy always
    sees the call as ``{arg_name: value}``.
    """

    def wrap(fn: F) -> F:
        tool = name or fn.__name__
        sig = inspect.signature(fn)

        def gate(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
            bound = sig.bind(*args, **kwargs)
            d = interlock.check(ToolCall(agent, tool, dict(bound.arguments)))
            if not d.allowed:
                raise InterlockBlocked(d)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                gate(args, kwargs)
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            gate(args, kwargs)
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return wrap
