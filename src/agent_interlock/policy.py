"""Policy model and TOML loader.

A policy is compiled once at load time so the hot path (Interlock.check) only
does dict lookups and comparisons. Any malformed policy fails at load, never
at call time.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TOOL_CLASSES = ("read", "write", "actuate")
MODES = ("enforce", "observe")


class PolicyError(ValueError):
    """Raised when a policy file is invalid."""


@dataclass(frozen=True, slots=True)
class ParamRule:
    name: str
    type: str | None = None  # "number" | "int" | "string" | "bool"
    min: float | None = None
    max: float | None = None
    enum: tuple[Any, ...] | None = None
    pattern: re.Pattern[str] | None = None
    max_len: int | None = None
    required: bool = True

    def check(self, value: Any) -> str | None:
        """Return a violation message, or None if the value is fine."""
        if self.type is not None and not _type_ok(self.type, value):
            return f"{self.name}: expected {self.type}, got {type(value).__name__}"
        if self.min is not None or self.max is not None:
            if not _is_number(value):
                return f"{self.name}: expected a number for range check"
            # NaN compares False against everything and would slip past both
            # bounds, so non-finite values are rejected outright.
            if not math.isfinite(value):
                return f"{self.name}: non-finite value {value!r}"
            if self.min is not None and value < self.min:
                return f"{self.name}={value} below min {self.min}"
            if self.max is not None and value > self.max:
                return f"{self.name}={value} above max {self.max}"
        if self.enum is not None and value not in self.enum:
            return f"{self.name}={value!r} not in {list(self.enum)}"
        if self.max_len is not None and hasattr(value, "__len__") and len(value) > self.max_len:
            return f"{self.name}: length {len(value)} exceeds {self.max_len}"
        if self.pattern is not None:
            if not isinstance(value, str) or not self.pattern.fullmatch(value):
                return f"{self.name}={value!r} does not match {self.pattern.pattern!r}"
        return None


@dataclass(frozen=True, slots=True)
class KeepOut:
    """Axis-aligned box the target point must not enter (e.g. an operator station)."""

    name: str
    bounds: dict[str, tuple[float, float]]  # arg name -> (lo, hi)

    def contains(self, args: dict[str, Any]) -> bool:
        for axis, (lo, hi) in self.bounds.items():
            v = args.get(axis)
            if not _is_number(v) or not lo <= v <= hi:
                return False
        return True


@dataclass(frozen=True, slots=True)
class RateLimit:
    max_calls: int
    per_s: float


@dataclass(frozen=True, slots=True)
class ToolRule:
    name: str
    tool_class: str
    params: dict[str, ParamRule] = field(default_factory=dict)
    keepout: tuple[KeepOut, ...] = ()
    rate: RateLimit | None = None
    require_approval: bool = False
    strict: bool = True  # reject args that are not declared in params
    agents: frozenset[str] | None = None  # None = any agent


@dataclass(frozen=True, slots=True)
class Policy:
    mode: str = "enforce"
    lockout_after: int = 3
    violation_window_s: float = 300.0
    estop_blocks: frozenset[str] = frozenset({"actuate"})
    tools: dict[str, ToolRule] = field(default_factory=dict)
    digest: str = ""  # sha256 of the source text, recorded in the audit trail

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        return cls.from_toml(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def from_toml(cls, text: str) -> Policy:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise PolicyError(f"TOML: {e}") from None
        policy = cls.from_dict(data)
        return dataclasses.replace(policy, digest=hashlib.sha256(text.encode()).hexdigest())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        head = data.get("interlock", {})
        mode = head.get("mode", "enforce")
        if mode not in MODES:
            raise PolicyError(f"interlock.mode must be one of {MODES}, got {mode!r}")
        lockout_after = head.get("lockout_after", 3)
        if not isinstance(lockout_after, int) or lockout_after < 0:
            raise PolicyError("interlock.lockout_after must be an int >= 0 (0 disables lockout)")
        estop_blocks = frozenset(head.get("estop_blocks", ["actuate"]))
        if bad := estop_blocks - set(TOOL_CLASSES):
            raise PolicyError(f"interlock.estop_blocks has unknown classes {sorted(bad)}")
        tools = {name: _tool_rule(name, spec) for name, spec in data.get("tools", {}).items()}
        return cls(
            mode=mode,
            lockout_after=lockout_after,
            violation_window_s=float(head.get("violation_window_s", 300)),
            estop_blocks=estop_blocks,
            tools=tools,
        )


def _tool_rule(name: str, spec: dict[str, Any]) -> ToolRule:
    where = f"tools.{name}"
    tool_class = spec.get("class")
    if tool_class not in TOOL_CLASSES:
        raise PolicyError(f"{where}.class must be one of {TOOL_CLASSES}, got {tool_class!r}")

    params = {
        p: _param_rule(f"{where}.params.{p}", p, s) for p, s in spec.get("params", {}).items()
    }

    keepout = []
    for i, box in enumerate(spec.get("keepout", [])):
        box = dict(box)
        box_name = box.pop("name", f"zone{i}")
        bounds = {}
        for axis, rng in box.items():
            if not (isinstance(rng, list) and len(rng) == 2 and all(map(_is_number, rng))):
                raise PolicyError(f"{where}.keepout[{box_name}].{axis} must be [lo, hi]")
            bounds[axis] = (float(min(rng)), float(max(rng)))
        if not bounds:
            raise PolicyError(f"{where}.keepout[{box_name}] has no axes")
        for axis in bounds:
            # An optional or untyped axis would let the agent skip the zone
            # check by leaving the argument out or passing a string.
            p = params.get(axis)
            if p is None or not p.required or p.type not in ("number", "int"):
                raise PolicyError(
                    f"{where}.keepout[{box_name}].{axis}: axis must be a required "
                    f'param with type = "number" or "int"'
                )
        keepout.append(KeepOut(box_name, bounds))

    rate = None
    if "rate" in spec:
        r = spec["rate"]
        try:
            rate = RateLimit(int(r["max"]), float(r["per_s"]))
        except (KeyError, TypeError, ValueError) as e:
            raise PolicyError(f"{where}.rate needs max and per_s: {e}") from None
        if rate.max_calls < 1 or rate.per_s <= 0:
            raise PolicyError(f"{where}.rate must have max >= 1 and per_s > 0")

    agents = spec.get("agents")
    if agents is not None and not (
        isinstance(agents, list) and all(isinstance(a, str) and a for a in agents)
    ):
        raise PolicyError(f"{where}.agents must be a list of agent names")
    return ToolRule(
        name=name,
        tool_class=tool_class,
        params=params,
        keepout=tuple(keepout),
        rate=rate,
        require_approval=bool(spec.get("require_approval", False)),
        strict=bool(spec.get("strict", True)),
        agents=frozenset(agents) if agents is not None else None,
    )


def _param_rule(where: str, name: str, spec: dict[str, Any]) -> ParamRule:
    known = {"type", "min", "max", "enum", "pattern", "max_len", "required"}
    if extra := set(spec) - known:
        raise PolicyError(f"{where}: unknown keys {sorted(extra)}")
    ptype = spec.get("type")
    if ptype is not None and ptype not in ("number", "int", "string", "bool"):
        raise PolicyError(f"{where}.type must be number|int|string|bool")
    lo, hi = spec.get("min"), spec.get("max")
    if lo is not None and hi is not None and lo > hi:
        raise PolicyError(f"{where}: min {lo} > max {hi}")
    try:
        pattern = re.compile(spec["pattern"]) if "pattern" in spec else None
    except re.error as e:
        raise PolicyError(f"{where}.pattern: {e}") from None
    return ParamRule(
        name=name,
        type=ptype,
        min=lo,
        max=hi,
        enum=tuple(spec["enum"]) if "enum" in spec else None,
        pattern=pattern,
        max_len=spec.get("max_len"),
        required=bool(spec.get("required", True)),
    )


def _is_number(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def _type_ok(t: str, v: Any) -> bool:
    if t == "number":
        return _is_number(v)
    if t == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "string":
        return isinstance(v, str)
    return isinstance(v, bool)
