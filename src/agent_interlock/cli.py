"""Command line: validate policies, dry-run calls, verify audit logs, benchmark."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time

from . import audit
from .decision import ToolCall
from .engine import Interlock
from .policy import Policy, PolicyError


def _validate(a: argparse.Namespace) -> int:
    try:
        p = Policy.from_file(a.policy)
    except (PolicyError, OSError, ValueError) as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    print(f"OK: mode={p.mode}, {len(p.tools)} tools")
    for t in p.tools.values():
        flags = [t.tool_class]
        if t.require_approval:
            flags.append("approval")
        if t.rate:
            flags.append(f"rate {t.rate.max_calls}/{t.rate.per_s:g}s")
        if t.keepout:
            flags.append(f"{len(t.keepout)} keep-out")
        print(f"  {t.name:24} {', '.join(flags)}")
    return 0


def _check(a: argparse.Namespace) -> int:
    il = Interlock.from_file(a.policy)
    d = il.check(ToolCall(a.agent, a.tool, json.loads(a.args)))
    print(
        json.dumps(
            {
                "verdict": d.verdict.value,
                "rule": d.rule,
                "reason": d.reason,
                "enforced": d.enforced,
                "latency_us": round(d.latency_us, 2),
            }
        )
    )
    return 0 if d.allowed else 2


def _verify(a: argparse.Namespace) -> int:
    ok, bad = audit.verify(audit.load(a.log))
    print("chain OK" if ok else f"chain BROKEN at record {bad}")
    return 0 if ok else 1


def _bench(a: argparse.Namespace) -> int:
    il = Interlock(Policy.from_file(a.policy), audit=audit.NullAudit())
    call = ToolCall(a.agent, a.tool, json.loads(a.args))
    samples = []
    for _ in range(a.n):
        t0 = time.perf_counter_ns()
        il.check(call)  # full check incl. locking; audit I/O excluded via NullAudit
        samples.append((time.perf_counter_ns() - t0) / 1000)
    samples.sort()
    print(
        f"n={a.n}  p50={statistics.median(samples):.2f}us  "
        f"p99={samples[int(len(samples) * 0.99) - 1]:.2f}us  max={samples[-1]:.2f}us"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="interlock", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="load and summarise a policy")
    v.add_argument("policy")
    v.set_defaults(fn=_validate)

    for name, fn, helptext in (
        ("check", _check, "dry-run one tool call"),
        ("bench", _bench, "measure decision latency"),
    ):
        c = sub.add_parser(name, help=helptext)
        c.add_argument("policy")
        c.add_argument("--agent", default="cli")
        c.add_argument("--tool", required=True)
        c.add_argument("--args", default="{}", help="JSON object")
        if name == "bench":
            c.add_argument("-n", type=int, default=100_000)
        c.set_defaults(fn=fn)

    r = sub.add_parser("verify-audit", help="verify an audit log hash chain")
    r.add_argument("log")
    r.set_defaults(fn=_verify)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
