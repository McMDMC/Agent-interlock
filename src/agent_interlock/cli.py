"""Command line: validate policies, dry-run calls, run the MCP gateway, operate latches."""

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
from .state import LatchStore


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


def _mcp_proxy(a: argparse.Namespace) -> int:
    from .mcp_gateway import McpGateway, run_stdio

    if not a.command:
        print("interlock mcp-proxy: give the server command after --", file=sys.stderr)
        return 2
    il = Interlock(
        Policy.from_file(a.policy),
        audit=audit.AuditLog(a.audit),
        state_path=a.state,
    )
    gw = McpGateway(il, agent=a.agent, hide_unlisted=not a.show_all)
    return run_stdio(gw, a.command, policy_path=a.policy)


def _latch_op(a: argparse.Namespace) -> int:
    store = LatchStore(a.state)
    log = audit.AuditLog(a.audit) if a.audit else None
    if a.cmd == "status":
        locked, estop = store.load()
        print(json.dumps({"estop": estop, "locked_out": locked}, indent=2))
        return 0
    if a.cmd == "estop":
        store.update(lambda locked, _: (locked, f"{a.reason or 'stop'} (from {a.source})"))
        if log:
            log.event("estop", source=a.source, reason=a.reason)
    elif a.cmd == "reset":
        store.update(lambda locked, _: (locked, None))
        if log:
            log.event("estop_reset", operator=a.operator)
    elif a.cmd == "release":
        store.update(lambda locked, e: ({k: v for k, v in locked.items() if k != a.agent}, e))
        if log:
            log.event("release", agent=a.agent, operator=a.operator)
    print(f"{a.cmd}: done")
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

    m = sub.add_parser("mcp-proxy", help="gate a stdio MCP server: ... -- <server command>")
    m.add_argument("--policy", required=True)
    m.add_argument("--agent", default="mcp-client", help="agent identity used in the policy")
    m.add_argument("--audit", default="interlock-audit.jsonl")
    m.add_argument("--state", default=None, help="shared latch file (lockouts, E-stop)")
    m.add_argument("--show-all", action="store_true", help="don't hide tools missing from policy")
    m.add_argument("command", nargs=argparse.REMAINDER)
    m.set_defaults(fn=_mcp_proxy)

    for name, helptext in (
        ("status", "show latched E-stop and lockouts"),
        ("estop", "latch the E-stop for every interlock sharing the state file"),
        ("reset", "reset the E-stop"),
        ("release", "release a locked-out agent"),
    ):
        o = sub.add_parser(name, help=helptext)
        o.add_argument("--state", required=True)
        o.add_argument("--audit", default=None)
        if name == "estop":
            o.add_argument("--source", default="cli")
            o.add_argument("--reason", default="")
        if name in ("reset", "release"):
            o.add_argument("--operator", required=True)
        if name == "release":
            o.add_argument("--agent", required=True)
        o.set_defaults(fn=_latch_op)

    a = ap.parse_args(argv)
    if a.cmd == "mcp-proxy" and a.command[:1] == ["--"]:
        a.command = a.command[1:]
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
