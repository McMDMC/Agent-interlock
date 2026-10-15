"""Walk-through: an agent driving a simulated robot cell through the interlock.

Run:  python examples/robot_cell_demo.py
No LLM needed; the "agent" is a scripted list of tool calls, some of them bad.
"""

from pathlib import Path

from agent_interlock import AuditLog, Interlock, InterlockBlocked, guarded, verify

ROOT = Path(__file__).resolve().parent.parent
audit = AuditLog()  # in memory; pass a path for a JSONL file
il = Interlock.from_file(ROOT / "policies" / "robot_cell.toml", audit=audit)
AGENT = "planner-01"


@guarded(il, AGENT)
def move_arm(x: float, y: float, z: float, speed: float) -> str:
    return f"arm -> ({x}, {y}, {z}) @ {speed} m/s"


@guarded(il, AGENT)
def read_sensor(sensor: str) -> str:
    return f"{sensor}: nominal"


def attempt(label, fn, *args, **kwargs):
    try:
        print(f"  OK      {label:44} {fn(*args, **kwargs)}")
    except InterlockBlocked as e:
        d = e.decision
        print(f"  {d.verdict.value.upper():7} {label:44} {d.reason}")


print("\n1) Normal operation")
attempt("move inside envelope", move_arm, 0.1, 0.1, 0.4, 0.2)
attempt("read light curtain", read_sensor, "light_curtain")

print("\n2) Agent goes outside its envelope (counts toward lockout)")
attempt("speed above 0.25 m/s", move_arm, 0.1, 0.1, 0.4, 1.5)
attempt("target in operator station", move_arm, 0.45, 0.0, 0.4, 0.1)
attempt("NaN coordinate", move_arm, float("nan"), 0.0, 0.4, 0.1)

print("\n3) Agent is now locked out, even for harmless reads")
attempt("read light curtain", read_sensor, "light_curtain")
print(f"  locked out: {il.locked_out()}")

print("\n4) Operator releases the lockout (LOTO)")
il.release(AGENT, operator="m.mcmorris")
attempt("move inside envelope", move_arm, 0.0, 0.0, 0.5, 0.1)

print("\n5) Light curtain trips -> E-stop. Motion blocked, sensors still readable")
il.estop(source="light_curtain", reason="beam broken")
attempt("move inside envelope", move_arm, 0.0, 0.0, 0.5, 0.1)
attempt("read force/torque", read_sensor, "force_torque")
il.reset_estop(operator="m.mcmorris")
attempt("move after reset", move_arm, 0.0, 0.0, 0.5, 0.1)

ok, bad = verify(audit.records)
print(f"\nAudit: {len(audit.records)} records, hash chain {'OK' if ok else f'BROKEN at {bad}'}")
