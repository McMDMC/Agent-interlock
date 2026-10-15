import json
from pathlib import Path

import pytest

from agent_interlock import (
    AuditLog,
    Interlock,
    InterlockBlocked,
    Policy,
    PolicyError,
    ToolCall,
    Verdict,
    guarded,
    verify,
)
from agent_interlock.audit import load
from agent_interlock.cli import main as cli

ROOT = Path(__file__).resolve().parent.parent
CELL = ROOT / "policies" / "robot_cell.toml"
OK_MOVE = {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def il(clock):
    return Interlock(Policy.from_file(CELL), clock=clock)


def move(il, agent="a1", **over):
    return il.check(ToolCall(agent, "move_arm", {**OK_MOVE, **over}))


# ------------------------------------------------------------------ verdicts


def test_allows_call_inside_envelope(il):
    d = move(il)
    assert d.verdict is Verdict.ALLOW and d.allowed


def test_unknown_tool_fails_closed(il):
    d = il.check(ToolCall("a1", "rm_rf", {}))
    assert d.verdict is Verdict.DENY and d.rule == "unknown_tool"


@pytest.mark.parametrize(
    "over, rule",
    [
        ({"speed": 0.3}, "param:speed"),
        ({"z": 0.0}, "param:z"),
        ({"x": float("nan")}, "param:x"),
        ({"x": float("inf")}, "param:x"),
        ({"x": True}, "param:x"),  # bool is an int subclass; must not pass as a number
        ({"x": "0.1"}, "param:x"),
        ({"x": 0.45, "y": 0.0}, "keepout:operator_station"),
        ({"force": 9000}, "args"),  # undeclared argument
    ],
)
def test_denies_out_of_envelope(il, over, rule):
    d = move(il, **over)
    assert d.verdict is Verdict.DENY and d.rule == rule, d.reason


def test_missing_required_arg(il):
    d = il.check(ToolCall("a1", "move_arm", {"x": 0, "y": 0, "z": 0.4}))
    assert d.rule == "param:speed" and "missing" in d.reason


def test_optional_arg_may_be_omitted(il):
    assert il.check(ToolCall("a1", "set_conveyor", {"speed": 0.2})).allowed


def test_enum_and_pattern(il):
    assert not il.check(ToolCall("a1", "read_sensor", {"sensor": "door"})).allowed
    d = il.check(ToolCall("a1", "load_program", {"name": "x; rm -rf /"}))
    assert d.verdict is Verdict.DENY and d.rule == "param:name"


def test_rate_limit_sliding_window(il, clock):
    for _ in range(5):
        assert move(il).allowed
    assert move(il).rule == "rate"
    clock.t += 1.0
    assert move(il).allowed


def test_rate_limit_is_per_agent(il):
    for _ in range(5):
        move(il, agent="a1")
    assert move(il, agent="a2").allowed


# ---------------------------------------------------------- approval / HOLD


def test_hold_without_approver_blocks(il):
    d = il.check(ToolCall("a1", "load_program", {"name": "pick_v2"}))
    assert d.verdict is Verdict.HOLD and not d.allowed


@pytest.mark.parametrize("answer, verdict", [(True, Verdict.ALLOW), (False, Verdict.DENY)])
def test_approver_decides(answer, verdict):
    seen = []
    il = Interlock(Policy.from_file(CELL), approver=lambda c: seen.append(c) or answer)
    d = il.check(ToolCall("a1", "load_program", {"name": "pick_v2"}))
    assert d.verdict is verdict and len(seen) == 1
    assert il.locked_out() == {}  # operator rejection is not an agent violation


# ----------------------------------------------------------------- lockout


def test_repeated_violations_lock_agent_out(il):
    for _ in range(3):
        move(il, speed=5.0)
    assert "a1" in il.locked_out()
    d = il.check(ToolCall("a1", "read_joint_states", {}))
    assert d.verdict is Verdict.LOCKOUT
    assert il.check(ToolCall("a2", "read_joint_states", {})).allowed  # other agents unaffected


def test_violations_outside_window_do_not_accumulate(il, clock):
    move(il, speed=5.0)
    move(il, speed=5.0)
    clock.t += 301
    move(il, speed=5.0)
    assert il.locked_out() == {}


def test_release_needs_operator_and_is_audited(il):
    for _ in range(3):
        move(il, speed=5.0)
    with pytest.raises(ValueError):
        il.release("a1", operator="")
    assert il.release("a1", operator="m.mcmorris")
    assert move(il).allowed
    assert il.release("a1", operator="m.mcmorris") is False
    assert [r for r in il.audit.records if r["kind"] == "release"][0]["operator"] == "m.mcmorris"


def test_manual_lockout(il):
    il.lockout("a1", operator="ops", reason="suspicious prompt")
    assert move(il).verdict is Verdict.LOCKOUT


# ------------------------------------------------------------------- E-stop


def test_estop_blocks_actuate_only(il):
    il.estop(source="light_curtain", reason="beam broken")
    assert move(il).verdict is Verdict.LOCKOUT
    assert il.check(ToolCall("a1", "read_joint_states", {})).allowed
    assert il.check(ToolCall("a1", "write_log_note", {"text": "stopped"})).allowed
    il.reset_estop(operator="m.mcmorris")
    assert move(il).allowed


def test_estop_does_not_count_as_agent_violation(il):
    il.estop(source="plc")
    for _ in range(5):
        move(il)
    assert il.locked_out() == {}


# ------------------------------------------------------------- observe mode


def observe_policy():
    return Policy.from_toml(CELL.read_text().replace('mode = "enforce"', 'mode = "observe"'))


def test_observe_mode_logs_but_lets_through():
    il = Interlock(observe_policy())
    d = move(il, speed=5.0)
    assert d.verdict is Verdict.DENY and not d.enforced and d.allowed
    for _ in range(5):
        move(il, speed=5.0)
    assert il.locked_out() == {}


def test_observe_mode_still_honours_estop():
    il = Interlock(observe_policy())
    il.estop(source="plc")
    d = move(il)
    assert d.verdict is Verdict.LOCKOUT and d.enforced and not d.allowed


# ------------------------------------------------------------------- guard


def test_guarded_decorator_maps_positional_args(il):
    calls = []

    @guarded(il, "a1")
    def move_arm(x, y, z, speed):
        calls.append((x, y, z, speed))
        return "moved"

    assert move_arm(0.1, 0.1, 0.4, speed=0.1) == "moved"
    with pytest.raises(InterlockBlocked) as e:
        move_arm(0.1, 0.1, 0.4, 3.0)
    assert e.value.decision.rule == "param:speed"
    assert len(calls) == 1  # the blocked call never reached the tool


async def test_guarded_async(il):
    @guarded(il, "a1", name="read_sensor")
    async def sensor(sensor):
        return sensor

    assert await sensor("light_curtain") == "light_curtain"
    with pytest.raises(InterlockBlocked):
        await sensor("door")


# ------------------------------------------------------------------- audit


def test_audit_chain_detects_tampering(tmp_path, clock):
    log = tmp_path / "audit.jsonl"
    il = Interlock(Policy.from_file(CELL), audit=AuditLog(log), clock=clock)
    move(il)
    move(il, speed=9.0)
    il.estop(source="plc")
    records = load(log)
    assert len(records) == 3 and verify(records) == (True, None)

    records[1]["verdict"] = "allow"  # someone hides the denial
    assert verify(records) == (False, 1)

    lines = log.read_text().splitlines()
    del lines[0]  # someone deletes a record
    assert verify([json.loads(x) for x in lines]) == (False, 0)


def test_audit_resumes_chain_across_restarts(tmp_path):
    log = tmp_path / "audit.jsonl"
    Interlock(Policy.from_file(CELL), audit=AuditLog(log)).check(ToolCall("a", "read_joint_states"))
    Interlock(Policy.from_file(CELL), audit=AuditLog(log)).check(ToolCall("a", "read_joint_states"))
    assert verify(load(log)) == (True, None)


# ------------------------------------------------------------------ policy


@pytest.mark.parametrize(
    "toml, msg",
    [
        ('[interlock]\nmode = "yolo"', "mode"),
        ('[tools.t]\nclass = "fly"', "class"),
        ('[tools.t]\nclass = "read"\nparams.p = { min = 2, max = 1 }', "min"),
        ('[tools.t]\nclass = "read"\nparams.p = { maxx = 1 }', "unknown keys"),
        ('[tools.t]\nclass = "read"\nparams.p = { pattern = "(" }', "pattern"),
        ('[tools.t]\nclass = "read"\nrate = { max = 0, per_s = 1 }', "rate"),
        ('[tools.t]\nclass = "read"\n[[tools.t.keepout]]\nx = [1]', "keepout"),
        ('[interlock]\nestop_blocks = ["warp"]', "estop_blocks"),
    ],
)
def test_bad_policies_fail_at_load(toml, msg):
    with pytest.raises(PolicyError, match=msg):
        Policy.from_toml(toml)


def test_agent_allowlist():
    p = Policy.from_toml('[tools.t]\nclass = "read"\nagents = ["ops"]')
    il = Interlock(p)
    assert il.check(ToolCall("ops", "t")).allowed
    assert il.check(ToolCall("intruder", "t")).rule == "agent"


# --------------------------------------------------------------------- cli


def test_cli(capsys, tmp_path):
    assert cli(["validate", str(CELL)]) == 0
    assert cli(["check", str(CELL), "--tool", "move_arm", "--args", json.dumps(OK_MOVE)]) == 0
    assert cli(["check", str(CELL), "--tool", "move_arm", "--args", '{"x": 9}']) == 2
    assert cli(["bench", str(CELL), "--tool", "read_joint_states", "-n", "1000"]) == 0
    bad = tmp_path / "bad.toml"
    bad.write_text('[tools.t]\nclass = "nope"')
    assert cli(["validate", str(bad)]) == 1
