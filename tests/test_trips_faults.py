"""Trips (result-side safety conditions) and tool faults, in the engine and the ADK plugin."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_interlock import Interlock, Policy, PolicyError, ToolCall, Verdict

CELL = Path(__file__).resolve().parent.parent / "policies" / "robot_cell.toml"
OK_MOVE = {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1}

BASE = """
[tools.read_sensor]
class = "read"
params.sensor = { enum = ["light_curtain", "force_torque"] }
"""


def policy(extra: str = "", head: str = "") -> Policy:
    return Policy.from_toml(f"[interlock]\n{head}\n{BASE}\n{extra}")


def curtain(value):
    return ToolCall("op", "read_sensor", {"sensor": "light_curtain"}), {"value": value}


# ------------------------------------------------------------------ policy


@pytest.mark.parametrize(
    "trip, msg",
    [
        ('field = "value"', "at least one of in, min, max"),
        ('in = ["x"]', "field must be"),
        ('field = "a..b"\nin = ["x"]', "field must be"),
        ('field = "v"\nin = []', "non-empty list"),
        ('field = "v"\nmin = 5\nmax = 1', "min 5 > max 1"),
        ('field = "v"\nmax = "high"', "max must be a number"),
        ('field = "v"\nin = ["x"]\nwhen = { sensr = "light_curtain" }', "undeclared params"),
        ('field = "v"\nin = ["x"]\nlevel = 3', "unknown keys"),
    ],
)
def test_bad_trips_fail_at_load(trip, msg):
    with pytest.raises(PolicyError, match=msg):
        policy(f"[[tools.read_sensor.trip]]\n{trip}")


def test_bad_estop_on_fault_class():
    with pytest.raises(PolicyError, match="estop_on_fault"):
        policy(head='estop_on_fault = ["move"]')


def test_defaults():
    p = policy()
    assert p.estop_on_fault == frozenset({"actuate"})
    assert p.tools["read_sensor"].trips == ()


# ------------------------------------------------------------------ engine


def test_trip_latches_estop_and_blocks_actuators():
    il = Interlock.from_file(CELL)
    assert il.check_result(*curtain("clear")) is None
    reason = il.check_result(*curtain("breached"))
    assert reason and "light_curtain" in reason
    assert il.estop_latched
    d = il.check(ToolCall("op", "move_arm", OK_MOVE))
    assert d.verdict is Verdict.LOCKOUT and d.rule == "estop"
    kinds = [r["kind"] for r in il.audit.records]
    assert kinds[-3:] == ["trip", "estop", "decision"]


@pytest.mark.parametrize("result", [{}, {"other": 1}, "light_curtain: nominal", None])
def test_missing_reading_trips(result):
    """Normally-closed wiring: no signal is a stop signal."""
    il = Interlock.from_file(CELL)
    call = ToolCall("op", "read_sensor", {"sensor": "light_curtain"})
    assert "missing" in il.check_result(call, result)


def test_trip_only_applies_when_args_match():
    il = Interlock.from_file(CELL)
    call = ToolCall("op", "read_sensor", {"sensor": "temp_spindle"})
    assert il.check_result(call, {}) is None and not il.estop_latched


@pytest.mark.parametrize(
    "result, trips",
    [
        ({"r": {"f": 10}}, False),
        ({"r": {"f": 151}}, True),
        ({"r": {"f": -1}}, True),
        ({"r": {"f": float("nan")}}, True),
        ({"r": {"f": True}}, True),  # bool is not a reading
        ({"r": {"f": "12"}}, True),
        ({"r": 5}, True),  # path goes through a non-dict
    ],
)
def test_range_trip_on_nested_field(result, trips):
    p = policy('[[tools.read_sensor.trip]]\nname = "force"\nfield = "r.f"\nmin = 0\nmax = 150')
    il = Interlock(p)
    call = ToolCall("op", "read_sensor", {"sensor": "force_torque"})
    assert (il.check_result(call, result) is not None) is trips


def test_trip_latches_in_observe_mode():
    il = Interlock(
        policy('[[tools.read_sensor.trip]]\nfield = "value"\nin = ["bad"]', 'mode = "observe"')
    )
    il.check_result(ToolCall("op", "read_sensor", {"sensor": "light_curtain"}), {"value": "bad"})
    assert il.estop_latched


def test_unknown_tool_result_is_ignored():
    il = Interlock.from_file(CELL)
    assert il.check_result(ToolCall("op", "nope", {}), {}) is None


def test_actuator_fault_latches_estop():
    il = Interlock.from_file(CELL)
    reason = il.fault(ToolCall("op", "move_arm", OK_MOVE), RuntimeError("encoder lost"))
    assert "encoder lost" in reason and il.estop_latched
    assert il.audit.records[-2]["kind"] == "tool_fault"


def test_read_fault_is_logged_not_latched():
    il = Interlock.from_file(CELL)
    assert il.fault(ToolCall("op", "read_sensor", {"sensor": "force_torque"}), OSError()) is None
    assert not il.estop_latched and il.audit.records[-1]["kind"] == "tool_fault"


def test_fault_on_unknown_tool_does_not_latch():
    il = Interlock.from_file(CELL)
    assert il.fault(ToolCall("op", "nope", {}), ValueError("x")) is None


def test_trip_estop_is_shared_through_state_file(tmp_path):
    state = tmp_path / "latch.json"
    a = Interlock.from_file(CELL, state_path=state)
    b = Interlock.from_file(CELL, state_path=state)
    a.check_result(*curtain("breached"))
    assert not b.check(ToolCall("other", "move_arm", OK_MOVE)).allowed


# ------------------------------------------------------- ADK plugin, stand-ins


def ctx(call_id):
    return SimpleNamespace(agent_name="cell_operator", function_call_id=call_id)


SENSOR = SimpleNamespace(name="read_sensor")
ARM = SimpleNamespace(name="move_arm")
LC = {"sensor": "light_curtain"}


@pytest.fixture
def plugin_and_il():
    pytest.importorskip("google.adk")
    from agent_interlock.adapters.adk import InterlockPlugin

    il = Interlock.from_file(CELL)
    return InterlockPlugin(il), il


def run(coro):
    return asyncio.run(coro)


def test_plugin_trip_annotates_result(plugin_and_il):
    p, il = plugin_and_il
    assert run(p.before_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c1"))) is None
    out = run(
        p.after_tool_callback(
            tool=SENSOR, tool_args=LC, tool_context=ctx("c1"), result={"value": "breached"}
        )
    )
    assert out["value"] == "breached" and out["interlock"]["estop"] == "latched"
    assert il.estop_latched


def test_plugin_clean_result_passes_unchanged(plugin_and_il):
    p, il = plugin_and_il
    run(p.before_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c1")))
    res = {"value": "clear"}
    assert (
        run(p.after_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c1"), result=res))
        is None
    )
    assert not il.estop_latched


def test_plugin_does_not_trip_on_its_own_block(plugin_and_il):
    """ADK runs after_tool_callback on the blocked-reason dict too. That must not trip."""
    p, il = plugin_and_il
    bad = {"sensor": "door"}
    blocked = run(p.before_tool_callback(tool=SENSOR, tool_args=bad, tool_context=ctx("c2")))
    assert blocked["status"] == "blocked_by_interlock"
    after = run(
        p.after_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c2"), result=blocked)
    )
    assert after is None and not il.estop_latched


def test_plugin_ignores_results_it_did_not_gate(plugin_and_il):
    p, il = plugin_and_il
    out = run(p.after_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("x"), result={}))
    assert out is None and not il.estop_latched


def test_plugin_actuator_fault(plugin_and_il):
    p, il = plugin_and_il
    run(p.before_tool_callback(tool=ARM, tool_args=OK_MOVE, tool_context=ctx("c3")))
    err = RuntimeError("drive fault")
    out = run(
        p.on_tool_error_callback(tool=ARM, tool_args=OK_MOVE, tool_context=ctx("c3"), error=err)
    )
    assert out["status"] == "tool_fault" and il.estop_latched
    # ADK then runs after_tool_callback on the fault dict: must not double-handle.
    after = run(
        p.after_tool_callback(tool=ARM, tool_args=OK_MOVE, tool_context=ctx("c3"), result=out)
    )
    assert after is None


def test_plugin_non_safety_fault_reraises(plugin_and_il):
    p, il = plugin_and_il
    run(p.before_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c4")))
    out = run(
        p.on_tool_error_callback(tool=SENSOR, tool_args=LC, tool_context=ctx("c4"), error=OSError())
    )
    assert out is None and not il.estop_latched


def test_plugin_pending_map_is_bounded(plugin_and_il, monkeypatch):
    from agent_interlock.adapters import adk

    monkeypatch.setattr(adk, "_MAX_PENDING", 3)
    p, _ = plugin_and_il
    for i in range(10):
        run(p.before_tool_callback(tool=SENSOR, tool_args=LC, tool_context=ctx(f"id{i}")))
    assert list(p._running) == ["id7", "id8", "id9"]
