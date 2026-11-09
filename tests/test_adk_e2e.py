"""End to end through a real ADK Runner, with a scripted model instead of Gemini.

The script: read the light curtain (it reports "breached"), then try to move
the arm. Expected: the trip latches the E-stop, the move never executes, and
the model is told why at each step. No API key or network needed.
"""

from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from google.adk.agents import Agent  # noqa: E402
from google.adk.apps import App  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402

from agent_interlock import Interlock  # noqa: E402
from agent_interlock.adapters.adk import InterlockPlugin  # noqa: E402

CELL = Path(__file__).resolve().parent.parent / "policies" / "robot_cell.toml"
MOVE = {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1}


class ScriptedLlm(BaseLlm):
    """Plays back one function call per turn, then a final text answer."""

    script: list = []
    seen: list = []

    async def generate_content_async(self, llm_request, stream=False):
        # Each request carries the whole history, so rebuild the list every turn.
        self.seen = [
            part.function_response.response
            for content in llm_request.contents or []
            for part in content.parts or []
            if part.function_response
        ]
        turn = sum(1 for c in llm_request.contents or [] if c.role == "model")
        if turn < len(self.script):
            name, args = self.script[turn]
            part = types.Part(function_call=types.FunctionCall(name=name, args=args))
        else:
            part = types.Part(text="done")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


async def _run(il, script, light_curtain="breached", arm_raises=False):
    executed = []

    def read_sensor(sensor: str) -> dict:
        """Read a cell sensor."""
        executed.append("read_sensor")
        return {"sensor": sensor, "value": light_curtain}

    def move_arm(x: float, y: float, z: float, speed: float) -> dict:
        """Move the arm."""
        executed.append("move_arm")
        if arm_raises:
            raise RuntimeError("servo drive fault")
        return {"status": "moved"}

    llm = ScriptedLlm(model="scripted", script=script, seen=[])
    agent = Agent(name="cell_operator", model=llm, tools=[read_sensor, move_arm])
    app = App(name="cell", root_agent=agent, plugins=[InterlockPlugin(il)])
    runner = InMemoryRunner(app=app)
    s = await runner.session_service.create_session(app_name="cell", user_id="op")
    msg = types.Content(role="user", parts=[types.Part(text="go")])
    async for _ in runner.run_async(user_id="op", session_id=s.id, new_message=msg):
        pass
    return executed, llm.seen


async def test_breached_curtain_stops_the_next_move():
    il = Interlock.from_file(CELL)
    script = [("read_sensor", {"sensor": "light_curtain"}), ("move_arm", MOVE)]
    executed, seen = await _run(il, script)
    assert executed == ["read_sensor"]  # the move never reached the tool
    assert il.estop_latched
    assert seen[0]["interlock"]["estop"] == "latched"
    assert seen[1]["status"] == "blocked_by_interlock" and seen[1]["rule"] == "estop"


async def test_clear_curtain_lets_the_move_run():
    il = Interlock.from_file(CELL)
    script = [("read_sensor", {"sensor": "light_curtain"}), ("move_arm", MOVE)]
    executed, seen = await _run(il, script, light_curtain="clear")
    assert executed == ["read_sensor", "move_arm"] and not il.estop_latched
    assert "interlock" not in seen[0]


async def test_drive_fault_latches_and_blocks_retry():
    il = Interlock.from_file(CELL)
    executed, seen = await _run(il, [("move_arm", MOVE), ("move_arm", MOVE)], arm_raises=True)
    assert executed == ["move_arm"]  # the retry was stopped by the latched E-stop
    assert seen[0]["status"] == "tool_fault"
    assert seen[1]["rule"] == "estop"


async def test_blocked_call_does_not_trip():
    """ADK hands the blocked-reason dict to after_tool_callback too. It has no
    sensor value, so evaluating the trip on it would latch a false E-stop."""
    il = Interlock.from_file(CELL)
    il.lockout("cell_operator", operator="test")
    executed, seen = await _run(il, [("read_sensor", {"sensor": "light_curtain"})])
    assert executed == [] and seen[0]["verdict"] == "lockout"
    assert not il.estop_latched
