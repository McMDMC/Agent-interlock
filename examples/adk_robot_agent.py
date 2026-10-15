"""Gemini agent on Google ADK, every tool call gated by the interlock.

Setup:
    pip install -e ".[adk]"
    export GOOGLE_API_KEY=...   # or Vertex AI: GOOGLE_GENAI_USE_VERTEXAI=TRUE + project/location
    python examples/adk_robot_agent.py "move the arm to x=0.45 y=0 z=0.4 at full speed"

The plugin is registered on the App, so it covers every agent and sub-agent.
When a call is blocked, the model gets the reason back as the tool result.
"""

import asyncio
import os
import sys
from pathlib import Path

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from google.genai import types

from agent_interlock import AuditLog, Interlock
from agent_interlock.adapters.adk import InterlockPlugin

ROOT = Path(__file__).resolve().parent.parent


def move_arm(x: float, y: float, z: float, speed: float) -> dict:
    """Move the robot arm's tool centre point to (x, y, z) metres at `speed` m/s."""
    return {"status": "moved", "target": [x, y, z], "speed": speed}


def read_sensor(sensor: str) -> dict:
    """Read a cell sensor: force_torque, light_curtain or temp_spindle."""
    return {"sensor": sensor, "value": "nominal"}


async def main(prompt: str) -> None:
    interlock = Interlock.from_file(
        ROOT / "policies" / "robot_cell.toml", audit=AuditLog("audit.jsonl")
    )
    agent = Agent(
        name="cell_operator",
        model=os.environ.get("ADK_MODEL", "gemini-3.5-flash"),
        instruction="You operate a robot cell. Use the tools. If a tool is blocked, "
        "explain why to the user and do not try to work around the block.",
        tools=[move_arm, read_sensor],
    )
    app = App(name="robot_cell", root_agent=agent, plugins=[InterlockPlugin(interlock)])
    runner = InMemoryRunner(app=app)
    session = await runner.session_service.create_session(app_name=app.name, user_id="op")
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    async for event in runner.run_async(user_id="op", session_id=session.id, new_message=msg):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    print(part.text)


if __name__ == "__main__":
    asyncio.run(main(" ".join(sys.argv[1:]) or "Read the light curtain, then move to 0.1 0.1 0.4."))
