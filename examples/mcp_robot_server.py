"""A simulated robot-cell MCP server (official MCP Python SDK 2.x).

On its own it executes whatever it is asked to. Put the interlock in front.

stdio:

    interlock mcp-proxy --policy policies/robot_cell.toml --agent planner-01 \\
        --state /tmp/cell-latch.json -- python examples/mcp_robot_server.py

Streamable HTTP (server on :8081, gateway on :8080, clients use :8080/mcp):

    python examples/mcp_robot_server.py --http 8081
    interlock mcp-http --policy policies/robot_cell.toml --agent planner-01 \\
        --upstream http://127.0.0.1:8081/mcp --listen 127.0.0.1:8080

CELL_LIGHT_CURTAIN=breached simulates someone stepping into the cell: the
policy's light_curtain trip reads the result and latches the E-stop.
"""

import os
import sys

from mcp.server.mcpserver import MCPServer

server = MCPServer("robot-cell")


@server.tool()
def move_arm(x: float, y: float, z: float, speed: float) -> str:
    """Move the arm's tool centre point to (x, y, z) metres at `speed` m/s."""
    return f"arm moved to ({x}, {y}, {z}) at {speed} m/s"


@server.tool()
def read_sensor(sensor: str) -> dict:
    """Read a cell sensor: force_torque, light_curtain or temp_spindle."""
    if sensor == "light_curtain":
        return {"sensor": sensor, "value": os.environ.get("CELL_LIGHT_CURTAIN", "clear")}
    return {"sensor": sensor, "value": "nominal"}


@server.tool()
def format_controller_disk() -> str:
    """Wipe the robot controller. Not in the policy, so the gateway hides and blocks it."""
    return "controller wiped"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--http":
        server.run("streamable-http", host="127.0.0.1", port=int(sys.argv[2]))
    else:
        server.run("stdio")
