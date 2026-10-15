"""A simulated robot-cell MCP server (official MCP Python SDK 2.x).

On its own it executes whatever it is asked to. Put the interlock in front:

    interlock mcp-proxy --policy policies/robot_cell.toml --agent planner-01 \\
        --state /tmp/cell-latch.json -- python examples/mcp_robot_server.py

Claude Code (.mcp.json) or any other MCP client then points at that command
instead of at the server. See README "MCP gateway".
"""

from mcp.server.mcpserver import MCPServer

server = MCPServer("robot-cell")


@server.tool()
def move_arm(x: float, y: float, z: float, speed: float) -> str:
    """Move the arm's tool centre point to (x, y, z) metres at `speed` m/s."""
    return f"arm moved to ({x}, {y}, {z}) at {speed} m/s"


@server.tool()
def read_sensor(sensor: str) -> str:
    """Read a cell sensor: force_torque, light_curtain or temp_spindle."""
    return f"{sensor}: nominal"


@server.tool()
def format_controller_disk() -> str:
    """Wipe the robot controller. Not in the policy, so the gateway hides and blocks it."""
    return "controller wiped"


if __name__ == "__main__":
    server.run("stdio")
