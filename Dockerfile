# agent-interlock MCP gateway (Streamable HTTP). Core is stdlib-only: no deps.
FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --uid 10001 --no-create-home interlock
COPY policies ./policies
USER interlock
# Cloud Run sets PORT; the gateway then listens on 0.0.0.0:$PORT.
ENTRYPOINT ["interlock", "mcp-http"]
CMD ["--policy", "policies/robot_cell.toml", "--upstream", "http://127.0.0.1:8081/mcp", "--audit", "-"]
