# Architecture

Three views of the codebase (v0.2.0). GitHub renders these diagrams inline.

## 1. Modules and how they connect

Entry points on top. Every path into a tool goes through `Interlock.check()`.

```mermaid
flowchart TB
    subgraph clients["Who calls tools"]
        ADKAgent["Google ADK agent"]
        MCPClient["MCP client<br/>(Claude Code, Gemini CLI, ...)"]
        PyCode["Plain Python code"]
        Operator["Operator shell"]
    end

    subgraph entry["Entry points"]
        adk["adapters/adk.py<br/>InterlockPlugin<br/>before_tool_callback"]
        gw["mcp_gateway.py<br/>McpGateway + run_stdio"]
        guard["guard.py<br/>@guarded"]
        cli["cli.py<br/>interlock ..."]
    end

    subgraph core["Core (stdlib only)"]
        engine["engine.py<br/>Interlock.check()<br/>lockout · E-stop · reload"]
        policy["policy.py<br/>Policy · ToolRule · ParamRule<br/>KeepOut · RateLimit"]
        decision["decision.py<br/>ToolCall · Decision · Verdict"]
    end

    subgraph persist["Persistence"]
        audit["audit.py<br/>AuditLog (SHA-256 chain)"]
        state["state.py<br/>LatchStore (flock + atomic write)"]
    end

    toml[("policies/*.toml")]
    auditfile[("audit.jsonl")]
    latch[("latch.json<br/>shared by all processes")]
    server["Real tool / MCP server / robot"]

    ADKAgent --> adk
    MCPClient -->|stdio JSON-RPC| gw
    PyCode --> guard
    Operator --> cli

    adk --> engine
    gw --> engine
    guard --> engine
    cli -->|validate · check · bench · mcp-proxy| engine
    cli -->|estop · reset · release · status| state

    engine --> policy
    engine --> decision
    engine --> audit
    engine --> state
    policy -->|load + digest| toml
    audit --> auditfile
    state --> latch

    gw -->|only if allowed| server
    adk -->|only if allowed| server
    guard -->|only if allowed| server
```

## 2. What `check()` does, in order

The first check that fails decides the verdict. Anything not explicitly
allowed is denied.

```mermaid
flowchart TD
    start(["ToolCall(agent, tool, args)"]) --> sync["Sync latches from latch.json<br/>(other processes, operator CLI)"]
    sync --> lo{"Agent locked out?"}
    lo -->|yes| LOCK["LOCKOUT"]
    lo -->|no| known{"Tool in policy?"}
    known -->|no| DENY["DENY"]
    known -->|yes| es{"E-stop latched and<br/>tool class in estop_blocks?"}
    es -->|yes| LOCK
    es -->|no| ag{"Agent allowed<br/>for this tool?"}
    ag -->|no| DENY
    ag -->|yes| ex{"Undeclared args?<br/>(strict)"}
    ex -->|yes| DENY
    ex -->|no| pr{"Params OK?<br/>type · min/max · enum<br/>pattern · max_len · no NaN"}
    pr -->|no| DENY
    pr -->|yes| ko{"Target inside a<br/>keep-out zone?"}
    ko -->|yes| DENY
    ko -->|no| rt{"Rate limit<br/>exceeded?"}
    rt -->|yes| DENY
    rt -->|no| ap{"require_approval?"}
    ap -->|no| ALLOW["ALLOW"]
    ap -->|yes| who{"Approver<br/>configured?"}
    who -->|no| HOLD["HOLD"]
    who -->|yes, approves| ALLOW
    who -->|yes, rejects| REJ["DENY (always enforced)"]

    DENY --> viol["Count violation<br/>(enforce mode only)"]
    viol --> n{"lockout_after reached<br/>within window?"}
    n -->|yes| latchagent["Latch agent lockout<br/>→ latch.json"]

    LOCK & DENY & HOLD & ALLOW & REJ --> log[("Audit record<br/>hash-chained")]

    classDef ok fill:#d8f3dc,stroke:#2d6a4f,color:#1b4332
    classDef bad fill:#ffe5e5,stroke:#c0392b,color:#7b241c
    classDef wait fill:#fff3cd,stroke:#b7950b,color:#7d6608
    class ALLOW ok
    class DENY,LOCK,REJ bad
    class HOLD wait
```

In **observe** mode, DENY and HOLD are logged but not enforced.
LOCKOUT (lockouts and the E-stop) and an operator's rejection are always
enforced.

## 3. MCP gateway: one session

```mermaid
sequenceDiagram
    autonumber
    participant C as MCP client
    participant G as interlock mcp-proxy
    participant I as Interlock
    participant S as MCP server
    participant L as latch.json

    C->>G: tools/list
    G->>S: tools/list (re-serialised)
    S-->>G: [move_arm, read_sensor, format_controller_disk]
    G-->>C: [move_arm, read_sensor] (unlisted tools hidden)

    C->>G: tools/call move_arm {speed: 0.1}
    G->>I: check()
    I->>L: stat (changed?)
    I-->>G: ALLOW
    G->>S: tools/call (re-serialised)
    S-->>G: result
    G-->>C: result

    C->>G: tools/call move_arm {speed: 3.0}
    G->>I: check()
    I-->>G: DENY param:speed
    Note over G,S: never forwarded
    G-->>C: result {isError: true, "Blocked ... speed=3.0 above max 0.25"}

    Note over L: operator runs `interlock estop`<br/>(or another gateway latches it)
    C->>G: tools/call move_arm {speed: 0.1}
    G->>I: check()
    I->>L: stat → changed → reload latches
    I-->>G: LOCKOUT estop
    G-->>C: result {isError: true, "E-stop latched ..."}
```

## File map

| Path | Role |
|---|---|
| `src/agent_interlock/engine.py` | `Interlock`: check pipeline, violation counting, lockout, E-stop, reload |
| `src/agent_interlock/policy.py` | TOML → compiled, validated `Policy` (fails at load, never at call time) |
| `src/agent_interlock/decision.py` | `ToolCall`, `Decision`, `Verdict` value types |
| `src/agent_interlock/audit.py` | Hash-chained JSONL audit log, `verify()` |
| `src/agent_interlock/state.py` | `LatchStore`: persistent, cross-process lockouts and E-stop |
| `src/agent_interlock/mcp_gateway.py` | stdio MCP proxy: gates `tools/call`, filters `tools/list` |
| `src/agent_interlock/adapters/adk.py` | Google ADK plugin and callback |
| `src/agent_interlock/guard.py` | `@guarded` decorator for any Python callable |
| `src/agent_interlock/cli.py` | `interlock` command |
| `policies/robot_cell.toml` | Example policy for a robot cell |
| `examples/` | Scripted demo, ADK agent, MCP robot server |
| `tests/` | 66 tests incl. real ADK and MCP SDK interop |
