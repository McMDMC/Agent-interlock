"""MCP gateway for the Streamable HTTP transport.

    interlock mcp-http --policy cell.toml --agent planner-01 \\
        --upstream http://127.0.0.1:8081/mcp --listen 127.0.0.1:8080

A reverse proxy in front of one MCP endpoint. Clients point at the gateway's
``/mcp`` instead of the server. Same rules as the stdio gateway: blocked
``tools/call`` never reaches the server, ``tools/list`` shows only declared
tools, results of allowed calls go through the policy's trips. Each message
is re-serialised from what the gateway parsed; raw bytes are never relayed.

Spec 2026-07-28 makes every request a self-contained POST and mirrors body
fields into headers (``Mcp-Method``, ``Mcp-Name``, ``Mcp-Param-*``) so load
balancers can route without reading the body. That opens a split-brain risk:
the interlock checks the body, but something downstream could act on a
header that says otherwise. The spec requires any server that processes the
body to validate the headers against it. The gateway does that before the
policy check, rejects a mismatch with ``400`` / ``-32020 HeaderMismatch``,
writes it to the audit log, and forwards headers it regenerated itself.

Earlier protocol revisions (``initialize`` handshake, ``Mcp-Session-Id``,
``GET`` event streams, ``DELETE``) are relayed with the same gating. They
carry no mirrored headers, so client-supplied ``Mcp-Param-*`` are dropped.

Security defaults: listens on 127.0.0.1; a request with an ``Origin`` header
that is not allow-listed gets ``403`` (DNS-rebinding guard, required by the
spec); request bodies are capped. Authentication is passed through: the
gateway forwards ``Authorization`` and relays ``401`` / ``WWW-Authenticate``.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import json
import re
import ssl
import sys
import threading
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .decision import ToolCall
from .mcp_gateway import INVALID_REQUEST, PARSE_ERROR, McpGateway

MODERN = "2026-07-28"  # first revision with mirrored headers; later ones compare >= this
HEADER_MISMATCH = -32020
INTERNAL_ERROR = -32603
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"
NAME_FIELD = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
ROUTING_HEADERS = ("mcp-protocol-version", "mcp-method", "mcp-name")
PARAM_PREFIX = "mcp-param-"

# Request headers the gateway never copies upstream. Routing headers are
# regenerated from the body; Origin was validated here; Accept-Encoding is
# dropped so the upstream answers in plain text the gateway can parse.
_REQ_DROP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
        "trailer", "transfer-encoding", "upgrade", "host", "content-length", "origin",
        "accept-encoding", "mcp-method", "mcp-name",
    }
)  # fmt: skip
_RESP_DROP = frozenset(
    {
        "connection", "keep-alive", "transfer-encoding", "content-length",
        "content-encoding", "trailer", "upgrade", "date", "server",
    }
)  # fmt: skip

_B64 = re.compile(r"=\?base64\?(.*)\?=")
_HEADER_SAFE = re.compile(r"[\x20-\x7E]*")
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_MAX_SCHEMA_DEPTH = 32
_MAX_RESUME = 10_000
_SCHEMA_PAGES = 20


class Rejected(Exception):
    """A request the gateway refuses before it reaches the policy check."""

    def __init__(self, code: int, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


# ------------------------------------------------------- header value codec


def encode_header_value(value: str) -> str:
    """Spec "Value Encoding": plain if header-safe, else ``=?base64?...?=``."""
    if _HEADER_SAFE.fullmatch(value) and value == value.strip() and not _B64.fullmatch(value):
        return value
    return f"=?base64?{base64.b64encode(value.encode()).decode('ascii')}?="


def decode_header_value(value: str) -> str | None:
    """Inverse of encode. A malformed or non-canonical sentinel decodes to None (never matches)."""
    m = _B64.fullmatch(value)
    if m is None:
        return value
    try:
        raw = base64.b64decode(m.group(1), validate=True)
        if base64.b64encode(raw).decode("ascii") != m.group(1):
            return None
        return raw.decode()
    except (binascii.Error, UnicodeDecodeError):
        return None


def _render(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float | str):
        return str(value)
    return None


def header_map(schema: Any, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], str]:
    """Property path -> ``x-mcp-header`` token, following only ``properties`` chains (spec)."""
    out: dict[tuple[str, ...], str] = {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict) or len(path) >= _MAX_SCHEMA_DEPTH:
        return out
    for key, sub in props.items():
        if not isinstance(sub, dict):
            continue
        token = sub.get("x-mcp-header")
        if isinstance(token, str) and _TOKEN.fullmatch(token):
            out[(*path, key)] = token
        out.update(header_map(sub, (*path, key)))
    return out


def expected_param_headers(
    hmap: dict[tuple[str, ...], str], args: dict[str, Any]
) -> dict[str, tuple[str, str]]:
    """lower-case header name -> (header name, plain value) a conforming client must send."""
    out = {}
    for path, token in hmap.items():
        node: Any = args
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node is not None and (rendered := _render(node)) is not None:
            name = f"Mcp-Param-{token}"
            out[name.lower()] = (name, rendered)
    return out


def _one(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    values = [v for k, v in headers if k.lower() == name]
    if len(values) > 1:
        # First-copy and last-copy readers would disagree. Refuse.
        raise Rejected(HEADER_MISMATCH, f"{name} header appears more than once")
    return values[0] if values else None


def is_modern(version: str | None) -> bool:
    return version is not None and version >= MODERN


def validate_routing_headers(headers: list[tuple[str, str]], msg: dict[str, Any]) -> None:
    """Check MCP-Protocol-Version, Mcp-Method and Mcp-Name against the body (spec: Server
    Validation).

    Mirrored headers are required from 2026-07-28 on. On earlier revisions
    they are optional, but if present they must still match.
    """
    version = _one(headers, "mcp-protocol-version")
    modern = is_modern(version)
    method = msg.get("method")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    mh = _one(headers, "mcp-method")
    if method is not None:
        if mh is None and modern:
            raise Rejected(HEADER_MISMATCH, "missing Mcp-Method header")
        if mh is not None and mh != method:
            raise Rejected(HEADER_MISMATCH, "Mcp-Method header does not match body method")
    elif mh is not None:
        raise Rejected(HEADER_MISMATCH, "Mcp-Method header on a message without a method")

    nh = _one(headers, "mcp-name")
    if (field := NAME_FIELD.get(method)) is not None:
        if nh is None:
            if modern:
                raise Rejected(HEADER_MISMATCH, "missing Mcp-Name header")
        elif decode_header_value(nh) != params.get(field):
            raise Rejected(HEADER_MISMATCH, f"Mcp-Name header does not match params.{field}")
    elif nh is not None:
        raise Rejected(HEADER_MISMATCH, f"Mcp-Name header is not defined for {method!r}")

    meta = params.get("_meta")
    if modern and isinstance(meta, dict) and PROTOCOL_VERSION_META in meta:
        if meta[PROTOCOL_VERSION_META] != version:
            raise Rejected(HEADER_MISMATCH, "MCP-Protocol-Version header does not match _meta")


def client_param_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    """lower-case ``Mcp-Param-*`` name -> decoded value. Duplicates or bad encoding: reject."""
    out: dict[str, str] = {}
    for k, v in headers:
        key = k.lower()
        if not key.startswith(PARAM_PREFIX):
            continue
        if key in out:
            raise Rejected(HEADER_MISMATCH, f"{k} header appears more than once")
        decoded = decode_header_value(v)
        if decoded is None:
            raise Rejected(HEADER_MISMATCH, f"{k} header has a malformed base64 value")
        out[key] = decoded
    return out


# ------------------------------------------------------------- SSE framing


def iter_sse(lines: Iterable[bytes]) -> Iterator[dict[str, str] | str]:
    """Yield SSE events as {field: value} dicts, and comment lines as str (keep-alives)."""
    event: dict[str, str] = {}
    data: list[str] = []
    for raw in lines:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data or event:
                if data:
                    event["data"] = "\n".join(data)
                yield event
            event, data = {}, []
            continue
        if line.startswith(":"):
            yield line
            continue
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "data":
            data.append(value)
        elif name in ("id", "event", "retry"):
            event[name] = value
    if data:
        event["data"] = "\n".join(data)
        yield event


def format_sse(event: dict[str, str]) -> bytes:
    out = []
    for key in ("event", "id", "retry"):
        if key in event and "\n" not in event[key] and "\r" not in event[key]:
            out.append(f"{key}: {event[key]}\n")
    out.append(f"data: {event.get('data', '')}\n\n")
    return "".join(out).encode()


def _dumps(msg: Any) -> str:
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- gateway

_LIST = "tools/list"  # marker for a pending tools/list (vs a ToolCall)


class HttpGateway:
    """Policy, upstream and caches shared by every request thread."""

    def __init__(
        self,
        core: McpGateway,
        upstream: str,
        path: str = "/mcp",
        allowed_origins: Iterable[str] = (),
        max_body: int = 1 << 20,
        timeout: float = 300.0,
    ) -> None:
        u = urlsplit(upstream)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"upstream must be an http(s) URL, got {upstream!r}")
        self.core = core
        self.upstream = u
        self.path = path
        self.allowed_origins = frozenset(allowed_origins)
        self.max_body = max_body
        self.timeout = timeout
        self._lock = threading.Lock()
        self._schemas: dict[str, dict[tuple[str, ...], str]] = {}  # tool -> x-mcp-header map
        # (session id, json(id)) -> pending work for responses that arrive on a
        # resumed GET stream (pre-2026 sessions only).
        self._resume: OrderedDict[tuple[str, str], ToolCall | str] = OrderedDict()

    # ---- upstream I/O

    def connect(self, timeout: float | None) -> http.client.HTTPConnection:
        u = self.upstream
        if u.scheme == "https":
            return http.client.HTTPSConnection(
                u.hostname, u.port, timeout=timeout, context=ssl.create_default_context()
            )
        return http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)

    @property
    def upstream_target(self) -> str:
        query = f"?{self.upstream.query}" if self.upstream.query else ""
        return (self.upstream.path or "/") + query

    # ---- schema cache for Mcp-Param-* validation

    def learn(self, tools: Any) -> None:
        if not isinstance(tools, list):
            return
        with self._lock:
            for t in tools:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    self._schemas[t["name"]] = header_map(t.get("inputSchema"))

    def schema(self, tool: str) -> dict[tuple[str, ...], str] | None:
        with self._lock:
            return self._schemas.get(tool)

    def fetch_schemas(self, headers: dict[str, str], meta: Any) -> None:
        """Ask the upstream for tools/list (paginated) to learn x-mcp-header maps."""
        cursor = None
        for page in range(_SCHEMA_PAGES):
            params: dict[str, Any] = {}
            if isinstance(meta, dict):
                params["_meta"] = meta
            if cursor is not None:
                params["cursor"] = cursor
            body = {"jsonrpc": "2.0", "id": f"agent-interlock-schema-{page}", "method": _LIST}
            if params:
                body["params"] = params
            conn = self.connect(self.timeout)
            try:
                conn.request(
                    "POST",
                    self.upstream_target,
                    body=_dumps(body).encode(),
                    headers={**headers, "Mcp-Method": _LIST},
                )
                resp = conn.getresponse()
                result = _read_response(resp, body["id"])
            finally:
                conn.close()
            if not isinstance(result, dict):
                raise OSError("upstream tools/list failed")
            self.learn(result.get("tools"))
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str):
                return

    # ---- resumed streams (legacy sessions)

    def park(self, session: str, id_: Any, work: ToolCall | str) -> None:
        with self._lock:
            self._resume[(session, json.dumps(id_))] = work
            while len(self._resume) > _MAX_RESUME:
                self._resume.popitem(last=False)

    def unpark(self, session: str, id_: Any) -> ToolCall | str | None:
        with self._lock:
            return self._resume.pop((session, json.dumps(id_)), None)

    # ---- response processing

    def process(self, msg: Any, work: ToolCall | str | None) -> None:
        if work == _LIST:
            result = msg.get("result")
            if isinstance(result, dict):
                self.learn(result.get("tools"))
            self.core.filter_tools(result)
        elif isinstance(work, ToolCall):
            self.core.after_call(work, msg)

    # ---- server

    def serve(self, host: str, port: int) -> ThreadingHTTPServer:
        gateway = self

        class Handler(_Handler):
            gw = gateway

        srv = ThreadingHTTPServer((host, port), Handler)
        srv.daemon_threads = True
        return srv


def _read_response(resp: http.client.HTTPResponse, id_: Any) -> Any:
    """Return the ``result`` for ``id_`` from a JSON or SSE response, else None."""
    if resp.status != 200:
        resp.read()
        return None
    ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        msg = json.loads(resp.read())
        return msg.get("result") if isinstance(msg, dict) and msg.get("id") == id_ else None
    if ctype == "text/event-stream":
        for ev in iter_sse(resp):
            if isinstance(ev, dict) and ev.get("data"):
                try:
                    msg = json.loads(ev["data"])
                except ValueError:
                    continue
                if isinstance(msg, dict) and msg.get("id") == id_ and "method" not in msg:
                    return msg.get("result")
    return None


def _is_response(msg: Any) -> bool:
    return isinstance(msg, dict) and "id" in msg and "method" not in msg


class _Handler(BaseHTTPRequestHandler):
    gw: HttpGateway
    protocol_version = "HTTP/1.1"
    server_version = "agent-interlock"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        sys.stderr.write(f"interlock-http: {self.address_string()} {format % args}\n")

    # ---- small writers

    def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _plain(self, status: int, text: str, extra: dict[str, str] | None = None) -> None:
        self._send(status, text.encode(), "text/plain; charset=utf-8", extra)

    def _rpc_error(self, status: int, id_: Any, code: int, message: str) -> None:
        body = {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}
        self._send(status, _dumps(body).encode(), "application/json")

    # ---- gate checks shared by all methods

    def _admit(self) -> bool:
        if urlsplit(self.path).path != self.gw.path:
            self._plain(404, "Not Found")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.gw.allowed_origins:
            self._plain(403, "Invalid Origin header")
            return False
        return True

    def _forward_headers(self) -> dict[str, str]:
        return {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in _REQ_DROP and not k.lower().startswith(PARAM_PREFIX)
        }

    def _audit_reject(self, r: Rejected, msg: Any = None) -> None:
        method = msg.get("method") if isinstance(msg, dict) else None
        self.gw.core.interlock.audit.event(
            "mcp_rejected", agent=self.gw.core.agent, method=method, reason=r.message
        )

    # ---- HTTP methods

    def do_GET(self) -> None:  # noqa: N802
        if urlsplit(self.path).path == "/healthz":
            il = self.gw.core.interlock
            body = {"ok": True, "estop": il.estop_latched, "locked_out": sorted(il.locked_out())}
            self._send(200, _dumps(body).encode(), "application/json")
            return
        if self._admit():
            self._relay("GET", None, self._forward_headers(), None)

    def do_DELETE(self) -> None:  # noqa: N802
        if self._admit():
            self._relay("DELETE", None, self._forward_headers(), None)

    def do_POST(self) -> None:  # noqa: N802
        if not self._admit():
            return
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._plain(411, "Content-Length required")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.close_connection = True
            self._plain(411, "Content-Length required")
            return
        if length < 0 or length > self.gw.max_body:
            self.close_connection = True
            self._plain(413, "Request body too large")
            return
        try:
            msg = json.loads(self.rfile.read(length))
        except ValueError:
            self._rpc_error(400, None, PARSE_ERROR, "Parse error")
            return
        if not isinstance(msg, dict):
            self._rpc_error(400, None, INVALID_REQUEST, "Invalid Request: batches not supported")
            return

        raw = list(self.headers.items())
        id_ = msg.get("id")
        try:
            validate_routing_headers(raw, msg)
        except Rejected as r:
            self._audit_reject(r, msg)
            self._rpc_error(r.status, id_, r.code, r.message)
            return

        method = msg.get("method")
        modern = is_modern(self.headers.get("MCP-Protocol-Version"))
        headers = self._forward_headers()
        if method is not None:
            if self.headers.get("Mcp-Method") is not None:
                headers["Mcp-Method"] = method
            field = NAME_FIELD.get(method)
            params = msg.get("params")
            if field and self.headers.get("Mcp-Name") is not None and isinstance(params, dict):
                headers["Mcp-Name"] = encode_header_value(str(params.get(field)))

        work: ToolCall | str | None = None
        if method == "tools/call":
            if "id" not in msg:
                self._rpc_error(400, None, INVALID_REQUEST, "tools/call must be a request")
                return
            call, reply = self.gw.core.gate(msg)
            if reply is not None:
                status = 200 if "result" in reply else 400
                self._send(status, _dumps({"jsonrpc": "2.0", "id": id_, **reply}).encode(),
                           "application/json")  # fmt: skip
                return
            if modern:
                try:
                    headers.update(self._param_headers(call, raw, headers, msg))
                except Rejected as r:
                    self._audit_reject(r, msg)
                    self._rpc_error(r.status, id_, r.code, r.message)
                    return
            work = call
        elif method == _LIST and "id" in msg:
            work = _LIST
        self._relay("POST", msg, headers, work)

    def _param_headers(
        self,
        call: ToolCall,
        raw: list[tuple[str, str]],
        headers: dict[str, str],
        msg: dict[str, Any],
    ) -> dict[str, str]:
        """Validate the client's Mcp-Param-* against the tool schema and body; return canonical."""
        sent = client_param_headers(raw)
        hmap = self.gw.schema(call.tool)
        if hmap is None:
            if not sent:
                return {}  # nothing mirrored, nothing to disagree with; upstream validates
            self._fetch(headers, msg)
            hmap = self.gw.schema(call.tool)
            if hmap is None:
                raise Rejected(HEADER_MISMATCH, f"{call.tool!r} not found in upstream tools/list")
        expected = expected_param_headers(hmap, call.args)
        if {k: v for k, (_, v) in expected.items()} != sent:
            # The schema may have changed since we cached it. Look once more.
            self._fetch(headers, msg)
            expected = expected_param_headers(self.gw.schema(call.tool) or {}, call.args)
            if {k: v for k, (_, v) in expected.items()} != sent:
                raise Rejected(HEADER_MISMATCH, "Mcp-Param-* headers do not match arguments")
        return {name: encode_header_value(v) for name, v in expected.values()}

    def _fetch(self, headers: dict[str, str], msg: dict[str, Any]) -> None:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        try:
            self.gw.fetch_schemas(headers, params.get("_meta"))
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise Rejected(INTERNAL_ERROR, f"could not load tool schemas upstream: {e}", 502) from e

    # ---- relay

    def _relay(
        self,
        verb: str,
        msg: dict[str, Any] | None,
        headers: dict[str, str],
        work: ToolCall | str | None,
    ) -> None:
        body = _dumps(msg).encode() if msg is not None else None
        id_ = msg.get("id") if msg is not None else None
        session = self.headers.get("Mcp-Session-Id") or ""
        conn = self.gw.connect(self.gw.timeout)
        try:
            try:
                conn.request(verb, self.gw.upstream_target, body=body, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                self.gw.core.interlock.audit.event("mcp_upstream_error", error=str(e)[:300])
                if verb == "POST" and id_ is not None:
                    self._rpc_error(502, id_, INTERNAL_ERROR, "upstream MCP server unavailable")
                else:
                    self._plain(502, "upstream MCP server unavailable")
                return
            self._relay_response(resp, id_, work, session)
        finally:
            conn.close()

    def _relay_response(
        self, resp: http.client.HTTPResponse, id_: Any, work: ToolCall | str | None, session: str
    ) -> None:
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        passthrough = {
            k: v
            for k, v in resp.getheaders()
            if k.lower() not in _RESP_DROP and k.lower() != "content-type"
        }

        if ctype == "text/event-stream":
            self._relay_sse(resp, passthrough, id_, work, session)
            return

        data = resp.read(self.gw.max_body * 16 + 1)
        if ctype == "application/json" and data:
            try:
                out = json.loads(data)
            except ValueError:
                out = None
            if isinstance(out, dict):
                if work is not None and _is_response(out) and out.get("id") == id_:
                    self.gw.process(out, work)
                self._send(resp.status, _dumps(out).encode(), "application/json", passthrough)
                return
            if 200 <= resp.status < 300:
                self._plain(502, "upstream sent a malformed JSON-RPC message")
                return
        # Empty 202s, auth challenges, plain-text errors: not MCP messages, relay as-is.
        self._send(resp.status, data, resp.getheader("Content-Type") or "text/plain", passthrough)

    def _relay_sse(
        self,
        resp: http.client.HTTPResponse,
        headers: dict[str, str],
        id_: Any,
        work: ToolCall | str | None,
        session: str,
    ) -> None:
        self.close_connection = True  # body ends when the stream ends
        self.send_response(resp.status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        for k, v in headers.items():
            if k.lower() != "cache-control":
                self.send_header(k, v)
        self.end_headers()
        done = work is None
        try:
            for ev in iter_sse(resp):
                if isinstance(ev, str):
                    self.wfile.write(ev.encode() + b"\n\n")
                    self.wfile.flush()
                    continue
                if ev.get("data"):
                    try:
                        msg = json.loads(ev["data"])
                    except ValueError:
                        continue  # not a JSON-RPC message: drop it rather than relay unchecked
                    if not isinstance(msg, dict):
                        continue
                    if _is_response(msg):
                        if not done and msg.get("id") == id_:
                            self.gw.process(msg, work)
                            done = True
                        elif session:
                            self.gw.process(msg, self.gw.unpark(session, msg.get("id")))
                    ev = {**ev, "data": _dumps(msg)}
                self.wfile.write(format_sse(ev))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away; closing the upstream stream cancels the request
        except (OSError, http.client.HTTPException):
            pass  # upstream dropped; client may resume with Last-Event-ID
        finally:
            if not done and session and work is not None:
                self.gw.park(session, id_, work)


def serve_http(gateway: HttpGateway, host: str, port: int, policy_path: str | None = None) -> None:
    """Run until interrupted. SIGHUP reloads the policy (same as the stdio gateway)."""
    from .mcp_gateway import install_reload

    srv = gateway.serve(host, port)
    if policy_path is not None:
        install_reload(gateway.core, policy_path)
    print(
        f"interlock: MCP gateway on http://{host}:{srv.server_port}{gateway.path} "
        f"-> {gateway.upstream.geturl()}",
        file=sys.stderr,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


__all__ = [
    "HttpGateway",
    "Rejected",
    "decode_header_value",
    "encode_header_value",
    "header_map",
    "serve_http",
    "validate_routing_headers",
]
