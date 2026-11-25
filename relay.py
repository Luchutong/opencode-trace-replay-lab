"""Forward bounded model requests to one fixed provider or a local test stub."""

import http.client
import http.server
import json
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from hashlib import sha256

RECORDS = {"control": "AZURE", "variant": "CORAL"}
BASE_COLOR = "AMBER"
LAYOUTS = {"plain": "Sample status: {color}", "key-value": "sample_status={color}"}
HOST = "https://api.deepseek.com/chat/completions"
ENDPOINT = "/v1/chat/completions"
RELAY_LOG = "relay.requests.jsonl"
RELAY_MANIFEST_VERSION = "1.1"
MAX_REQUEST = 512 * 1024
MAX_RESPONSE = 2 * 1024 * 1024


def format_record(color, layout):
    return LAYOUTS[layout].format(color=color) + "\n"


def fixture_reads(text):
    return [
        {"color": color, "layout": layout}
        for color in (BASE_COLOR, *RECORDS.values())
        for layout in LAYOUTS
        if format_record(color, layout).strip() in text
    ]


def digest(value):
    return sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def observed_tool_messages(messages, user_index, marker_map):
    rows = []
    for index, message in enumerate(messages[user_index + 1 :], user_index + 1):
        if message.get("role") != "tool":
            continue
        content = message.get("content")
        if isinstance(content, str):
            texts = [content]
        elif isinstance(content, list):
            texts = [
                item["text"]
                for item in content
                if isinstance(item, dict)
                and item.get("type") == "text"
                and isinstance(item.get("text"), str)
            ]
        else:
            texts = []
        rows.append(
            {
                "message_index": index,
                "role": "tool",
                "tool_call_id": message.get("tool_call_id"),
                "content_sha256": digest(content),
                "text_sha256": digest("".join(texts)),
                "markers": sorted(
                    name
                    for name, value in marker_map.items()
                    if any(value in text for text in texts)
                ),
            }
        )
    return rows


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, address):
        super().__init__("localhost", timeout=100)
        self.address = address

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.address)


def read_body(handler):
    size = int(handler.headers.get("Content-Length", "0"))
    if not 0 < size <= MAX_REQUEST:
        raise ValueError("invalid request size")
    return handler.rfile.read(size)


def streamed_deltas(chunk):
    for line in chunk.splitlines():
        if not line.startswith(b"data:"):
            continue
        try:
            data = json.loads(line[5:])
        except ValueError:
            continue
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if isinstance(choice, dict) and choice.get("index", 0) == 0:
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    yield delta


def delta_tool_ids(delta):
    calls = delta.get("tool_calls")
    if isinstance(calls, list):
        for call in calls:
            call_id = call.get("id") if isinstance(call, dict) else None
            if isinstance(call_id, str) and call_id:
                yield call_id


def tapped(chunks, needle_map=None, record_tool_ids=False, progress_sha256=None):
    """Pass stream bytes through untouched while collecting usage and needle hits."""
    seen = []
    hits = set()
    tool_events = {}
    progress = None
    visible = ""
    ordinal = 0
    for chunk in chunks:
        if b'"usage"' in chunk:
            seen.append(chunk)
        if needle_map:
            for name, needle in needle_map.items():
                if needle.encode() in chunk:
                    hits.add(name)
        if record_tool_ids:
            for delta in streamed_deltas(chunk):
                ordinal += 1
                for call_id in delta_tool_ids(delta):
                    tool_events.setdefault(call_id, ordinal)
                content = delta.get("content")
                if progress_sha256 and visible is not None and isinstance(content, str):
                    visible += content
                    if len(visible) > 2048:
                        visible = None
                    elif visible.rstrip().endswith("}"):
                        try:
                            value = json.loads(visible)
                        except ValueError:
                            pass
                        else:
                            if (
                                isinstance(value, dict)
                                and digest(value) == progress_sha256
                            ):
                                progress = ordinal
                                visible = None
        yield chunk
    yield {
        "usage_chunks": seen,
        "needle_hits": sorted(hits),
        "tool_call_ids": sorted(tool_events),
        "tool_events": tool_events,
        "progress_event": progress,
    }


def last_usage(collected):
    for chunk in reversed(collected):
        for line in chunk.decode("utf-8", "replace").splitlines():
            if not line.startswith("data:") or b'"usage"' not in chunk:
                continue
            try:
                usage = json.loads(line[5:].strip()).get("usage")
            except json.JSONDecodeError:
                continue
            if usage:
                return usage
    return None


def reply(handler, status, content_type, chunks):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.close_connection = True
    remaining = MAX_RESPONSE
    summary = None
    for chunk in chunks:
        if isinstance(chunk, dict):
            summary = chunk
            continue
        remaining -= len(chunk)
        if remaining < 0:
            raise ValueError("response size limit exceeded")
        handler.wfile.write(chunk)
        handler.wfile.flush()
    return summary


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def bridge(port, address):
    """Inside the private network namespace, bridge exactly one route to Unix IPC."""

    class Handler(QuietHandler):
        def do_POST(self):
            if self.path != ENDPOINT:
                self.send_error(404)
                return
            conn = UnixConnection(address)
            try:
                conn.request(
                    "POST",
                    ENDPOINT,
                    read_body(self),
                    {"Content-Type": "application/json"},
                )
                response = conn.getresponse()
                reply(
                    self,
                    response.status,
                    response.getheader("Content-Type", "application/json"),
                    iter(response.fp.readline, b""),
                )
            finally:
                conn.close()

    return http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)


def stub(body):
    """A deterministic tool-call exchange for the fixed, harmless fixtures."""
    messages = body["messages"]
    user = max(i for i, msg in enumerate(messages) if msg["role"] == "user")
    previous_tool = next(
        (m for m in reversed(messages[user + 1 :]) if m["role"] == "tool"), None
    )
    if previous_tool:
        output = json.dumps(previous_tool)
        hits = fixture_reads(output)
        code = hits[0]["color"] if hits else None
        delta = {"content": code or "CHECKPOINT_READY"}
        reason = "stop"
    else:
        path = (
            "/project/overview.txt"
            if "overview.txt" in str(messages[user]["content"])
            else "/project/record.txt"
        )
        names = [t["function"]["name"] for t in body["tools"]]
        read = next(name for name in names if name.lower() == "read")
        delta = {
            "tool_calls": [
                {
                    "index": 0,
                    "id": f"call_fixture_{user}",
                    "type": "function",
                    "function": {
                        "name": read,
                        "arguments": json.dumps({"filePath": path}),
                    },
                }
            ]
        }
        reason = "tool_calls"
    envelope = {
        "id": "chatcmpl-fixture",
        "model": body["model"],
        "created": 0,
        "object": "chat.completion.chunk",
    }
    for part, finish in [({"role": "assistant", **delta}, None), ({}, reason)]:
        chunk = dict(
            envelope, choices=[{"index": 0, "delta": part, "finish_reason": finish}]
        )
        yield ("data: " + json.dumps(chunk) + "\n\n").encode()
    usage = dict(
        envelope,
        choices=[],
        usage={"prompt_tokens": 32, "completion_tokens": 8, "total_tokens": 40},
    )
    yield ("data: " + json.dumps(usage) + "\n\ndata: [DONE]\n\n").encode()


@contextmanager
def provider_relay(
    socket_path,
    log,
    *,
    key,
    model,
    budget=7,
    max_tokens=512,
    allowed_tools=None,
    needles=None,
    evidence_markers=None,
    progress_sha256=None,
    stub_fn=None,
    upstream_timeout=25,
    disable_thinking=True,
):
    lock = threading.Lock()
    count = 0
    opener = urllib.request.build_opener(NoRedirect)
    allowed = {"read", "invalid"} if allowed_tools is None else set(allowed_tools)

    class Handler(QuietHandler):
        def do_POST(self):
            nonlocal count
            if self.path != ENDPOINT:
                self.send_error(404)
                return
            try:
                body = json.loads(read_body(self))
                if body["model"] != model or body.get("stream") is not True:
                    raise ValueError("unexpected model or request mode")
                messages = body["messages"]
                if not isinstance(messages, list):
                    raise TypeError("invalid messages")
                tools = [tool["function"]["name"] for tool in body.get("tools", [])]
                if not tools or set(tools) - allowed:
                    raise ValueError("unexpected tools advertised to model")
            except (ValueError, KeyError, TypeError):
                self.send_error(400)
                return
            with lock:
                if count >= budget:
                    self.send_error(400, "lab model request budget exhausted")
                    return
                count += 1
                ordinal = count
            tool_results = json.dumps(
                [m.get("content") for m in messages if m.get("role") == "tool"],
                ensure_ascii=False,
            )
            user_index = max(
                i for i, msg in enumerate(messages) if msg.get("role") == "user"
            )
            current_results = json.dumps(
                [
                    m.get("content")
                    for m in messages[user_index + 1 :]
                    if m.get("role") == "tool"
                ],
                ensure_ascii=False,
            )
            row = {
                "request": ordinal,
                "input_sha256": digest(body),
                "messages_sha256": digest(messages),
                "tools": tools,
                "model": model,
            }
            if evidence_markers is not None:
                row["observed_at_monotonic_ns"] = time.monotonic_ns()
                row["tool_message_observations"] = observed_tool_messages(
                    messages, user_index, evidence_markers
                )
            if needles is None:
                hits = fixture_reads(tool_results)
                row["tool_result_markers"] = sorted({hit["color"] for hit in hits})
                row["fixture_reads"] = hits
                row["current_turn_fixture_reads"] = fixture_reads(current_results)
            else:
                row["tool_result_markers"] = sorted(
                    name for name, needle in needles.items() if needle in tool_results
                )
                row["current_turn_markers"] = sorted(
                    name
                    for name, needle in needles.items()
                    if needle in current_results
                )
            started = time.monotonic()
            summary = None
            record_ids = evidence_markers is not None or progress_sha256 is not None
            try:
                if key is None:
                    row["status"] = 200
                    summary = reply(
                        self,
                        200,
                        "text/event-stream",
                        tapped(
                            (stub_fn or stub)(body),
                            needles,
                            record_ids,
                            progress_sha256,
                        ),
                    )
                else:
                    body["max_tokens"] = max_tokens
                    if disable_thinking:
                        body["thinking"] = {"type": "disabled"}
                    request = urllib.request.Request(
                        HOST,
                        json.dumps(body).encode(),
                        {
                            "Authorization": "Bearer " + key,
                            "Content-Type": "application/json",
                        },
                    )
                    try:
                        with opener.open(request, timeout=upstream_timeout) as response:
                            row["status"] = response.status
                            row["provider_request_id"] = response.headers.get(
                                "x-request-id"
                            )
                            stream = tapped(
                                iter(response.readline, b""),
                                needles,
                                record_ids,
                                progress_sha256,
                            )
                            summary = reply(
                                self,
                                response.status,
                                response.headers.get(
                                    "Content-Type", "text/event-stream"
                                ),
                                stream,
                            )
                    except urllib.error.HTTPError as exc:
                        row["status"] = exc.code
                        # The response body is unnecessary for this lab and can carry private information.
                        reply(
                            self,
                            400,
                            "application/json",
                            [
                                json.dumps(
                                    {"error": {"message": f"DeepSeek HTTP {exc.code}"}}
                                ).encode()
                            ],
                        )
            except (OSError, ValueError) as exc:
                row["transport_error"] = type(exc).__name__
            finally:
                if summary is not None:
                    row["usage"] = last_usage(summary["usage_chunks"])
                    row["response_markers"] = summary["needle_hits"]
                    if record_ids:
                        row["response_tool_call_ids"] = summary["tool_call_ids"]
                    if progress_sha256 is not None:
                        row["response_progress_event"] = summary["progress_event"]
                        row["response_tool_call_events"] = summary["tool_events"]
                row["duration_seconds"] = round(time.monotonic() - started, 3)
                with lock, log.open("a", encoding="utf-8") as file:
                    file.write(json.dumps(row) + "\n")

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        # Finish journal writes before the caller hashes the closed log.
        daemon_threads = False

    with Server(str(socket_path), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join()
