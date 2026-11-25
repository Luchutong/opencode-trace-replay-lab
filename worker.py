"""Run one OpenCode phase inside the namespace."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from history import projection
from relay import bridge, digest

ADDRESS = "http://127.0.0.1:4096"
MODEL = "lab/deepseek-flash"
BINARY = "/runtime/opencode"
OUTPUT = Path("/output")
SURVEY = (
    "Read overview.txt with the read tool once. Then reply with only CHECKPOINT_READY."
)
CONTINUE = "Read record.txt with the read tool once. Reply with only the sample status value from that file."


def api(path, body=None, timeout=5):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        ADDRESS + path, data, {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def isolation_probe(spec):
    # An address-independent route check: no host interfaces are present.
    probe = spec.get("writable_probe_path", "/project/record.txt")
    interfaces = sorted(name for _, name in socket.if_nameindex())
    if (
        interfaces != ["lo"]
        or {entry.name for entry in Path("/home").iterdir()} != {"lab"}
        or "DEEPSEEK_API_KEY" in os.environ
    ):
        raise RuntimeError("unexpected network, home mount or credential in worker")
    if not Path(probe).is_file() or os.access(probe, os.W_OK):
        raise RuntimeError("fixture is missing or writable in worker")
    save(
        "isolation.json",
        {
            "interfaces": interfaces,
            "project_read_only": True,
            "writable_probe_path": probe,
            "host_home_visible": False,
            "provider_key_in_environment": False,
        },
    )


def serve():
    server = subprocess.Popen(
        [
            BINARY,
            "serve",
            "--pure",
            "--hostname",
            "127.0.0.1",
            "--port",
            "4096",
            "--log-level",
            "WARN",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if server.poll() is not None:
                break
            try:
                api("/global/health", timeout=0.3)
                return server
            except (OSError, ValueError):
                time.sleep(0.1)
        raise RuntimeError("OpenCode server did not become ready")
    except BaseException:
        stop(server)
        raise


def stop(server):
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def messages(session):
    return api(f"/session/{session}/message")


def run(spec):
    isolation_probe(spec)
    model = spec.get("model", MODEL)
    agent = spec.get("agent", "lab")
    cli_timeout = spec.get("cli_timeout", 70)
    proxy = bridge(4097, "/relay.sock")
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    server = None
    source = spec.get("source_session_id")
    try:
        server = serve()
        if source:
            save("restored.source.messages.json", messages(source))
            boundary = spec.get("exclusive_message_id")
            fork_request = {"messageID": boundary} if boundary else {}
            session = api(f"/session/{source}/fork", fork_request)["id"]
            if session == source:
                raise RuntimeError("fork returned source session")
            forked = messages(session)
            save("fork.before.messages.json", forked)
            if digest(projection(forked)) != spec["expected_prefix_sha256"]:
                raise RuntimeError("native fork differs from selected checkpoint")
            prompts = [spec.get("continue_prompt", CONTINUE)]
        else:
            session = api(
                "/session", {"title": spec.get("session_title", "Trace replay fixture")}
            )["id"]
            prompts = spec.get("prompts") or (
                [SURVEY, CONTINUE] if spec["record_full"] else [SURVEY]
            )

        started = time.monotonic()
        turns = []
        with (
            (OUTPUT / "trace.native.jsonl").open("w") as stdout,
            (OUTPUT / "cli.stderr.log").open("w") as stderr,
        ):
            for prompt in prompts:
                cli = subprocess.run(
                    [
                        BINARY,
                        "run",
                        "--pure",
                        "--attach",
                        ADDRESS,
                        "--session",
                        session,
                        "--model",
                        model,
                        "--agent",
                        agent,
                        "--format",
                        "json",
                        prompt,
                    ],
                    check=False,
                    timeout=cli_timeout,
                    stdout=stdout,
                    stderr=stderr,
                )
                after = messages(session)
                turns.append(
                    {
                        "prompt": prompt,
                        "message_count": len(after),
                        "last_message_id": after[-1]["info"]["id"] if after else None,
                        "cli_exit_code": cli.returncode,
                    }
                )
                if cli.returncode:
                    break

        save("session.messages.json", after)
        if source:
            save("source.after.messages.json", messages(source))
        save(
            "phase.json",
            {
                "session_id": session,
                "source_session_id": source,
                "cli_exit_code": cli.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "prompt": prompts[-1],
                "turns": turns,
            },
        )
    finally:
        if server is not None:
            stop(server)
        proxy.shutdown()
        proxy.server_close()


if __name__ == "__main__":
    run(json.loads(sys.argv[1]))
