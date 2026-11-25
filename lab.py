"""Capture and replay fixed benign fixtures through an isolated OpenCode process."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

from history import projection
from relay import BASE_COLOR, LAYOUTS, RECORDS, digest, format_record, provider_relay

ROOT = Path(__file__).resolve().parent
BINARY = ROOT / ".runtime/node_modules/opencode-linux-x64/bin/opencode"
VERSION = "1.19.6"
MODEL = "deepseek-flash"


def load(path):
    return json.loads(path.read_text())


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def journal(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def api_key(env_file):
    if os.getenv("DEEPSEEK_API_KEY"):
        return os.environ["DEEPSEEK_API_KEY"]
    if env_file:
        for line in env_file.read_text().splitlines():
            m = re.fullmatch(r"\s*(?:export\s+)?DEEPSEEK_API_KEY\s*=\s*(.*?)\s*", line)
            if m:
                value = m[1].strip("'\"")
                if value:
                    return value
    raise ValueError(
        "set DEEPSEEK_API_KEY or provide --env-file containing DEEPSEEK_API_KEY"
    )


def tool_config():
    return {
        "autoupdate": False,
        "share": "disabled",
        "snapshot": False,
        "lsp": False,
        "formatter": False,
        "compaction": {"auto": False, "prune": False},
        "permission": {
            "*": "deny",
            "read": {
                "*": "deny",
                "project/overview.txt": "allow",
                "project/record.txt": "allow",
            },
        },
        "agent": {
            "lab": {
                "mode": "primary",
                "description": "Read two fixed text fixtures",
                "prompt": "You are a read-only fixture reader. Follow the user's requested output format.",
                "steps": 3,
            }
        },
        "default_agent": "lab",
        "enabled_providers": ["lab"],
        "provider": {
            "lab": {
                "name": "Isolated model relay",
                "npm": "@ai-sdk/openai-compatible",
                "options": {
                    "baseURL": "http://127.0.0.1:4097/v1",
                    "apiKey": "local-relay-only",
                },
                "models": {
                    MODEL: {
                        "id": MODEL,
                        "name": MODEL,
                        "tool_call": True,
                        "reasoning": False,
                        "limit": {"context": 32000, "output": 512},
                    }
                },
            }
        },
        "model": f"lab/{MODEL}",
    }


def tree_hashes(root):
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("unsupported checkpoint file type")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = sha256(
                path.read_bytes()
            ).hexdigest()
    return files


def fixture(path):
    path.mkdir()
    (path / "overview.txt").write_text(
        "A local color status fixture for a replay experiment.\n"
    )
    (path / "record.txt").write_text(format_record(BASE_COLOR, "plain"))


def checkpoint_history(checkpoint, manifest):
    history = load(checkpoint / "history.json")
    if len(history) != manifest["message_count"] or not history:
        raise ValueError("checkpoint message count differs")
    if history[-1]["info"]["id"] != manifest["last_message_id"]:
        raise ValueError("checkpoint boundary message differs")
    prefix = projection(history)
    if digest(prefix) != manifest["semantic_prefix_sha256"]:
        raise ValueError("checkpoint history digest differs")
    return history, prefix


def sandbox(output, project, state, relay_socket, spec):
    args = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home/lab",
        "--ro-bind",
        str(BINARY),
        "/runtime/opencode",
        "--ro-bind",
        str(ROOT / "worker.py"),
        "/code/worker.py",
        "--ro-bind",
        str(ROOT / "relay.py"),
        "/code/relay.py",
        "--ro-bind",
        str(ROOT / "history.py"),
        "/code/history.py",
        "--ro-bind",
        str(project),
        "/project",
        "--bind",
        str(state),
        "/state",
        "--bind",
        str(output),
        "/output",
        "--ro-bind",
        str(relay_socket),
        "/relay.sock",
        "--chdir",
        "/project",
    ]
    env = {
        "HOME": "/home/lab",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "XDG_DATA_HOME": "/state/data",
        "XDG_CACHE_HOME": "/tmp/cache",
        "XDG_CONFIG_HOME": "/tmp/config",
        "XDG_STATE_HOME": "/tmp/state",
        "OPENCODE_CONFIG_CONTENT": json.dumps(spec.get("config") or tool_config()),
        "OPENCODE_DISABLE_AUTOUPDATE": "true",
        "OPENCODE_DISABLE_MODELS_FETCH": "true",
        "OPENCODE_DISABLE_LSP_DOWNLOAD": "true",
        "OPENCODE_DISABLE_SHARE": "true",
        "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
        "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
    }
    for key, value in env.items():
        args.extend(["--setenv", key, value])
    args.extend(["/usr/bin/python3", "/code/worker.py", json.dumps(spec)])
    with (output / "worker.log").open("w") as log:
        subprocess.run(
            args,
            stdout=log,
            stderr=log,
            timeout=spec.get("sandbox_timeout", 175),
            check=True,
        )


def normalize(source, out, bench):
    sys.path.insert(0, str(bench / "src"))
    from vulnmirage.trace.normalize import normalize_trace

    return normalize_trace(
        source,
        out,
        adapter="opencode_jsonl",
        repo_root=Path("/project"),
        framework_version=VERSION,
    )


def backfill_trace(out, report):
    before = out / "fork.before.messages.json"
    historical = (
        {item["info"]["id"] for item in load(before)} if before.exists() else set()
    )
    source = out / "trace.session_projection.jsonl"
    types = {
        "step-start": "step_start",
        "step-finish": "step_finish",
        "tool": "tool_use",
        "text": "text",
        "reasoning": "reasoning",
    }
    with source.open("w", encoding="utf-8") as journal_file:
        for item in load(out / "session.messages.json"):
            info = item["info"]
            if info["role"] != "assistant" or info["id"] in historical:
                continue
            for part in item["parts"]:
                if part["type"] not in types:
                    continue
                event = {
                    "type": types[part["type"]],
                    "sessionID": report["session_id"],
                    "part": part,
                    "origin": "durable_session_export",
                }
                journal_file.write(json.dumps(event, ensure_ascii=False) + "\n")
            if info.get("error"):
                journal_file.write(
                    json.dumps({"type": "error", "error": info["error"]}) + "\n"
                )
    return source


def execute(root, phase, project, state, *, key, bench, spec):
    out = root / phase
    out.mkdir()
    relay_kwargs = dict(spec.get("relay") or {})
    worker_spec = {k: v for k, v in spec.items() if k != "relay"}
    with tempfile.TemporaryDirectory(prefix="oclab-") as ipc:
        socket_path = Path(ipc) / "relay.sock"
        with provider_relay(
            socket_path,
            out / "relay.requests.jsonl",
            key=key,
            model=MODEL,
            **relay_kwargs,
        ):
            sandbox(out, project, state, socket_path, worker_spec)
    phase_report = load(out / "phase.json")
    native = normalize(out / "trace.native.jsonl", out / "native_normalized", bench)
    source = backfill_trace(out, phase_report)
    normalized = normalize(source, out, bench)
    trace = journal(source)
    requests = sorted(
        journal(out / "relay.requests.jsonl"), key=lambda row: row["request"]
    )
    report = {
        **phase_report,
        "normalized_status": normalized["status"],
        "trace_completeness": normalized["completeness"],
        "native_trace_completeness": native["completeness"],
        "normalized_trace_source": source.name,
        "tool_calls": load_calls(out),
        "request_count": len(requests),
        "provider_statuses": [row.get("status") for row in requests],
        "errors": sum(row.get("type") == "error" for row in trace),
        "answer": "".join(
            row.get("part", {}).get("text", "")
            for row in trace
            if row.get("type") == "text"
        ).strip(),
    }
    save(out / "phase_summary.json", report)
    if (
        phase_report["cli_exit_code"]
        or report["errors"]
        or not requests
        or any(
            row.get("status") != 200 or row.get("transport_error") for row in requests
        )
    ):
        raise ValueError(f"{phase} failed; see {out / 'phase_summary.json'}")
    if normalized["completeness"] != "complete":
        raise ValueError(f"{phase} is missing a complete terminal tool/answer trace")
    if not report["tool_calls"] or any(
        row["tool_name"] != "read"
        or (
            not spec.get("allow_tool_errors")
            and row["status"] != "completed"
        )
        for row in report["tool_calls"]
    ):
        raise ValueError(f"{phase} lacks a successful read-only trace")
    return report, requests


def load_calls(out):
    return [
        {k: row.get(k) for k in ("tool_name", "status", "input_summary", "duration_ms")}
        for row in journal(out / "tool_calls.jsonl")
    ]


def index_checkpoints(history, turns, prior_read_names=("record.txt",)):
    points = {}
    start = 0
    for ordinal, turn in enumerate(turns, 1):
        end = turn["message_count"]
        if not start < end <= len(history) or turn["cli_exit_code"]:
            raise ValueError("recording contains an incomplete turn")
        info = history[end - 1]["info"]
        if (
            history[start]["info"]["role"] != "user"
            or info["id"] != turn["last_message_id"]
            or info["role"] != "assistant"
            or info.get("finish") != "stop"
            or not info.get("time", {}).get("completed")
        ):
            raise ValueError("checkpoint must end at a completed user turn")
        tool_parts = [
            part
            for msg in history[:end]
            for part in msg["parts"]
            if part["type"] == "tool"
        ]
        if any(part["state"]["status"] != "completed" for part in tool_parts):
            raise ValueError("checkpoint contains a failed or pending tool call")
        read_paths = sorted(
            {Path(part["state"]["input"]["filePath"]).name for part in tool_parts}
        )
        points[f"turn-{ordinal}"] = {
            "message_count": end,
            "last_message_id": info["id"],
            "exclusive_message_id": history[end]["info"]["id"]
            if end < len(history)
            else None,
            "semantic_prefix_sha256": digest(projection(history[:end])),
            "read_paths_in_prefix": read_paths,
            "replaced_file_previously_read": bool(
                set(read_paths) & set(prior_read_names)
            ),
        }
        start = end
    if start != len(history):
        raise ValueError("recorded turns do not cover the stored session")
    return points


def capture(args, key):
    root = args.out.resolve()
    root.mkdir(parents=True, mode=0o700)
    project = root / "fixture"
    fixture(project)
    state = root / "capture-state"
    state.mkdir()
    report, requests = execute(
        root,
        "capture",
        project,
        state,
        key=key,
        bench=args.bench,
        spec={"record_full": args.record_full},
    )
    history = load(root / "capture/session.messages.json")
    projected = projection(history)
    if any(set(row["tool_result_markers"]) - {BASE_COLOR} for row in requests):
        raise ValueError("variant leaked into checkpoint")
    expected_paths = (
        ["overview.txt", "record.txt"] if args.record_full else ["overview.txt"]
    )
    expected_answer = "CHECKPOINT_READY" + (BASE_COLOR if args.record_full else "")
    observed_paths = [
        call["input_summary"].get("filePath") for call in report["tool_calls"]
    ]
    if report["answer"] != expected_answer or observed_paths != expected_paths:
        raise ValueError("capture did not finish the expected fixture turns")
    points = index_checkpoints(history, report["turns"])
    checkpoint = root / "checkpoint"
    checkpoint.mkdir()
    shutil.copytree(state, checkpoint / "state")
    shutil.copytree(project, checkpoint / "fixture")
    save(checkpoint / "history.json", history)
    save(
        checkpoint / "manifest.json",
        {
            "version": VERSION,
            "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
            "model": MODEL,
            "configuration_sha256": digest(tool_config()),
            "provider": "deepseek" if key else "fixture_stub",
            "source_session_id": report["session_id"],
            "last_message_id": history[-1]["info"]["id"],
            "message_count": len(history),
            "semantic_prefix_sha256": digest(projected),
            "checkpoints": points,
            "files": tree_hashes(checkpoint),
            "boundary": "completed turn with OpenCode stopped before snapshot copy",
        },
    )
    return checkpoint


def list_checkpoints(args, _key):
    checkpoint = args.checkpoint.resolve()
    manifest = load(checkpoint / "manifest.json")
    points = manifest.get("checkpoints")
    if points is None:
        points = {"final": {"message_count": manifest["message_count"], "legacy": True}}
    print(json.dumps(points, indent=2, ensure_ascii=False))


def replay(args, key):
    checkpoint = args.checkpoint.resolve()
    manifest = load(checkpoint / "manifest.json")
    files = tree_hashes(checkpoint)
    del files["manifest.json"]
    if (
        files != manifest["files"]
        or manifest["version"] != VERSION
        or manifest["configuration_sha256"] != digest(tool_config())
        or manifest["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest()
        or manifest["provider"] != ("deepseek" if key else "fixture_stub")
    ):
        raise ValueError("checkpoint files, runtime, provider or configuration differ")
    source = manifest["source_session_id"]
    history, full_prefix = checkpoint_history(checkpoint, manifest)
    points = manifest.get("checkpoints") or {
        "final": {
            "message_count": len(history),
            "last_message_id": manifest["last_message_id"],
            "semantic_prefix_sha256": digest(full_prefix),
            "exclusive_message_id": None,
        }
    }
    selected = args.at or next(reversed(points))
    if selected not in points:
        raise ValueError(
            f"unknown checkpoint {selected!r}; available: {', '.join(points)}"
        )
    point = points[selected]
    end = point["message_count"]
    prefix = full_prefix[:end]
    excluded = history[end]["info"]["id"] if end < len(history) else None
    if (
        not 0 < end <= len(history)
        or history[end - 1]["info"]["id"] != point["last_message_id"]
        or excluded != point["exclusive_message_id"]
        or digest(prefix) != point["semantic_prefix_sha256"]
    ):
        raise ValueError("selected checkpoint does not match archived history")
    prior_read = point.get("replaced_file_previously_read", False)
    if prior_read and not args.allow_prior_read:
        raise ValueError(
            "record.txt already appears in the selected prefix; choose an earlier checkpoint or use --allow-prior-read"
        )
    out = args.out.resolve()
    if out.is_relative_to(checkpoint):
        raise ValueError("replay output cannot be inside the checkpoint")
    out.mkdir(parents=True, mode=0o700)
    spec = {
        "source_session_id": source,
        "exclusive_message_id": excluded,
        "expected_prefix_sha256": digest(prefix),
    }
    reports = {}
    first = {}
    first_inputs = {}
    cases = RECORDS if args.case == "both" else {args.case: RECORDS[args.case]}
    for phase, marker in cases.items():
        state = out / f"{phase}-state"
        project = out / f"{phase}-fixture"
        shutil.copytree(checkpoint / "state", state)
        shutil.copytree(checkpoint / "fixture", project)
        record = project / "record.txt"
        before_hash = sha256(record.read_bytes()).hexdigest()
        record.write_text(format_record(marker, args.layout))
        fixture_edit = {
            "path": "record.txt",
            "layout": args.layout,
            "before_sha256": before_hash,
            "after_sha256": sha256(record.read_bytes()).hexdigest(),
        }
        report, requests = execute(
            out, phase, project, state, key=key, bench=args.bench, spec=spec
        )
        phase_dir = out / phase
        for name in ("restored.source.messages.json", "source.after.messages.json"):
            if load(phase_dir / name) != history:
                raise ValueError(f"{phase}: {name} does not match the checkpoint")
        if projection(load(phase_dir / "fork.before.messages.json")) != prefix:
            raise ValueError(f"{phase}: fork does not match the checkpoint prefix")
        after = projection(load(phase_dir / "session.messages.json"))
        if after[: len(prefix)] != prefix or len(after) <= len(prefix):
            raise ValueError("continuation did not retain prefix")
        prior_markers = [BASE_COLOR] if prior_read else []
        new_read = {"color": marker, "layout": args.layout}
        if (
            requests[0]["tool_result_markers"] != prior_markers
            or not any(
                row["current_turn_fixture_reads"] == [new_read] for row in requests[1:]
            )
            or any(
                set(row["tool_result_markers"]) - {marker, *prior_markers}
                for row in requests
            )
        ):
            raise ValueError(
                f"{phase}: provider request evidence differs from expected fixture"
            )
        if report["answer"] != marker or [
            call["input_summary"].get("filePath") for call in report["tool_calls"]
        ] != ["record.txt"]:
            raise ValueError(
                f"{phase}: trace or answer did not match the expected fixture read"
            )
        first[phase] = requests[0]["messages_sha256"]
        first_inputs[phase] = requests[0]["input_sha256"]
        reports[phase] = {
            **report,
            "fixture_edit": fixture_edit,
            "observed_new_read": new_read,
        }
    equal = len(set(first.values())) == 1 if len(first) > 1 else None
    inputs_equal = (
        len(set(first_inputs.values())) == 1 if len(first_inputs) > 1 else None
    )
    verified = files == {
        k: v for k, v in tree_hashes(checkpoint).items() if k != "manifest.json"
    }
    result = {
        "passed": equal is not False and inputs_equal is not False and verified,
        "provider": manifest["provider"],
        "opencode_version": VERSION,
        "model": MODEL,
        "checkpoint_id": selected,
        "semantic_prefix_sha256": digest(prefix),
        "retained_original_messages": end,
        "discarded_original_messages": len(history) - end,
        "original_exclusive_message_id": excluded,
        "replaced_file_previously_read": prior_read,
        "checkpoint_unchanged": verified,
        "first_provider_messages_equal": equal,
        "first_provider_messages_sha256": first,
        "first_relay_request_equal": inputs_equal,
        "first_relay_request_sha256": first_inputs,
        "fork_prefix_verified": True,
        "arms": reports,
        "scope": "completed-turn fork, replay with fresh model calls and benign fixture substitutions",
    }
    save(out / "verification.json", result)
    if not result["passed"]:
        raise ValueError("paired checkpoint replay did not verify")
    print(out / "verification.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, default=ROOT.parent / "vulnmirage")
    parser.add_argument(
        "--live", action="store_true", help="call official DeepSeek API"
    )
    parser.add_argument(
        "--env-file", type=Path, help="read only DEEPSEEK_API_KEY from this dotenv file"
    )
    sub = parser.add_subparsers(required=True)
    entry = sub.add_parser("capture")
    entry.add_argument("--out", type=Path, required=True)
    entry.set_defaults(command=capture, record_full=False)
    entry = sub.add_parser(
        "record", help="record and index a complete two-turn fixture run"
    )
    entry.add_argument("--out", type=Path, required=True)
    entry.set_defaults(command=capture, record_full=True)
    entry = sub.add_parser(
        "checkpoints", help="list archived checkpoints without calling the model"
    )
    entry.add_argument("--checkpoint", type=Path, required=True)
    entry.set_defaults(command=list_checkpoints)
    entry = sub.add_parser("replay")
    entry.add_argument("--checkpoint", type=Path, required=True)
    entry.add_argument("--out", type=Path, required=True)
    entry.add_argument("--at", help="select a checkpoint from the recording")
    entry.add_argument("--case", choices=("both", *RECORDS), default="both")
    entry.add_argument("--layout", choices=LAYOUTS, default="plain")
    entry.add_argument("--allow-prior-read", action="store_true")
    entry.set_defaults(command=replay)
    args = parser.parse_args()
    if args.command is list_checkpoints:
        list_checkpoints(args, None)
        return
    key = api_key(args.env_file) if args.live else None
    version = subprocess.check_output([str(BINARY), "--version"], text=True).strip()
    if version != VERSION:
        raise ValueError(f"expected OpenCode {VERSION}, got {version}")
    result = args.command(args, key)
    if result is not None:
        print(result)


if __name__ == "__main__":
    main()
