"""Remote helper. Only Python standard library; action payload arrives over stdin."""
import base64
import contextlib
import difflib
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid

MAX_LOG = 20 * 1024 * 1024
MAX_TEXT = 5 * 1024 * 1024
STATE_ROOT = pathlib.Path.home() / ".local" / "state" / "ssh-ops-mcp"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def masked(text):
    def lines(value):
        return re.sub(r"[^\r\n]+", "[REDACTED]", value)
    def sensitive(key):
        normal = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).replace("-", "_").replace(".", "_").lower()
        return re.search(r"(?:^|_)(?:password|passwd|passphrase|token|secret|api_?key|private_?key|access_?key|secret_?key|credentials?|authorization)(?:_(?:value|data))?$", normal) is not None
    def assignment(match):
        prefix, value = match.groups()
        key = re.match(r'''^["']?([\w.-]+)''', prefix)[1]
        if key.lower() == "authorization" and re.fullmatch(r"(?:Bearer|Basic)[ \t]+", value):
            return match[0]
        suffix = re.search(r"[ \t]*(?:#.*)?$", value)[0]
        scalar = value[:len(value) - len(suffix)] if suffix else value
        if not sensitive(key) or not scalar or re.fullmatch(r"(?:true|false|null|~|[|>][+-]?)", scalar, flags=re.I):
            return match[0]
        if value[0] in "\"'" and value[-1] == value[0]:
            return prefix + value[0] + lines(value[1:-1]) + value[-1]
        return prefix + "[REDACTED]" + suffix
    text = re.sub(r"(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+", r"\1[REDACTED]", text, flags=re.I)
    text = re.sub(r'''((?:"[\w.-]+"|'[\w.-]+'|\b[\w.-]+)[ \t]*[:=][ \t]*)("(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\r\n,;{}\[\]]+)''', assignment, text)
    result, block_indent = [], None
    for line in text.splitlines(keepends=True):
        indent = len(re.match(r"^[ \t]*", line)[0])
        if block_indent is not None:
            if not line.strip():
                result.append(line)
                continue
            if indent > block_indent:
                result.append(re.sub(r"[^\r\n]+", lambda m: re.match(r"^[ \t]*", m[0])[0] + "[REDACTED]", line, count=1))
                continue
            block_indent = None
        block = re.fullmatch(r'''[ \t]*["']?([\w.-]+)["']?[ \t]*:[ \t]*[|>][+-]?[ \t]*(?:#.*)?(?:\r?\n)?''', line)
        if block and sensitive(block[1]):
            block_indent = indent
        result.append(line)
    text = "".join(result)
    text = re.sub(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|$)", lambda m: lines(m[0]), text)
    text = re.sub(r"(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+", r"\1[REDACTED]", text, flags=re.I)
    return re.sub(r"(\w+://[^\s/:]+:)[^\s@]+@", r"\1[REDACTED]@", text)

def secure_dir(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("Unsafe state directory owner or symlink.")
    os.chmod(directory, 0o700)

def state_root():
    secure_dir(STATE_ROOT)
    return STATE_ROOT

def save_json(file, value):
    fd, name = tempfile.mkstemp(prefix=".state-", dir=file.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, file)
        sync_parent(file)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def sync_parent(file):
    fd = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def load_json(file):
    with open(file) as handle:
        return json.load(handle)

@contextlib.contextmanager
def lock(file):
    fd = os.open(file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield

def boot_id():
    return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()

def process_start(pid):
    try:
        fields = pathlib.Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        return fields[19]
    except (OSError, IndexError):
        return None

def operation_dir(operation_id):
    if not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise ValueError("Invalid operation_id.")
    return state_root() / "operations" / operation_id

def status(a):
    directory = operation_dir(a["operation_id"])
    data = load_json(directory / "status.json")
    # Never turn missing connectivity/process into success or restart the command.
    if data["state"] in ("starting", "running"):
        stale = data.get("boot_id") != boot_id()
        if data.get("runner_pid"):
            stale |= process_start(data["runner_pid"]) != data.get("runner_start")
        elif time.time() - data["created_at"] > 30:
            stale = True
        if stale:
            data = dict(data, state="process_lost", outcome="unknown; do not repeat automatically")
    return data

def execution_spec(a):
    timeout = a.get("timeout_seconds", 3600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 86400:
        raise ValueError("timeout_seconds must be 1..86400.")
    command, steps = a.get("command"), a.get("steps")
    if (command is None) == (steps is None):
        raise ValueError("Provide exactly one of command or steps.")
    spec = {"timeout_seconds": timeout}
    if steps is not None:
        if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
            raise ValueError("steps must contain 1..20 named commands.")
        for step in steps:
            if not isinstance(step, dict) or not isinstance(step.get("name"), str) or not 1 <= len(step["name"]) <= 200:
                raise ValueError("Each step requires a name of 1..200 characters.")
            if not isinstance(step.get("command"), str) or not 1 <= len(step["command"]) <= 1000000:
                raise ValueError("Each step requires a command of 1..1000000 characters.")
        if sum(len(step["command"]) for step in steps) > 1000000:
            raise ValueError("Combined step commands exceed 1 MiB.")
        spec["steps"] = [{"name": step["name"], "command": step["command"]} for step in steps]
    else:
        if not isinstance(command, str) or not 1 <= len(command) <= 1000000:
            raise ValueError("command must contain 1..1000000 characters.")
        spec["command"] = command
    if a.get("resource"):
        spec["resource"] = resource_name(a["resource"])
    return spec

def safe_label(value, fallback=None):
    if value is None:
        return fallback
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or "\x00" in value:
        raise ValueError("Operation labels must contain 1..200 characters, without NUL.")
    return masked(value)

def milliseconds(start, end):
    return max(0, int(round((end - start) * 1000))) if start is not None and end is not None else None

def utc(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat().replace("+00:00", "Z") if value is not None else None

def operation_summary(data, now=None):
    now = time.time() if now is None else now
    state = data["state"]
    phases = data.get("phases", [])
    active = next((step for step in phases if step["state"] == "running"), None)
    elapsed_end = data.get("finished_at")
    if elapsed_end is None and state in ("starting", "running"):
        elapsed_end = now
    return {"operation_id": data["operation_id"], "request_id": data.get("request_id"),
            "title": masked(data.get("title") or "Operation " + data["operation_id"][:8]),
            "resource": data.get("resource"), "state": state, "created_at": data["created_at"],
            "started_at": data.get("started_at"), "finished_at": data.get("finished_at"),
            "duration_ms": data.get("duration_ms", milliseconds(data.get("started_at"), elapsed_end)),
            "elapsed_ms": milliseconds(data["created_at"], elapsed_end), "exitCode": data.get("exitCode"),
            "current_phase": {"index": active["index"], "name": masked(active["name"]),
                              "state": "unknown" if state == "process_lost" else active["state"],
                              "started_at": utc(active.get("started_at")),
                              "duration_ms": milliseconds(active.get("started_at"), now) if state != "process_lost" else None} if active else None}

def report(a):
    data = status(a)
    now = time.time()
    summary = operation_summary(data, now)
    phases = data.get("phases")
    legacy = phases is None
    if legacy:
        phases = [{"index": 1, "name": "Command", "state": data["state"],
                   "started_at": data.get("started_at"), "finished_at": data.get("finished_at"), "exitCode": data.get("exitCode")}]
    rendered = []
    for phase in phases:
        phase_state = "unknown" if data["state"] == "process_lost" and phase["state"] == "running" else phase["state"]
        end = phase.get("finished_at")
        if end is None and phase_state == "running":
            end = now
        rendered.append({"index": phase["index"], "name": masked(phase["name"]), "state": phase_state,
                         "started_at": utc(phase.get("started_at")), "finished_at": utc(phase.get("finished_at")),
                         "duration_ms": phase.get("duration_ms", milliseconds(phase.get("started_at"), end)),
                         "exit_code": phase.get("exitCode")})
    outcomes = {"completed": ("success", "All commands finished with exit code 0; application-level health is not inferred."),
                "failed": ("failure", "Operation failed; later phases were not run. Completed changes were not rolled back."),
                "timed_out": ("timeout", "Operation deadline reached. Completed changes were not rolled back."),
                "cancelled": ("cancelled", "Cancellation requested; completed changes were not rolled back."),
                "starting": ("in_progress", "Operation is queued for its runner."),
                "running": ("in_progress", "Operation is running."),
                "process_lost": ("unknown", "Runner is unavailable. Verify remote processes and effects before retrying or unlocking.")}
    outcome, explanation = outcomes.get(data["state"], ("unknown", "Operation outcome is unknown."))
    return {"operation_id": summary["operation_id"], "request_id": summary["request_id"],
            "title": summary["title"], "resource": summary["resource"], "state": data["state"],
            "generated_at": utc(now), "created_at": utc(data["created_at"]),
            "started_at": utc(data.get("started_at")), "finished_at": utc(data.get("finished_at")),
            "duration_ms": summary["duration_ms"], "elapsed_ms": summary["elapsed_ms"],
            "queue_ms": milliseconds(data["created_at"], data.get("started_at")),
            "phases": rendered, "legacy_metadata": legacy,
            "result": {"outcome": outcome, "exit_code": data.get("exitCode"), "explanation": explanation},
            "logs": {"tool": "ssh_operation_logs", "operation_id": summary["operation_id"],
                     "truncated": data.get("truncated", {})}}

class ResourceBusy(ValueError):
    code = "resource_busy"
    def __init__(self, owner):
        super().__init__(owner["explanation"])
        self.details = {"outcome": "not_started", "blocker": owner}

def start(a, source):
    operation_id = a["operation_id"]
    directory = operation_dir(operation_id)
    operations = directory.parent
    secure_dir(operations)
    spec = execution_spec(a)
    title = safe_label(a.get("title"), safe_label(a.get("request_id"), "Operation " + operation_id[:8]))
    request_id = safe_label(a.get("request_id"))
    resource = resource_name(a.get("resource") or "__server_admin__")
    spec_hash = digest(json.dumps(spec, sort_keys=True).encode())
    with lock(operations / ".registry.lock"):
        if directory.exists():
            old = load_json(directory / "status.json")
            if old["spec_hash"] != spec_hash:
                raise ValueError("request_id is already used with different command/options.")
            return dict(status(a), reused=True)
        if resource:
            owner = resource_status({"resource": resource})
            if owner.get("blocked"):
                raise ResourceBusy(owner)
        secure_dir(directory)
        now = time.time()
        data = {"operation_id": operation_id, "state": "starting", "created_at": now,
                "boot_id": boot_id(), "spec_hash": spec_hash, "title": title, "request_id": request_id,
                "phases": [{"index": index + 1, "name": masked(step["name"]), "state": "pending"}
                           for index, step in enumerate(spec.get("steps") or [{"name": "Command"}])]}
        if resource:
            data["resource"] = resource
        save_json(directory / "status.json", data)
        save_json(directory / "spec.json", spec)
        if resource:
            save_json(resource_file(resource), {"resource": resource, "operation_id": operation_id})
        runner = state_root() / ("runner-" + digest(source.encode())[:16] + ".py")
        if not runner.exists():
            fd = os.open(runner, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(source)
        # Detach before responding: no SSH session or terminal lifetime dependency.
        subprocess.Popen([sys.executable, str(runner), "_run", operation_id],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    return dict(data, reused=False)

def resource_name(value):
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or "\x00" in value:
        raise ValueError("Invalid deployment resource.")
    return str(pathlib.Path(value).resolve()) if value.startswith("/") else value

def resource_file(resource):
    directory = state_root() / "deploy-locks"
    secure_dir(directory)
    return directory / (digest(resource.encode()) + ".json")

def resource_status(a):
    resource = resource_name(a["resource"])
    file = resource_file(resource)
    if not file.exists():
        return {"resource": resource, "blocked": False, "blocked_reason": None, "explanation": "No task holds this resource."}
    owner = load_json(file)
    try:
        current = status({"operation_id": owner["operation_id"]})
    except (OSError, ValueError):
        current = {"state": "process_lost"}
    blocked = current["state"] in ("starting", "running", "process_lost")
    task = operation_summary(current) if "created_at" in current else {"operation_id": owner["operation_id"], "state": "process_lost", "title": "Unavailable task metadata"}
    if current["state"] == "process_lost":
        reason, advice = "outcome_unknown", "Verify remote processes/effects, then explicitly unlock with verified_stopped=true. Do not retry blindly."
        explanation = "Resource remains blocked by task " + task["title"] + " (operation_id=" + owner["operation_id"] + "): runner/outcome unknown. Verify processes and effects before explicit unlock."
    elif blocked:
        reason, advice = "task_" + current["state"], "Poll the owner's report/logs; cancel it only if authorized and wait for a terminal state."
        explanation = "Resource is held by task " + task["title"] + " (operation_id=" + owner["operation_id"] + ", state=" + current["state"] + ")."
        if task.get("current_phase"):
            explanation += " Current phase: " + task["current_phase"]["name"] + "."
        if task.get("elapsed_ms") is not None:
            explanation += " Elapsed: %.1f seconds." % (task["elapsed_ms"] / 1000)
    else:
        reason, advice = None, "Resource is available for a new operation."
        explanation = "Previous task " + task["title"] + " finished; this resource is available."
    return dict(owner, state=current["state"], blocked=blocked, blocked_reason=reason,
                task=task, explanation=explanation, suggested_action=advice)

def resource_unlock(a):
    operations = state_root() / "operations"
    secure_dir(operations)
    with lock(operations / ".registry.lock"):
        owner = resource_status(a)
        if owner.get("operation_id") != a["expected_operation_id"]:
            raise ValueError("Lock owner changed; inspect it again.")
        if owner.get("state") in ("starting", "running"):
            raise ValueError("Cannot unlock a running deployment; cancel and wait for status.")
        if owner.get("state") == "process_lost" and not a.get("verified_stopped", False):
            raise ValueError("Outcome unknown. Verify remote processes and effects before explicitly unlocking.")
        resource_file(resource_name(a["resource"])).unlink()
        return {"resource": a["resource"], "blocked": False, "released_operation_id": a["expected_operation_id"]}

def terminate_group(pid):
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    time.sleep(0.2)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

def execute_phase(directory, command, data, started, files, sizes, truncated):
    child = None
    selector = selectors.DefaultSelector()
    try:
        child = subprocess.Popen(["/bin/bash", "-c", command], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, close_fds=True)
        data["pid"] = child.pid
        save_json(directory / "status.json", data)
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        final_state, drain_deadline = None, None
        while selector.get_map() or child.poll() is None:
            if final_state is None and (directory / "cancel").exists():
                final_state = "cancelled"
                terminate_group(child.pid)
            if final_state is None and time.monotonic() - started >= data["timeout_seconds"]:
                final_state = "timed_out"
                terminate_group(child.pid)
            if final_state is not None and drain_deadline is None:
                drain_deadline = time.monotonic() + 2
            if child.poll() is not None and drain_deadline is None:
                terminate_group(child.pid)
                drain_deadline = time.monotonic() + 2
            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                for key in list(selector.get_map().values()):
                    truncated[key.data] = True
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                kind = key.data
                remaining = max(0, MAX_LOG - sizes[kind])
                files[kind].write(chunk[:remaining])
                files[kind].flush()
                sizes[kind] += min(len(chunk), remaining)
                truncated[kind] |= len(chunk) > remaining
        code = child.wait()
        return final_state or ("completed" if code == 0 else "failed"), code
    finally:
        if child is not None:
            terminate_group(child.pid)
            child.wait()
            for stream in (child.stdout, child.stderr):
                stream.close()
        selector.close()


def run(operation_id):
    directory = operation_dir(operation_id)
    with lock(directory / ".runner.lock"):
        data = load_json(directory / "status.json")
        if data["state"] != "starting":
            return
        spec = load_json(directory / "spec.json")
        steps = spec.get("steps") or [{"name": "Command", "command": spec["command"]}]
        if "phases" not in data:
            data["phases"] = [{"index": i + 1, "name": masked(step["name"]), "state": "pending"}
                              for i, step in enumerate(steps)]
        started = time.monotonic()
        data.update(state="running", started_at=time.time(), timeout_seconds=spec["timeout_seconds"],
                    runner_pid=os.getpid(), runner_start=process_start(os.getpid()))
        save_json(directory / "status.json", data)
        files = {}
        sizes = {"stdout": 0, "stderr": 0}
        truncated = {"stdout": False, "stderr": False}
        try:
            for kind in ("stdout", "stderr"):
                files[kind] = open(directory / (kind + ".log"), "wb")
                os.chmod(files[kind].name, 0o600)
            final_state, code = "completed", 0
            for step, phase in zip(steps, data["phases"]):
                if (directory / "cancel").exists():
                    final_state, code = "cancelled", None
                    break
                if time.monotonic() - started >= spec["timeout_seconds"]:
                    final_state, code = "timed_out", None
                    break
                phase_started = time.monotonic()
                phase.update(state="running", started_at=time.time())
                save_json(directory / "status.json", data)
                final_state, code = execute_phase(directory, step["command"], data, started, files, sizes, truncated)
                phase.update(state=final_state, finished_at=time.time(), exitCode=code,
                             duration_ms=max(0, int(round((time.monotonic() - phase_started) * 1000))))
                save_json(directory / "status.json", data)
                if final_state != "completed":
                    break
            data.update(state=final_state, exitCode=code)
        except Exception:
            data.update(state="failed", exitCode=None, error="Operation runner failed.")
            for phase in data["phases"]:
                if phase["state"] == "running":
                    phase.update(state="failed", finished_at=time.time(),
                                 duration_ms=milliseconds(phase.get("started_at"), time.time()))
        finally:
            for handle in files.values():
                handle.close()
            for phase in data["phases"]:
                if phase["state"] == "pending":
                    phase["state"] = "skipped"
            data.update(finished_at=time.time(), truncated=truncated,
                        duration_ms=max(0, int(round((time.monotonic() - started) * 1000))))
            data.pop("pid", None)
            save_json(directory / "status.json", data)
            # Commands are removed after completion; only safe labels and bounded logs remain.
            (directory / "spec.json").unlink(missing_ok=True)

def logs(a):
    data = status(a)
    directory = operation_dir(a["operation_id"])
    kind = a.get("stream", "stdout")
    if kind not in ("stdout", "stderr"):
        raise ValueError("Invalid stream.")
    offset = max(0, int(a.get("offset", 0)))
    limit = min(65536, max(1, int(a.get("limit_bytes", 16384))))
    file = directory / (kind + ".log")
    # Logs are bounded on disk. Redact the complete stored text BEFORE paging so
    # a token/key spanning chunks cannot leak across byte offsets.
    text = file.read_text(errors="replace") if file.exists() else ""
    if data["state"] in ("starting", "running"):
        # Hold back an incomplete line so a token split across writes is not shown.
        text = text[:text.rfind("\n") + 1]
    text = masked(text)
    encoded = text.encode()
    if offset > len(encoded) or offset < len(encoded) and encoded[offset] & 0xc0 == 0x80:
        raise ValueError("Invalid UTF-8 cursor; reuse next_offset from the previous response.")
    end = min(offset + limit, len(encoded))
    while end < len(encoded) and encoded[end] & 0xc0 == 0x80:
        end -= 1
    if end == offset and offset < len(encoded):
        end = offset + 1
        while end < len(encoded) and encoded[end] & 0xc0 == 0x80:
            end += 1
    piece = encoded[offset:end]
    return {"operation_id": a["operation_id"], "state": data["state"], "text": piece.decode(),
            "next_offset": min(offset + len(piece), len(encoded)), "more": offset + len(piece) < len(encoded),
            "truncated": data.get("truncated", {}).get(kind, False)}

def cancel(a):
    data = status(a)
    if data["state"] in ("starting", "running"):
        fd = os.open(operation_dir(a["operation_id"]) / "cancel", os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    return dict(data, cancellation_requested=data["state"] in ("starting", "running"))

def listing(a):
    directory = state_root() / "operations"
    query = a.get("query", "")
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("query must be at most 200 characters.")
    states = a.get("states")
    allowed = {"starting", "running", "completed", "failed", "cancelled", "timed_out", "process_lost"}
    if states is not None and (not isinstance(states, list) or not 1 <= len(states) <= 7 or any(state not in allowed for state in states)):
        raise ValueError("Invalid operation states.")
    def timestamp(value):
        if value is None:
            return None
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("History timestamps require a timezone.")
        return parsed.timestamp()
    after, before = timestamp(a.get("created_after")), timestamp(a.get("created_before"))
    if after is not None and before is not None and after > before:
        raise ValueError("created_after must not be later than created_before.")
    resource = resource_name(a.get("resource"))
    limit = a.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("History limit must be 1..100.")
    criteria = {"query": query.casefold(), "states": sorted(set(states)) if states else None,
                "resource": resource, "after": after, "before": before}
    filter_hash = digest(json.dumps(criteria, sort_keys=True).encode())
    boundary = None
    cursor = a.get("cursor")
    if cursor:
        try:
            if not isinstance(cursor, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", cursor):
                raise ValueError()
            page = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            boundary = page["before"]
            if page["filter_hash"] != filter_hash or not isinstance(boundary, list) or len(boundary) != 2 or not isinstance(boundary[0], (int, float)) or not re.fullmatch(r"[a-f0-9]{32}", boundary[1]):
                raise ValueError()
            boundary = tuple(boundary)
        except (ValueError, TypeError, KeyError):
            raise ValueError("Invalid history cursor or changed filters. Start a new search.") from None
    result, unavailable = [], 0
    if directory.exists():
        for entry in directory.iterdir():
            if entry.is_dir() and re.fullmatch(r"[a-f0-9]{32}", entry.name):
                try:
                    data = status({"operation_id": entry.name})
                    item = operation_summary(data)
                    order = (item["created_at"], item["operation_id"])
                    if boundary is not None and order >= boundary:
                        continue
                    if states and item["state"] not in states or resource is not None and item["resource"] != resource:
                        continue
                    if after is not None and item["created_at"] < after or before is not None and item["created_at"] > before:
                        continue
                    haystack = "\n".join(str(item.get(key) or "") for key in ("title", "request_id", "operation_id", "resource")).casefold()
                    if criteria["query"] not in haystack:
                        continue
                    result.append(item)
                except (OSError, ValueError, KeyError, TypeError):
                    unavailable += 1
    result.sort(key=lambda item: (item["created_at"], item["operation_id"]), reverse=True)
    more = len(result) > limit
    selected = result[:limit]
    next_cursor = None
    if more:
        last = selected[-1]
        next_cursor = base64.urlsafe_b64encode(json.dumps({"filter_hash": filter_hash, "before": [last["created_at"], last["operation_id"]]}).encode()).decode().rstrip("=")
    return {"operations": selected, "next_cursor": next_cursor, "more": more,
            "matched_remaining": len(result), "unavailable_count": unavailable}

def checked_file(file):
    if not file.is_absolute():
        raise ValueError("Remote path must be absolute.")
    if file.is_symlink():
        raise ValueError("Refusing symlink target.")
    if file.exists() and not file.is_file():
        raise ValueError("Target must be a regular file.")
    # Resolve parent symlinks so cooperating agents lock the same underlying path.
    return file.parent.resolve() / file.name

def current(file):
    if file.is_symlink():
        raise ValueError("Target changed to a symlink.")
    if file.exists():
        if file.stat().st_size > MAX_TEXT:
            raise ValueError("File is too large for text edit; use atomic upload.")
        content = file.read_bytes()
        return content, digest(content), file.stat()
    return b"", None, None

def file_hash(a):
    file = checked_file(pathlib.Path(a["path"]))
    if not file.exists():
        return {"path": str(file), "sha256": None, "exists": False}
    h = hashlib.sha256()
    with file.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    info = file.stat()
    return {"path": str(file), "sha256": h.hexdigest(), "exists": True,
            "mode": "%04o" % stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}

def file_snapshot(a):
    file = checked_file(pathlib.Path(a["path"]))
    h = hashlib.sha256()
    def identity(info):
        return {"size": info.st_size, "mtime_ns": str(info.st_mtime_ns), "ctime_ns": str(info.st_ctime_ns),
                "inode": str(info.st_ino), "device": str(info.st_dev)}
    with file.open("rb") as handle:
        before = identity(os.fstat(handle.fileno()))
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
        after = identity(os.fstat(handle.fileno()))
    if before != after or after != identity(file.stat()):
        raise ValueError("Remote source changed while hashing; retry only after creating a stable dump.")
    return dict(after, sha256=h.hexdigest())

def write(a):
    file = checked_file(pathlib.Path(a["path"]))
    locks = state_root() / "file-locks"
    secure_dir(locks)
    with lock(locks / digest(str(file).encode())):
        before, expected, info = current(file)
        if "expected_sha256" not in a or a["expected_sha256"] != expected:
            raise ValueError("File changed or expected_sha256 missing. Inspect/hash it and preview again.")
        content = a["content"].encode()
        if len(content) > MAX_TEXT:
            raise ValueError("Text exceeds 5 MiB.")
        if a.get("preview", False):
            diff = "".join(difflib.unified_diff(before.decode(errors="replace").splitlines(True),
                           content.decode().splitlines(True), fromfile="before", tofile="after"))
            safe = masked(diff)
            return {"path": str(file), "sha256": expected, "diff": safe[:65536], "truncated": len(safe) > 65536}
        fd, temp_name = tempfile.mkstemp(prefix=".mcp-stage-", dir=file.parent)
        backup = None
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                if info:
                    os.fchown(handle.fileno(), info.st_uid, info.st_gid)
                    os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
                elif a.get("mode"):
                    os.fchmod(handle.fileno(), int(a["mode"], 8))
            validator = a.get("validate_command")
            if validator:
                if "{path}" not in validator:
                    raise ValueError("validate_command must use {path} for staged file validation.")
                import shlex
                checked = subprocess.run(["/bin/bash", "-c", validator.replace("{path}", shlex.quote(temp_name))],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                if checked.returncode:
                    raise ValueError("Staged configuration validation failed; original file preserved.")
            # Detect external editors that don't participate in our lock.
            _, actual, _ = current(file)
            if actual != expected:
                raise ValueError("File changed during validation; original preserved.")
            if info and a.get("backup", True):
                directory = state_root() / "backups"
                secure_dir(directory)
                backup = directory / (uuid.uuid4().hex + ".bak")
                with open(backup, "xb") as handle:
                    os.chmod(backup, 0o600)
                    handle.write(before)
                    handle.flush()
                    os.fsync(handle.fileno())
            os.replace(temp_name, file)
            sync_parent(file)
            return {"path": str(file), "sha256": digest(content), "backup": str(backup) if backup else None}
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

def read(a):
    file = checked_file(pathlib.Path(a["path"]))
    first = max(1, int(a.get("start_line", 1)))
    count = min(2000, max(1, int(a.get("lines", 200))))
    result, size, truncated = [], 0, False
    with file.open("rb") as handle:
        # Limit line length too: binary files and huge single lines cannot exhaust memory.
        index = 0
        while True:
            chunk = handle.readline(65537)
            if not chunk:
                break
            index += 1
            if len(chunk) > 65536 and not chunk.endswith(b"\n"):
                truncated = True
                break
            if index < first:
                continue
            if len(result) >= count or size + len(chunk) > 65536:
                truncated = True
                break
            result.append(chunk.decode(errors="replace"))
            size += len(chunk)
    return {"text": masked("".join(result)), "start_line": first, "truncated": truncated}

def upload_commit(a):
    source = state_root() / "uploads" / a["upload_id"]
    if not re.fullmatch(r"[a-f0-9]{32}", a["upload_id"]):
        raise ValueError("Invalid upload_id.")
    file = checked_file(pathlib.Path(a["path"]))
    locks = state_root() / "file-locks"
    secure_dir(locks)
    with lock(locks / digest(str(file).encode())):
        expected = file_hash({"path": str(file)})["sha256"]
        if expected != a["expected_sha256"]:
            raise ValueError("Upload target changed; staged file retained.")
        info = file.stat() if file.exists() else None
        fd, staged = tempfile.mkstemp(prefix=".mcp-upload-", dir=file.parent)
        try:
            with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
                import shutil
                shutil.copyfileobj(inp, out, 65536)
                out.flush()
                os.fsync(out.fileno())
                if info:
                    os.fchown(out.fileno(), info.st_uid, info.st_gid)
                    os.fchmod(out.fileno(), stat.S_IMODE(info.st_mode))
                elif a.get("mode"):
                    os.fchmod(out.fileno(), int(a["mode"], 8))
            if file_hash({"path": str(file)})["sha256"] != expected:
                raise ValueError("Upload target changed during staging.")
            backup = None
            if info:
                backup_dir = state_root() / "backups"
                secure_dir(backup_dir)
                backup = backup_dir / (uuid.uuid4().hex + ".bak")
                import shutil
                with open(backup, "xb") as out, file.open("rb") as inp:
                    os.chmod(backup, 0o600)
                    shutil.copyfileobj(inp, out, 65536)
                    out.flush()
                    os.fsync(out.fileno())
            os.replace(staged, file)
            sync_parent(file)
            source.unlink()
            return dict(file_hash({"path": str(file)}), backup=str(backup) if backup else None)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)

def upload_prepare(a):
    if not re.fullmatch(r"[a-f0-9]{32}", a["upload_id"]):
        raise ValueError("Invalid upload_id.")
    directory = state_root() / "uploads"
    secure_dir(directory)
    file = directory / a["upload_id"]
    fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    return {"path": str(file)}

def drop_privileges():
    # Non-root SSH accounts can diagnose as themselves without extra setup.
    name = globals().get("p", {}).get("diagnostic_user") or ("mcp-diagnostics" if os.getuid() == 0 else pwd.getpwuid(os.getuid()).pw_name)
    account = pwd.getpwnam(name)
    if account.pw_uid == 0:
        raise ValueError("Diagnostics must use a non-root account.")
    if os.getuid() == 0:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    elif os.getuid() != account.pw_uid:
        raise ValueError("Cannot assume diagnostic account.")
    os.chdir("/")
    os.environ.clear()
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LANG="C.UTF-8")

def service(a):
    drop_privileges()
    name = a["name"]
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", name):
        raise ValueError("Invalid service name.")
    output = subprocess.run(["systemctl", "show", "--no-pager", name,
                             "--property=ActiveState,SubState,LoadState,MainPID"],
                            capture_output=True, timeout=10)
    return {"text": output.stdout.decode(), "exitCode": output.returncode}

def journal(a):
    # Journald normally restricts access. This explicitly privileged tool does not
    # add the diagnostic user to system-wide journal-reading groups.
    name = a["service"]
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", name):
        raise ValueError("Invalid service name.")
    count = min(1000, max(1, int(a.get("lines", 100))))
    output = subprocess.run(["journalctl", "-u", name, "-n", str(count),
                             "--no-pager", "--output=short-iso"], capture_output=True, timeout=15)
    text = output.stdout.decode(errors="replace")
    return {"text": masked(text[:65536]), "truncated": len(text) > 65536, "exitCode": output.returncode}

def secret_presence(a):
    # Report only presence, never value or hash (low-entropy values may be guessed).
    file = checked_file(pathlib.Path(a["path"]))
    if file.stat().st_size > MAX_TEXT:
        raise ValueError("Secret presence input exceeds 5 MiB.")
    names = a["names"]
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
        raise ValueError("Invalid variable name.")
    present = {name: False for name in names}
    with file.open() as handle:
        for line in iter(lambda: handle.readline(65536), ""):
            match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if match and match[1] in present:
                present[match[1]] = bool(match[2].strip().strip("\"'"))
    return {"present": present}

def probe(a):
    drop_privileges()
    host, port = a["host"], int(a["port"])
    timeout = min(10, max(1, int(a.get("timeout_seconds", 5))))
    mode = a.get("protocol", "tcp")
    result = {}
    try:
        dns_code = "import json,socket,sys; print(json.dumps(sorted(set(x[4][0] for x in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)))))"
        lookup = subprocess.run([sys.executable, "-c", dns_code, host, str(port)], capture_output=True, timeout=timeout)
        if lookup.returncode:
            raise OSError("DNS lookup failed.")
        addresses = json.loads(lookup.stdout)
        result["dns"] = {"ok": True, "addresses": addresses}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"dns": {"ok": False, "error": str(error)}}
    conn = None
    try:
        # Use an already-resolved address so the TCP stage cannot re-block on DNS.
        conn = socket.create_connection((addresses[0], port), timeout=timeout)
        conn.settimeout(timeout)
        result["tcp"] = {"ok": True}
        if mode == "tls":
            conn = ssl.create_default_context().wrap_socket(conn, server_hostname=host)
            result["tls"] = {"ok": True, "version": conn.version()}
        elif mode in ("smtp", "smtp_starttls"):
            def reply():
                data = b""
                while len(data) < 8192:
                    chunk = conn.recv(1)
                    if not chunk:
                        raise OSError("SMTP closed before response.")
                    data += chunk
                    if data.endswith(b"\r\n"):
                        lines = data.decode(errors="replace").splitlines()
                        if re.match(r"^\d{3} ", lines[-1]):
                            return data.decode(errors="replace")
                raise OSError("SMTP response too large.")
            greeting = reply()
            result["smtp"] = {"ok": greeting.startswith("220"), "greeting": greeting.strip()}
            if not greeting.startswith("220"):
                return result
            conn.sendall(b"EHLO mcp-probe.invalid\r\n")
            ehlo = reply()
            advertised = "STARTTLS" in ehlo.upper()
            result["starttls_advertised"] = advertised
            if mode == "smtp_starttls":
                if not advertised:
                    result["starttls"] = {"ok": False, "error": "Not advertised."}
                else:
                    conn.sendall(b"STARTTLS\r\n")
                    response = reply()
                    if not response.startswith("220"):
                        result["starttls"] = {"ok": False, "error": response.strip()}
                    else:
                        conn = ssl.create_default_context().wrap_socket(conn, server_hostname=host)
                        result["starttls"] = {"ok": True, "version": conn.version()}
            conn.sendall(b"QUIT\r\n")
    except (OSError, ssl.SSLError) as error:
        stage = "tcp" if conn is None else ("starttls" if mode == "smtp_starttls" else ("tls" if mode == "tls" else "smtp"))
        result[stage] = {"ok": False, "error": str(error)}
    finally:
        if conn:
            conn.close()
    return result

def dispatch(action, args, source):
    actions = {"status": status, "report": report, "logs": logs, "cancel": cancel, "list": listing,
               "file_hash": file_hash, "file_snapshot": file_snapshot, "write": write, "read": read,
               "upload_prepare": upload_prepare, "upload_commit": upload_commit,
               "service": service, "journal": journal, "secret_presence": secret_presence,
               "probe": probe, "resource_status": resource_status, "resource_unlock": resource_unlock}
    if action == "start":
        return start(args, source)
    if action not in actions:
        raise ValueError("Unknown helper action.")
    return actions[action](args)

if len(sys.argv) > 1 and sys.argv[1] == "_run":
    run(sys.argv[2])
elif "p" in globals():
    try:
        print(json.dumps(dispatch(p["action"], p["args"], p["source"])))
    except Exception as error:
        print(json.dumps({"error": str(error), "code": getattr(error, "code", None), "details": getattr(error, "details", None)}))
