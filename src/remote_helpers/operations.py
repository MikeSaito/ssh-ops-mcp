"""operations functions, assembled into the standalone helper."""

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
            # Commands are removed after completion; only safe labels and bounded logs remain.
            (directory / "spec.json").unlink(missing_ok=True)
            save_json(directory / "status.json", data)

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
            "truncated": data.get("truncated", {}).get(kind, False),
            "logs_cleanup_performed": (directory / 'logs-cleaned.json').exists()}

def cancel(a):
    data = status(a)
    if data["state"] in ("starting", "running"):
        fd = os.open(operation_dir(a["operation_id"]) / "cancel", os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    return dict(data, cancellation_requested=data["state"] in ("starting", "running"))
