"""files functions, assembled into the standalone helper."""

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
        if "edits" in a:
            if not info:
                raise ValueError("Exact edit requires an existing file.")
            try:
                text = before.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Exact edit requires UTF-8 text.")
            if b"\x00" in before:
                raise ValueError("Binary files cannot be edited as text.")
            edits = a["edits"]
            if not isinstance(edits, list) or not 1 <= len(edits) <= 50:
                raise ValueError("Provide 1-50 exact edits.")
            for edit in edits:
                old, new = edit["old_text"], edit["new_text"]
                count = edit.get("expected_matches", 1)
                if not isinstance(old, str) or not old or not isinstance(new, str) or type(count) is not int or not 1 <= count <= 100:
                    raise ValueError("Invalid exact edit.")
                if "[REDACTED]" in old or "[REDACTED]" in new:
                    raise ValueError("Do not use masked output as replacement text.")
                if text.count(old) != count:
                    raise ValueError("Exact edit match count differs; original preserved.")
                if len(text.encode()) + count * (len(new.encode()) - len(old.encode())) > MAX_TEXT:
                    raise ValueError("Edited text exceeds 5 MiB.")
                text = text.replace(old, new)
            content = text.encode()
        else:
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
            if backup:
                finish_backup(backup)
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
            if backup:
                finish_backup(backup)
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
