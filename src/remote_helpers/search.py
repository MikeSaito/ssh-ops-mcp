"""Bounded literal searches. No optional programs or regular-expression engine."""

def search_files(a):
    import fnmatch
    root = pathlib.Path(a["path"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("Search root must be an absolute real directory.")
    root = root.resolve()
    device = root.stat().st_dev
    limit = min(1000, max(1, int(a.get("max_results", 100))))
    depth_limit = min(32, max(0, int(a.get("max_depth", 8))))
    deadline = time.monotonic() + 10
    queue, result, visited, scanned, skipped = [(root, 0)], [], 0, 0, 0
    truncated = False
    needle = a.get("text")
    if needle is not None and (not isinstance(needle, str) or not needle or len(needle) > 4096):
        raise ValueError("Literal search text must be nonempty and bounded.")
    if a.get("case_sensitive", True) is False and needle is not None:
        needle = needle.casefold()
    while queue and not truncated:
        directory, depth = queue.pop(0)
        try:
            entries = []
            with os.scandir(directory) as iterator:
                for item in iterator:
                    entries.append(item)
                    if len(entries) + visited >= 10000:
                        truncated = True
                        break
            entries.sort(key=lambda item: item.name)
        except OSError:
            skipped += 1
            continue
        for entry in entries:
            visited += 1
            if visited > 10000 or time.monotonic() > deadline:
                truncated = True
                break
            if entry.is_symlink() or (entry.name.startswith(".") and not a.get("include_hidden", False)):
                continue
            sensitive = entry.name == ".env" or entry.name.startswith(".env.") or entry.name.startswith("id_") or entry.name.lower().endswith((".pem", ".key", ".p12", ".pfx", ".ppk"))
            if sensitive and not a.get("include_sensitive", False):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != device:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if depth < depth_limit:
                        queue.append((pathlib.Path(entry.path), depth + 1))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                relative = pathlib.Path(entry.path).relative_to(root).as_posix()
                pattern = a.get("pattern", "*")
                if not fnmatch.fnmatchcase(relative, pattern) and not fnmatch.fnmatchcase(entry.name, pattern):
                    continue
                if needle is None:
                    result.append({"path": str(root / relative), "size": info.st_size})
                else:
                    if info.st_size > 1024 * 1024:
                        skipped += 1
                        continue
                    if scanned + info.st_size > 16 * 1024 * 1024:
                        truncated = True
                        break
                    fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, "rb") as handle:
                        actual = os.fstat(handle.fileno())
                        if actual.st_ino != info.st_ino or actual.st_dev != info.st_dev or not stat.S_ISREG(actual.st_mode):
                            skipped += 1
                            continue
                        data = handle.read(1024 * 1024 + 1)
                    scanned += len(data)
                    if len(data) > 1024 * 1024 or b"\0" in data:
                        skipped += 1
                        continue
                    try:
                        lines = data.decode("utf-8-sig").splitlines()
                    except UnicodeDecodeError:
                        skipped += 1
                        continue
                    for index, line in enumerate(lines, 1):
                        compared = line if a.get("case_sensitive", True) else line.casefold()
                        if needle in compared:
                            result.append({"path": str(root / relative), "line_number": index, "line": masked(line)[:2048], "line_truncated": len(masked(line)) > 2048})
                            if len(result) >= limit:
                                truncated = True
                                break
                if len(result) >= limit or len(json.dumps(result).encode()) > 60000:
                    truncated = True
                    break
            except OSError:
                skipped += 1
    while result and len(json.dumps(result).encode()) > 65536:
        result.pop()
        truncated = True
    return {"results": result, "truncated": truncated, "visited": visited, "scanned_bytes": scanned, "skipped": skipped}
