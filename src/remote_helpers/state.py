"""state functions, assembled into the standalone helper."""

def digest(data):
    return hashlib.sha256(data).hexdigest()

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
    if file.name == 'status.json' and file.parent.parent.name == 'operations':
        return history_save(file, value)
    return plain_save_json(file, value)

def plain_save_json(file, value):
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
