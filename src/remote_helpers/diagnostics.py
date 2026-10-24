"""diagnostics functions, assembled into the standalone helper."""

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
