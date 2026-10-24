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

# BUNDLED_HELPERS

write = maintenance_guard(write)
upload_commit = maintenance_guard(upload_commit)

def dispatch(action, args, source):
    actions = {"status": status, "report": report, "logs": logs, "cancel": cancel, "list": listing,
               "file_hash": file_hash, "file_snapshot": file_snapshot, "write": write, "read": read,
               "upload_prepare": upload_prepare, "upload_commit": upload_commit,
               "service": service, "journal": journal, "secret_presence": secret_presence,
               "probe": probe, "resource_status": resource_status, "resource_unlock": resource_unlock,
               "state_usage": state_usage, "state_cleanup": state_cleanup}
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
