"""Bounded file operations, tested without production connections."""
import hashlib
import pathlib
import re
import sys
import tempfile
import unittest
from helper_loader import helper_source

@unittest.skipUnless(sys.platform.startswith("linux"), "Linux helper")
class SearchEditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sshops-search-")
        self.root = pathlib.Path(self.temp.name)
        source = re.sub(r"^STATE_ROOT = .*", "STATE_ROOT = pathlib.Path(" + repr(str(self.root / "state")) + ")", helper_source(), flags=re.M)
        self.ns = {"__name__": "search_edit_tests"}
        exec(compile(source, "synthetic-helper", "exec"), self.ns)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, file, data):
        file.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def test_exact_edit_preview_stale_ambiguous_and_metadata(self):
        file = self.root / "config.txt"
        original = b"\xef\xbb\xbfalpha\r\nbeta\r\n"
        sha = self.write(file, original)
        file.chmod(0o640)
        args = {"path": str(file), "expected_sha256": sha, "edits": [{"old_text": "beta", "new_text": "gamma"}], "preview": True}
        preview = self.ns["write"](args)
        self.assertIn("gamma", preview["diff"])
        self.assertEqual(file.read_bytes(), original)
        result = self.ns["write"](dict(args, preview=False))
        self.assertEqual(file.read_bytes(), original.replace(b"beta", b"gamma"))
        self.assertEqual(file.stat().st_mode & 0o777, 0o640)
        self.assertEqual(pathlib.Path(result["backup"]).read_bytes(), original)
        with self.assertRaises(ValueError):
            self.ns["write"](dict(args, preview=False))
        bad = dict(args, expected_sha256=result["sha256"], edits=[{"old_text": "alpha", "new_text": "ok"}, {"old_text": "missing", "new_text": "no"}], preview=False)
        with self.assertRaises(ValueError):
            self.ns["write"](bad)
        self.assertEqual(file.read_bytes(), original.replace(b"beta", b"gamma"))

    def test_validator_failure_and_binary_preserve_original(self):
        file = self.root / "text"
        sha = self.write(file, b"a a\n")
        args = {"path": str(file), "expected_sha256": sha, "edits": [{"old_text": "a", "new_text": "b"}]}
        with self.assertRaises(ValueError):
            self.ns["write"](args)
        args["edits"][0]["expected_matches"] = 2
        args["validate_command"] = "test -f {path} && false"
        with self.assertRaises(ValueError):
            self.ns["write"](args)
        self.assertEqual(file.read_bytes(), b"a a\n")
        sha = self.write(file, b"a\0b")
        with self.assertRaises(ValueError):
            self.ns["write"](dict(args, expected_sha256=sha))

    def test_search_limits_redaction_hidden_binary_and_symlink(self):
        self.write(self.root / "a.conf", b"status=true\npassword=synthetic-search-secret\n")
        self.write(self.root / ".env", b"password=private-hidden\n")
        self.write(self.root / "binary", b"status\0binary")
        (self.root / "link").symlink_to(self.root / "a.conf")
        found = self.ns["search_files"]({"path": str(self.root), "pattern": "*.conf"})
        self.assertEqual(len(found["results"]), 1)
        hits = self.ns["search_files"]({"path": str(self.root), "text": "password"})
        self.assertEqual(len(hits["results"]), 1)
        self.assertNotIn("synthetic-search-secret", str(hits))
        self.assertNotIn("private-hidden", str(hits))
        limited = self.ns["search_files"]({"path": str(self.root), "max_results": 1})
        self.assertTrue(limited["truncated"])
        self.assertEqual(len(limited["results"]), 1)
        with self.assertRaises(ValueError):
            self.ns["search_files"]({"path": str(self.root / "link")})
