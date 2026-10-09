"""Linux-only integration tests with private temporary state; no SSH credentials."""
import hashlib
import json
import pathlib
import re
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform.startswith("linux"), "Remote helper requires Linux; use a disposable Linux container")
class OperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sshops-operation-test-")
        self.root = pathlib.Path(self.temp.name)
        original = (pathlib.Path(__file__).parents[1] / "src" / "remote_helper.py").read_text(encoding="utf-8")
        self.source = re.sub(r"^STATE_ROOT = .*", "STATE_ROOT = pathlib.Path(" + repr(str(self.root / "state")) + ")", original, flags=re.M)
        self.ns = {"__name__": "operation_test_helper"}
        exec(compile(self.source, "operation-test-helper", "exec"), self.ns)
        self.ids = []
        self.children = []
        original_popen = self.ns["subprocess"].Popen
        def tracked_popen(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            self.children.append(child)
            return child
        self.popen_patch = patch("subprocess.Popen", side_effect=tracked_popen)
        self.popen_patch.start()

    def tearDown(self):
        for operation_id in self.ids:
            try:
                current = self.call("status", {"operation_id": operation_id})
                if current["state"] in ("starting", "running"):
                    self.call("cancel", {"operation_id": operation_id})
                    self.wait(operation_id)
            except (OSError, ValueError):
                pass
        try:
            for child in self.children:
                child.wait(timeout=12)
        finally:
            self.popen_patch.stop()
            self.temp.cleanup()

    def call(self, action, args):
        return self.ns["dispatch"](action, args, self.source)

    def start(self, request="test", **kwargs):
        operation_id = hashlib.sha256(request.encode()).hexdigest()[:32]
        self.ids.append(operation_id)
        return self.call("start", {"operation_id": operation_id, "request_id": request, **kwargs})

    def wait(self, operation_id, running=False):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            current = self.call("status", {"operation_id": operation_id})
            if running and any(step["state"] == "running" for step in current.get("phases", [])):
                return current
            if not running and current["state"] not in ("starting", "running"):
                return current
            time.sleep(0.02)
        self.fail("Operation did not reach the expected state")

    def fixture(self, name, created, state="completed", **extras):
        operation_id = hashlib.sha256(name.encode()).hexdigest()[:32]
        directory = self.ns["operation_dir"](operation_id)
        self.ns["secure_dir"](directory)
        data = {"operation_id": operation_id, "created_at": created, "state": state, "exitCode": 0,
                "finished_at": created + 1, "title": name, "request_id": name, **extras}
        self.ns["save_json"](directory / "status.json", data)
        return operation_id

    def test_report_named_phases_and_deduplication(self):
        marker = self.root / "once"
        steps = [{"name": "Prepare", "command": "printf synthetic-hidden-command-marker"},
                 {"name": "Deploy", "command": "printf x >> " + str(marker)}]
        first = self.start("report-success", title="Deploy demo", steps=steps, timeout_seconds=10)
        self.assertEqual(self.wait(first["operation_id"])["state"], "completed")
        report = self.call("report", {"operation_id": first["operation_id"]})
        self.assertEqual(report["title"], "Deploy demo")
        self.assertEqual([step["state"] for step in report["phases"]], ["completed", "completed"])
        self.assertTrue(all(step["duration_ms"] >= 0 for step in report["phases"]))
        self.assertGreaterEqual(report["duration_ms"], sum(step["duration_ms"] for step in report["phases"]) - 2)
        self.assertGreaterEqual(report["elapsed_ms"], report["duration_ms"] - 2)
        self.assertTrue(report["created_at"].endswith("Z"))
        self.assertEqual(report["result"]["outcome"], "success")
        self.assertNotIn("synthetic-hidden-command-marker", json.dumps(report))
        self.assertFalse(report["legacy_metadata"])
        reused = self.start("report-success", title="Another label", steps=steps, timeout_seconds=10)
        self.assertTrue(reused["reused"])
        self.assertEqual(marker.read_text(), "x")
        with self.assertRaisesRegex(ValueError, "different"):
            self.start("report-success", steps=[{"name": "Changed", "command": "true"}], timeout_seconds=10)
        self.assertFalse((self.ns["operation_dir"](first["operation_id"]) / "spec.json").exists())

    def test_failure_skips_later_phases_without_rollback(self):
        marker = self.root / "never"
        operation = self.start(steps=[{"name": "Fail", "command": "exit 7"}, {"name": "Skipped", "command": "touch " + str(marker)}])
        self.assertEqual(self.wait(operation["operation_id"])["exitCode"], 7)
        report = self.call("report", {"operation_id": operation["operation_id"]})
        self.assertEqual([phase["state"] for phase in report["phases"]], ["failed", "skipped"])
        self.assertEqual(report["result"]["outcome"], "failure")
        self.assertFalse(marker.exists())

    def test_deadline_applies_to_all_phases(self):
        operation = self.start(timeout_seconds=1, steps=[{"name": "Fast", "command": "printf first"},
                                                       {"name": "Slow", "command": "sleep 30"},
                                                       {"name": "Skipped", "command": "true"}])
        self.assertEqual(self.wait(operation["operation_id"])["state"], "timed_out")
        report = self.call("report", {"operation_id": operation["operation_id"]})
        self.assertEqual(report["result"]["outcome"], "timeout")
        self.assertEqual([phase["state"] for phase in report["phases"]], ["completed", "timed_out", "skipped"])

    def test_running_lock_has_task_phase_and_explicit_rejection(self):
        operation = self.start("lock-holder", title="Demo deployment", resource="app", steps=[{"name": "Build", "command": "sleep 30"}, {"name": "Deploy", "command": "true"}])
        self.wait(operation["operation_id"], running=True)
        owner = self.call("resource_status", {"resource": "app"})
        self.assertTrue(owner["blocked"])
        self.assertEqual(owner["task"]["title"], "Demo deployment")
        self.assertEqual(owner["task"]["request_id"], "lock-holder")
        self.assertEqual(owner["task"]["current_phase"]["name"], "Build")
        self.assertGreaterEqual(owner["task"]["duration_ms"], 0)
        self.assertIn("Demo deployment", owner["explanation"])
        self.assertIn("Build", owner["explanation"])
        with self.assertRaises(self.ns["ResourceBusy"]) as caught:
            self.start("blocked", command="true", resource="app")
        self.assertEqual(caught.exception.code, "resource_busy")
        self.assertEqual(caught.exception.details["outcome"], "not_started")
        self.assertEqual(caught.exception.details["blocker"]["operation_id"], operation["operation_id"])
        self.call("cancel", {"operation_id": operation["operation_id"]})
        self.assertEqual(self.wait(operation["operation_id"])["state"], "cancelled")
        self.assertFalse(self.call("resource_status", {"resource": "app"})["blocked"])
        report = self.call("report", {"operation_id": operation["operation_id"]})
        self.assertEqual([phase["state"] for phase in report["phases"]], ["cancelled", "skipped"])

    def test_cancel_before_first_phase_never_executes(self):
        marker = self.root / "never"
        with patch("subprocess.Popen"):
            operation = self.start(command="touch " + str(marker))
        self.call("cancel", {"operation_id": operation["operation_id"]})
        self.ns["run"](operation["operation_id"])
        self.assertEqual(self.call("report", {"operation_id": operation["operation_id"]})["result"]["outcome"], "cancelled")
        self.assertFalse(marker.exists())

    def test_lost_process_stays_blocked_and_report_is_unknown(self):
        created = time.time() - 60
        operation_id = self.fixture("Lost task", created, state="running", boot_id="previous-boot", finished_at=None,
                                    started_at=created + 1, phases=[{"index": 1, "name": "Migration", "state": "running", "started_at": created + 2}])
        self.ns["save_json"](self.ns["resource_file"]("app"), {"resource": "app", "operation_id": operation_id})
        owner = self.call("resource_status", {"resource": "app"})
        self.assertTrue(owner["blocked"])
        self.assertEqual(owner["state"], "process_lost")
        report = self.call("report", {"operation_id": operation_id})
        self.assertEqual(report["result"]["outcome"], "unknown")
        self.assertEqual(report["phases"][0]["state"], "unknown")
        self.assertIsNone(report["phases"][0]["duration_ms"])
        with self.assertRaisesRegex(ValueError, "Verify"):
            self.call("resource_unlock", {"resource": "app", "expected_operation_id": operation_id})

    def test_history_filters_and_stable_pages(self):
        for index in range(6):
            self.fixture("Деплой " + str(index), 100, resource="/srv/app", state="failed" if index % 2 else "completed")
        self.fixture("Unrelated", 200, resource="other")
        search = {"query": "ДЕПЛОЙ", "resource": "/srv/app", "states": ["completed"], "limit": 1,
                  "created_after": "1970-01-01T00:01:40Z", "created_before": "1970-01-01T00:01:40+00:00"}
        seen, cursor = [], None
        while True:
            page = self.call("list", {**search, **({"cursor": cursor} if cursor else {})})
            seen.extend(operation["operation_id"] for operation in page["operations"])
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(seen), 3)
        self.assertEqual(len(set(seen)), 3)
        first = self.call("list", {"query": "Деплой", "limit": 2})
        self.fixture("Деплой new", 300)
        second = self.call("list", {"query": "Деплой", "limit": 2, "cursor": first["next_cursor"]})
        self.assertTrue(set(item["operation_id"] for item in first["operations"]).isdisjoint(item["operation_id"] for item in second["operations"]))
        self.assertTrue(all(item["created_at"] == 100 for item in second["operations"]))
        with self.assertRaisesRegex(ValueError, "changed filters"):
            self.call("list", {"query": "other", "cursor": first["next_cursor"]})
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.call("list", {"cursor": "bad!"})
        with self.assertRaises(ValueError):
            self.call("list", {"created_after": "2026-01-02T00:00:00Z", "created_before": "2026-01-01T00:00:00Z"})

    def test_history_does_not_search_commands_or_read_corrupt_entries(self):
        operation = self.start("history-label", title="Visible label", command="printf secret-only-in-command")
        self.wait(operation["operation_id"])
        self.assertEqual(self.call("list", {"query": "secret-only-in-command"})["operations"], [])
        self.assertEqual(len(self.call("list", {"query": "Visible label"})["operations"]), 1)
        directory = self.ns["operation_dir"]("f" * 32)
        self.ns["secure_dir"](directory)
        (directory / "status.json").write_text("broken", encoding="utf-8")
        page = self.call("list", {})
        self.assertEqual(page["unavailable_count"], 1)
        self.assertEqual(len(page["operations"]), 1)

    def test_legacy_request_hashes_and_partial_reports(self):
        spec = {"command": "true", "timeout_seconds": 3600}
        operation_id = self.fixture("legacy", 100, spec_hash=hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest())
        result = self.call("start", {"operation_id": operation_id, "command": "true"})
        self.assertTrue(result["reused"])
        report = self.call("report", {"operation_id": operation_id})
        self.assertTrue(report["legacy_metadata"])
        self.assertIsNone(report["duration_ms"])
        self.assertEqual(report["elapsed_ms"], 1000)
        self.assertEqual(report["result"]["outcome"], "success")

    def test_validation_and_redacted_labels(self):
        for invalid in ({}, {"command": "true", "steps": [{"name": "X", "command": "true"}]},
                        {"steps": []}, {"steps": [{"name": "", "command": "true"}]}):
            with self.assertRaises(ValueError):
                self.start(**invalid)
        operation = self.start(title="password=synthetic-label-secret", command="true")
        self.wait(operation["operation_id"])
        report = self.call("report", {"operation_id": operation["operation_id"]})
        self.assertNotIn("synthetic-label-secret", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
