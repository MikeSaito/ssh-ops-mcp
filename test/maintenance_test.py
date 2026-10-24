"""Synthetic Linux state tests. No production connections."""
import hashlib
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux helper only')
class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sshops-maintenance-')
        self.root = pathlib.Path(self.temp.name)
        source = (pathlib.Path(__file__).parents[1] / 'src/remote_helper.py').read_text(encoding='utf-8')
        self.source = re.sub(r'^STATE_ROOT = .*', 'STATE_ROOT = pathlib.Path(' + repr(str(self.root / 'state')) + ')', source, flags=re.M)
        self.ns = {'__name__': 'maintenance_tests'}
        exec(compile(self.source, 'helper-tests', 'exec'), self.ns)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, n, state='completed'):
        operation_id = '%032x' % n
        directory = self.ns['operation_dir'](operation_id)
        self.ns['secure_dir'](directory)
        data = {'operation_id': operation_id, 'created_at': n, 'finished_at': n + 1, 'state': state,
                'title': 'Task %d' % n, 'request_id': 'request-%d' % n, 'spec_hash': 'unchanged', 'exitCode': 0}
        self.ns['plain_save_json'](directory / 'status.json', data)
        return operation_id, directory, data

    def cleanup(self, **args):
        return self.ns['state_cleanup']({'target_identity': 'a' * 24, 'category': 'operation_logs', **args})

    def test_large_history_uses_index_and_repairs_dirty_updates(self):
        for n in range(10000):
            self.fixture(n)
        first = self.ns['listing']({})
        self.assertEqual(first['matched_remaining'], 10000)
        self.assertEqual(first['operations'][0]['operation_id'], '%032x' % 9999)
        original = self.ns['load_json']
        reads = []
        def tracked(file):
            reads.append(str(file))
            return original(file)
        with patch.dict(self.ns, {'load_json': tracked}):
            second = self.ns['listing']({'cursor': first['next_cursor']})
        self.assertEqual(second['matched_remaining'], 9900)
        self.assertEqual(len(reads), 0, 'Indexed page must not reread every status JSON')
        operation_id, directory, data = self.fixture(20)
        data['title'] = 'Recovered after cache failure'
        self.ns['plain_save_json'](directory / 'status.json', data)
        dirty = self.root / 'state/history-dirty'
        self.ns['secure_dir'](dirty)
        (dirty / operation_id).touch()
        repaired = self.ns['listing']({'query': 'Recovered after cache failure'})
        self.assertEqual(len(repaired['operations']), 1)
        self.assertFalse((dirty / operation_id).exists())

    def test_corrupt_index_falls_back_then_rebuilds(self):
        self.fixture(1)
        self.ns['listing']({})
        (self.root / 'state/history.sqlite').write_bytes(b'corrupt index')
        result = self.ns['listing']({})
        self.assertEqual(len(result['operations']), 1)
        self.assertEqual(result['warnings'][0]['code'], 'history_index_unavailable')
        self.assertEqual(len(self.ns['listing']({})['operations']), 1)
        self.assertTrue(list((self.root / 'state').glob('history-invalid-*.sqlite')))

    def test_cleanup_preview_rechecks_content_and_preserves_deduplication(self):
        operation_id, directory, data = self.fixture(1)
        (directory / 'stdout.log').write_text('synthetic secret output')
        (directory / 'stderr.log').write_text('old error')
        plan = self.cleanup(created_before='2026-01-01T00:00:00Z')
        self.assertEqual(len(plan['candidates']), 2)
        self.assertTrue((directory / 'stdout.log').exists())
        (directory / 'stderr.log').write_text('changed by another process')
        result = self.cleanup(preview=False, plan_id=plan['plan_id'])
        self.assertEqual(len(result['removed']), 1)
        self.assertEqual(len(result['skipped']), 1)
        self.assertFalse((directory / 'stdout.log').exists())
        self.assertTrue((directory / 'stderr.log').exists())
        self.assertEqual(json.loads((directory / 'status.json').read_text()), data)
        with self.assertRaisesRegex(ValueError, 'already applied'):
            self.cleanup(preview=False, plan_id=plan['plan_id'])

    def test_unknown_symlink_foreign_expired_and_wrong_category_are_rejected(self):
        _, directory, _ = self.fixture(1, 'process_lost')
        (directory / 'stdout.log').write_text('unknown operation')
        _, finished, _ = self.fixture(2)
        target = self.root / 'outside'
        target.write_text('never delete')
        (finished / 'stdout.log').symlink_to(target)
        self.assertEqual(self.cleanup(created_before='2026-01-01T00:00:00Z')['candidates'], [])
        (finished / 'stdout.log').unlink()
        (finished / 'stdout.log').write_text('old')
        plan = self.cleanup(created_before='2026-01-01T00:00:00Z')
        with self.assertRaisesRegex(ValueError, 'another server'):
            self.ns['state_cleanup']({'category': 'operation_logs', 'target_identity': 'b' * 24, 'preview': False, 'plan_id': plan['plan_id']})
        plan_file = self.root / 'state/cleanup-plans' / (plan['plan_id'] + '.json')
        saved = json.loads(plan_file.read_text()); saved['expires_at'] = 1
        self.ns['save_json'](plan_file, saved)
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.cleanup(preview=False, plan_id=plan['plan_id'])
        self.assertTrue(target.exists())

    def test_backups_require_complete_metadata_and_explicit_category(self):
        backups = self.root / 'state/backups'
        self.ns['secure_dir'](backups)
        legacy = backups / ('b' * 32 + '.bak'); legacy.write_text('legacy')
        new = backups / ('c' * 32 + '.bak'); new.write_text('new backup')
        self.ns['finish_backup'](new)
        import time
        time.sleep(0.01)
        cutoff = self.ns['utc'](time.time())
        plan = self.cleanup(category='file_backups', created_before=cutoff)
        self.assertEqual(len(plan['candidates']), 1)
        result = self.cleanup(category='file_backups', preview=False, plan_id=plan['plan_id'])
        self.assertEqual(len(result['removed']), 1)
        self.assertTrue(legacy.exists()); self.assertFalse(new.exists())

if __name__ == '__main__':
    unittest.main()
