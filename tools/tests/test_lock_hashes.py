"""Hash-only changes and full lock discovery through real Git/CLI boundaries."""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_lock_hashes", ROOT / "tools/check_lock_delta.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
H1 = " --hash=sha256:" + "a" * 64
H2 = " --hash=sha256:" + "b" * 64


class TestHashDelta(unittest.TestCase):
    def test_same_version_hash_changes_are_reported(self):
        for marker in ('', ' ; sys_platform == "win32"'):
            before = 'demo==1' + marker + H1
            for after in ('demo==1' + marker + H2, before + H2):
                for old, new in ((before, after), (after, before)):
                    with self.subTest(marker=marker, before=old, after=new):
                        self.assertEqual(guard.check_delta(old, new), ['demo'])

    def test_hash_order_and_duplicates_are_not_changes(self):
        self.assertEqual(guard.check_delta('demo==1' + H1 + H2,
                                          'demo==1' + H2 + H1 + H1), [])


class TestLockInventoryCLI(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'tools').mkdir()
        (self.root / 'requirements').mkdir()
        for name in ('check_lock_delta.py', 'check_changed_locks.py'):
            shutil.copy2(ROOT / 'tools' / name, self.root / 'tools' / name)
        # An empty requirements inventory is intentional: later fixtures are new
        # or existing locks according to a real successful Git base listing.
        self.git('init', '-q')
        self.git('add', '.')
        self.git('commit', '-qm', 'baseline')
        self.base = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-c', 'user.name=Lock test', '-c', 'user.email=lock-test@example.invalid',
             '-c', 'commit.gpgsign=false', *args], cwd=self.root,
            stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'candidate')

    def run_cli(self, name, *args):
        return subprocess.run([sys.executable, str(self.root / 'tools' / name), *args],
                              cwd=self.root, capture_output=True, text=True, check=False)

    def test_driver_reports_same_version_hash_changes(self):
        lock = self.root / 'requirements/runtime.txt'
        lock.write_text('demo==1' + H1)
        self.commit()
        base = self.git('rev-parse', 'HEAD')
        lock.write_text('demo==1' + H2)
        self.commit()
        result = self.run_cli('check_changed_locks.py', '--base', base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS requirements/runtime.txt: changed packages ['demo']", result.stdout)

    def test_driver_discovers_each_requirement_lock_name(self):
        for name in ('runtime', 'server', 'custom-generated'):
            with self.subTest(name=name):
                lock = self.root / f'requirements/{name}.txt'
                lock.write_text('demo==1' + H1)
                self.commit()
                result = self.run_cli('check_changed_locks.py', '--base', self.base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'NEW requirements/{name}.txt', result.stdout)
                lock.write_text('demo==1')
                self.commit()
                result = self.run_cli('check_changed_locks.py', '--base', self.base)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('missing SHA-256 hash', result.stderr)
                lock.write_text('demo==1' + H1)
                self.commit()

    def test_manual_inventory_checks_existing_and_new_locks(self):
        (self.root / 'requirements/runtime.txt').write_text('demo==1' + H1)
        self.commit()
        base = self.git('rev-parse', 'HEAD')
        (self.root / 'requirements/server.txt').write_text('other==1' + H2)
        result = self.run_cli('check_lock_delta.py', '--base', base, '--all-locks')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS requirements/runtime.txt', result.stdout)
        self.assertIn('PASS requirements/server.txt', result.stdout)
        self.assertIn('new lock; requires dependency review', result.stdout)
        (self.root / 'requirements/server.txt').write_text('other==1')
        result = self.run_cli('check_lock_delta.py', '--base', base, '--all-locks')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing SHA-256 hash', result.stderr)

    def test_manual_inventory_cannot_hide_deleted_or_renamed_locks(self):
        original = self.root / 'requirements/runtime.txt'
        original.write_text('demo==1' + H1)
        self.commit()
        base = self.git('rev-parse', 'HEAD')
        original.unlink()
        for renamed in (False, True):
            with self.subTest(renamed=renamed):
                if renamed:
                    (self.root / 'requirements/renamed.txt').write_text('demo==1' + H1)
                result = self.run_cli('check_lock_delta.py', '--base', base, '--all-locks')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requirements/runtime.txt', result.stderr)

    def test_bad_base_cannot_be_mistaken_for_new_inventory(self):
        (self.root / 'requirements/runtime.txt').write_text('demo==1' + H1)
        result = self.run_cli('check_lock_delta.py', '--base', 'missing-base', '--all-locks')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('new lock', result.stdout)


if __name__ == '__main__':
    unittest.main()
