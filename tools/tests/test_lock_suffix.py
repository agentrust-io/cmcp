"""Paired marker/hash controls through the parser and real Git driver."""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_lock_delta_suffix", ROOT / "tools/check_lock_delta.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

SUFFIX_HASH = " --hash=sha256:" + "a" * 64
SUFFIX_PIN = 'demo==1 ; python_version >= "3.11"'


class TestHashSuffix(unittest.TestCase):
    def test_marker_and_multiple_hashes_remain_valid(self):
        for marker in ('', ' ; python_version >= "3.11"',
                       ' ; os_name == "value --hash=sha256:BAD"'):
            with self.subTest(marker=marker):
                text = "demo==1" + marker + SUFFIX_HASH + SUFFIX_HASH.replace("a" * 64, "b" * 64)
                self.assertEqual(guard.parse_lock(text), {("demo", ("",), marker.strip()): "1"})

    def test_entire_hash_suffix_is_validated(self):
        for marker in ('', ' ; python_version >= "3.11"'):
            for extra in (' --hash=sha256:BAD', ' --hash=sha256:' + 'b' * 63,
                          ' --hash=sha256:' + 'b' * 65, ' --hash=sha512:' + 'b' * 64,
                          ' --index-url=https://example.invalid', ' trailing-junk'):
                with self.subTest(marker=marker, extra=extra):
                    with self.assertRaisesRegex(ValueError, "unsupported lock option or malformed hash"):
                        guard.parse_lock("demo==1" + marker + SUFFIX_HASH + extra)

    def test_unsupported_option_before_valid_hash_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unsupported lock option or malformed hash"):
            guard.parse_lock(SUFFIX_PIN + " --index-url=https://example.invalid" + SUFFIX_HASH)

    def test_required_lock_cli_refuses_malformed_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            shutil.copy2(ROOT / "tools/check_lock_delta.py", root / "tools/check_lock_delta.py")
            lock = root / "test.txt"
            for optimize in ([], ["-O"]):
                for extra, expected in (('', 0), (' --hash=sha256:BAD', 1),
                                        (' --index-url=https://example.invalid', 1)):
                    with self.subTest(optimize=optimize, extra=extra):
                        lock.write_text(SUFFIX_PIN + SUFFIX_HASH + extra)
                        result = subprocess.run(
                            [sys.executable, *optimize, str(root / "tools/check_lock_delta.py"), "test.txt"],
                            cwd=root, capture_output=True, text=True, check=False)
                        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                        if expected:
                            self.assertIn("unsupported lock option or malformed hash", result.stderr)


class TestNewLockSuffix(unittest.TestCase):
    def test_real_git_new_lock_checks_whole_suffix(self):
        for extra, expected in (('', 0), (' --hash=sha256:BAD', 1),
                                (' --index-url=https://example.invalid', 1)):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools").mkdir()
                (root / "requirements").mkdir()
                for source in ("check_lock_delta.py", "check_changed_locks.py"):
                    shutil.copy2(ROOT / "tools" / source, root / "tools" / source)

                def git(*args):
                    return subprocess.check_output(
                        ["git", "-c", "user.name=Lock test", "-c", "user.email=lock-test@example.invalid",
                         "-c", "commit.gpgsign=false", *args],
                        cwd=root, stderr=subprocess.DEVNULL, text=True).strip()

                git("init")
                git("add", ".")
                git("commit", "-m", "synthetic baseline")
                base = git("rev-parse", "HEAD")
                (root / "requirements/new.txt").write_text(SUFFIX_PIN + SUFFIX_HASH + extra)
                git("add", ".")
                git("commit", "-m", "synthetic new lock")
                for optimize in ([], ["-O"]):
                    result = subprocess.run(
                        [sys.executable, *optimize, str(root / "tools/check_changed_locks.py"), "--base", base],
                        cwd=root, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if expected:
                        self.assertIn("unsupported lock option or malformed hash", result.stderr)
                    else:
                        self.assertIn("NEW requirements/new.txt", result.stdout)
