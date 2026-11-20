"""Reject deleted Git locks substituted through a symlinked parent."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = "demo==1 --hash=sha256:" + "a" * 64 + "\n"


class TestLockParentSymlinks(unittest.TestCase):
    def test_deleted_lock_parent_substitution_and_ordinary_control(self):
        for linked_parent in (False, True):
            with self.subTest(linked_parent=linked_parent), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools").mkdir()
                nested = root / "requirements/nested"
                nested.mkdir(parents=True)
                elsewhere = root / "elsewhere"
                elsewhere.mkdir()
                (nested / "dev.txt").write_text(LOCK, encoding="utf-8")
                (elsewhere / "dev.txt").write_text(LOCK, encoding="utf-8")
                for source in ("check_lock_delta.py", "check_changed_locks.py"):
                    shutil.copy2(ROOT / "tools" / source, root / "tools" / source)

                def git(*args):
                    return subprocess.check_output(
                        ["git", "-c", "user.name=Lock test", "-c",
                         "user.email=lock-test@example.invalid", "-c",
                         "commit.gpgsign=false", *args],
                        cwd=root, stderr=subprocess.DEVNULL, text=True,
                    ).strip()

                git("init")
                git("add", ".")
                git("commit", "-m", "synthetic baseline")
                base = git("rev-parse", "HEAD")
                if linked_parent:
                    shutil.rmtree(nested)
                    try:
                        nested.symlink_to("../elsewhere", target_is_directory=True)
                    except OSError as exc:
                        self.skipTest(f"symlink creation unavailable: {exc}")
                else:
                    (nested / "dev.txt").write_text("# ordinary directory control\n" + LOCK, encoding="utf-8")
                git("add", "-A")
                git("commit", "-m", "replace parent or edit ordinary lock")
                status = git("diff", "--no-renames", "--name-status", base, "HEAD")
                self.assertIn(("D" if linked_parent else "M") + "\trequirements/nested/dev.txt", status)
                for optimized in (False, True):
                    with self.subTest(optimized=optimized):
                        result = subprocess.run(
                            [sys.executable, *(["-O"] if optimized else []),
                             str(root / "tools/check_changed_locks.py"), "--base", base],
                            cwd=root, capture_output=True, text=True, check=False,
                        )
                        if linked_parent:
                            self.assertNotEqual(result.returncode, 0, result.stdout)
                            self.assertIn("lock path must not contain symlinks: requirements/nested/dev.txt", result.stderr)
                            self.assertNotIn("PASS requirements/nested/dev.txt", result.stdout)
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertIn("PASS requirements/nested/dev.txt: changed packages []", result.stdout)
