"""Exercise Git rename detection at the generated-lock driver boundary."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = "".join(f"dependency-{i}==1 --hash=sha256:{'a' * 64}\n" for i in range(10))


class TestRenamedLockCLI(unittest.TestCase):
    def test_renamed_lock_requires_review_with_or_without_dependency_loss(self):
        for drop_dependency in (False, True):
            with self.subTest(drop_dependency=drop_dependency), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools").mkdir()
                (root / "requirements").mkdir()
                for source in ("check_lock_delta.py", "check_changed_locks.py"):
                    shutil.copy2(ROOT / "tools" / source, root / "tools" / source)
                original = root / "requirements/dev.txt"
                original.write_text(LOCK, encoding="utf-8")

                def git(*args):
                    return subprocess.check_output(
                        ["git", "-c", "user.name=Lock test", "-c",
                         "user.email=lock-test@example.invalid", "-c",
                         "commit.gpgsign=false", *args],
                        cwd=root, stderr=subprocess.DEVNULL, text=True,
                    ).strip()

                git("init")
                git("config", "diff.renames", "true")
                git("add", ".")
                git("commit", "-m", "synthetic baseline")
                base = git("rev-parse", "HEAD")
                renamed = original.with_name("renamed.txt")
                original.rename(renamed)
                if drop_dependency:
                    renamed.write_text("".join(LOCK.splitlines(keepends=True)[:-1]), encoding="utf-8")
                git("add", "-A")
                git("commit", "-m", "rename generated lock")
                # Confirm this fixture really exercises Git's rename classification.
                status = git("diff", "--name-status", "--find-renames", base, "HEAD")
                self.assertRegex(status, r"^R\d+\s+requirements/dev\.txt\s+requirements/renamed\.txt$")
                for optimized in (False, True):
                    with self.subTest(optimized=optimized):
                        result = subprocess.run(
                            [sys.executable, *(["-O"] if optimized else []),
                             str(root / "tools/check_changed_locks.py"), "--base", base],
                            cwd=root, capture_output=True, text=True, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn("deleted lock requires explicit maintainer review: requirements/dev.txt", result.stderr)


if __name__ == "__main__":
    unittest.main()
