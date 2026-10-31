"""Synthetic controls for the generated-lock subset; no package installation."""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_lock_delta", ROOT / "tools/check_lock_delta.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
HASH = " --hash=sha256:" + "a" * 64
BASE = "core==1" + HASH + "\ncolorama==1 ; sys_platform == 'win32'" + HASH + "\n"


class TestLockDelta(unittest.TestCase):
    def test_version_upgrade_preserves_other_pins(self):
        self.assertEqual(guard.check_delta(BASE, BASE.replace("core==1", "core==2")), ["core"])

    def test_independent_corruptions(self):
        cases = [
            "core==1" + HASH,
            BASE.replace(" ; sys_platform == 'win32'", ""),
            BASE.replace(HASH, ""),
            BASE.replace("a" * 64, "a" * 63),
            BASE + "core==2" + HASH,
            "core>=1" + HASH,
            "",
        ]
        for index, after in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                guard.check_delta(BASE, after)

    def test_extra_loss_and_explicit_scoped_removal(self):
        with self.assertRaises(ValueError):
            guard.check_delta("coverage[toml]==1" + HASH, "coverage==1" + HASH)
        self.assertEqual(guard.check_delta(BASE, "core==1" + HASH, ["colorama"]), [])
        with self.assertRaises(ValueError):
            guard.check_delta(BASE, "colorama==1" + HASH, ["colorama"])

    def test_optimized_cli_still_refuses_missing_hash(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", dir=ROOT / "tools") as handle:
            handle.write("unhashed==1\n")
            handle.flush()
            result = subprocess.run(
                [sys.executable, "-O", str(ROOT / "tools/check_lock_delta.py"), handle.name],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing SHA-256", result.stderr)



class TestChangedLockCLI(unittest.TestCase):
    def test_actual_driver_refuses_regeneration_loss_and_accepts_upgrade(self):
        import shutil

        cases = [
            ("upgrade", BASE.replace("core==1", "core==2"), True),
            ("removed-marker", BASE.replace(" ; sys_platform == 'win32'", ""), False),
            ("deleted", None, False),
            ("missing-hash", "core==2\n", False),
        ]
        for name, after, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools").mkdir()
                (root / "requirements").mkdir()
                for source in ("check_lock_delta.py", "check_changed_locks.py"):
                    shutil.copy2(ROOT / "tools" / source, root / "tools" / source)
                lock = root / "requirements/test.txt"
                lock.write_text(BASE)

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
                if after is None:
                    lock.unlink()
                else:
                    lock.write_text(after)
                git("add", "-A")
                git("commit", "-m", "synthetic candidate")
                result = subprocess.run(
                    [sys.executable, str(root / "tools/check_changed_locks.py"),
                     "--base", base], cwd=root, capture_output=True, text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
