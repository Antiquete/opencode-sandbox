"""Project initialization preserves valid external state stores."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INIT = Path(__file__).resolve().parents[1] / "opencode-project-init"


class ProjectInitTests(unittest.TestCase):
    def test_gitignore_is_left_to_user(self):
        for contents in (None, "existing\n"):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                home = base / "home"
                home.mkdir()
                project = base / "project"
                project.mkdir()
                (project / ".git").mkdir()
                ignore = project / ".gitignore"
                if contents is not None:
                    ignore.write_text(contents)
                    ignore.chmod(0o640)
                for _ in range(2):
                    result = subprocess.run([str(INIT)], cwd=project,
                                            env={**os.environ, "HOME": str(home)},
                                            text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Add .opencode-sandbox/ to your ignore rules", result.stdout)
                if contents is None:
                    self.assertFalse(ignore.exists())
                else:
                    self.assertEqual(ignore.read_text(), contents)
                    self.assertEqual(ignore.stat().st_mode & 0o777, 0o640)

    def test_state_creation_and_existing_paths(self):
        for kind in ("new", "directory", "directory-link", "file", "file-link", "broken-link"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                home = base / "home"
                home.mkdir()
                project = base / "project"
                project.mkdir()
                state = project / ".opencode-sandbox"
                target = base / "external"
                if kind in ("directory", "directory-link"):
                    target.mkdir(mode=0o750)
                    (target / "session").write_text("preserved")
                elif kind in ("file", "file-link"):
                    target.write_text("preserved")
                if kind.endswith("link"):
                    state.symlink_to(target)
                elif kind == "directory":
                    target.rename(state)
                elif kind == "file":
                    target.rename(state)
                result = subprocess.run(
                    [str(INIT)], cwd=project, env={**os.environ, "HOME": str(home)},
                    text=True, capture_output=True, timeout=5,
                )
                if kind in ("new", "directory", "directory-link"):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--opencode-model=some-model", result.stdout)
                    if kind == "new":
                        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                    else:
                        self.assertEqual((state / "session").read_text(), "preserved")
                        self.assertEqual(state.stat().st_mode & 0o777, 0o750)
                    self.assertEqual(state.is_symlink(), kind == "directory-link")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("not a directory", result.stdout)
                    self.assertEqual(state.is_symlink(), kind.endswith("link"))
