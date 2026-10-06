"""Guard override validation with isolated launcher and runtime fixtures."""
import shutil
import subprocess
import unittest

from launcher_fixture import ROOT, LauncherTestCase


class GuardDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = LauncherTestCase()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.project.parent
        self.launcher = self.base / "opencode-sandbox"
        shutil.copy2(ROOT / "opencode-sandbox", self.launcher)
        self.guard = self.base / "build" / "opencode-guard"
        self.guard.parent.mkdir()
        self.guard.write_text("#!/bin/sh\nexit 0\n")
        self.guard.chmod(0o755)

    def launch(self, *options):
        return subprocess.run(
            ["bash", str(self.launcher), "--runtime=docker", *options],
            cwd=self.fixture.project, env=self.fixture.env,
            input="n\n", text=True, capture_output=True, timeout=5,
        )

    def test_explicit_executable_file_is_accepted(self):
        result = self.launch("--guard=" + str(self.guard))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Continue?", result.stdout)

    def test_explicit_directory_is_rejected(self):
        result = self.launch("--guard=" + str(self.guard.parent))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guard is missing or not executable", result.stdout)

    def test_source_fallback_and_empty_override(self):
        for options in ((), ("--guard=",)):
            with self.subTest(options=options):
                result = self.launch(*options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Guard binary:{self.guard}", result.stdout)

    def test_invalid_override_does_not_fall_back(self):
        for kind in ("missing", "non-executable"):
            with self.subTest(kind=kind):
                override = self.base / kind
                if kind == "non-executable":
                    override.write_text("not executable")
                result = self.launch(f"--guard={override}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("guard is missing or not executable", result.stdout)
                self.assertNotIn("Continue?", result.stdout)

    def test_disabled_guard_does_not_validate_override(self):
        self.guard.unlink()
        result = self.launch(f"--guard={self.base / 'missing'}", "--no-guard")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Guard:OFF", result.stdout)
