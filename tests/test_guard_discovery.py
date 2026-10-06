"""Guard override validation with isolated launcher and runtime fixtures."""
import shutil
import subprocess
import unittest

import test_runtime


class GuardDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_runtime.RuntimeIdentityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.project.parent
        self.launcher = self.base / "opencode-sandbox"
        shutil.copy2(test_runtime.ROOT / "opencode-sandbox", self.launcher)
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
