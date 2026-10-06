"""Shared recording-runtime fixture for launcher tests."""
from pathlib import Path
import os
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def make_fake_runtime(directory, name):
    runtime = directory / name
    runtime.write_text((ROOT / "tests" / "fake_runtime.py").read_text())
    runtime.chmod(0o755)
    return runtime


class LauncherTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="launcher-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.home = self.base / "home"
        (self.home / ".config/opencode").mkdir(parents=True)
        self.project = self.base / "project"
        (self.project / ".opencode-sandbox").mkdir(parents=True)
        binaries = self.base / "bin"
        binaries.mkdir()
        for runtime in ("docker", "podman"):
            make_fake_runtime(binaries, runtime)
        self.log = self.base / "runtime.log"
        self.env = dict(os.environ, HOME=str(self.home),
                        PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""),
                        TEST_RUNTIME_LOG=str(self.log))
        for name in list(self.env):
            if name.startswith("TEST_") and name != "TEST_RUNTIME_LOG":
                del self.env[name]
        self.env.pop("BASH_ENV", None)
