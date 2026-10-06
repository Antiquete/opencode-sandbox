"""Exact source paths and HOME construction using recording runtimes."""
import csv
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from launcher_fixture import ROOT, make_fake_runtime


class MountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mounts-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / 'home ,"*\n'
        self.home.mkdir()
        self.project = self.base / 'project ,"*\n'
        self.project.mkdir()
        self.state = self.base / 'external state ,"*\n'
        self.state.mkdir()
        (self.project / ".opencode-sandbox").symlink_to(self.state)
        self.guard = self.base / 'guard ,"*\n'
        self.guard.write_text("#!/bin/sh\nexit 0\n")
        self.guard.chmod(0o755)
        binaries = self.base / "bin"
        binaries.mkdir()
        for runtime in ("docker", "podman"):
            make_fake_runtime(binaries, runtime)
        self.log = self.base / "calls.jsonl"
        self.env = dict(os.environ, HOME=str(self.home),
                        PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                        TEST_RUNTIME_LOG=str(self.log))
        self.env.pop("BASH_ENV", None)

    def launch(self, runtime, *options, rootless=True):
        self.log.write_text("")
        env = dict(self.env, TEST_DOCKER_SECURITY_OPTIONS='["name=rootless"]' if rootless else "[]",
                   TEST_PODMAN_ROOTLESS=str(rootless).lower())
        result = subprocess.run(
            ["bash", str(ROOT / "opencode-sandbox"), f"--runtime={runtime}",
             "--guard=" + os.path.relpath(self.guard, self.project), *options],
            cwd=self.project, env=env, input="y\n", text=True,
            capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        runs = [call for call in calls if call[:1] == ["run"]]
        self.assertEqual(len(runs), 1)
        return result, runs[0]

    def mounts(self, args):
        # Decode recorded CSV fields, without emulating runtime validation.
        return [next(csv.reader([args[i + 1]])) for i, arg in enumerate(args) if arg == "--mount"]

    def test_exact_sources_and_first_run_config(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                result, args = self.launch(runtime)
                mounts = self.mounts(args)
                for source, target in (
                    (self.project, "/workspace"),
                    (self.state, "/root/.local/share/opencode"),
                    (self.home / ".config/opencode", "/root/.config/opencode"),
                    (self.guard, "/opt/opencode-sandbox/guard"),
                ):
                    mount = next(fields for fields in mounts if "dst=" + target in fields)
                    self.assertIn("src=" + str(source), mount)
                    self.assertNotIn("", mount)
                self.assertTrue((self.home / ".config/opencode").is_dir())
                self.assertIn(str(self.state), result.stdout)
                self.assertTrue(any("dst=/workspace/.opencode-sandbox" in fields for fields in mounts))

    def test_config_mode_and_summary_agree(self):
        for runtime in ("docker", "podman"):
            for editable in (False, True):
                with self.subTest(runtime=runtime, editable=editable):
                    result, args = self.launch(runtime, *(["--edit-config"] if editable else []))
                    mount = next(fields for fields in self.mounts(args) if "dst=/root/.config/opencode" in fields)
                    self.assertEqual("readonly" in mount, not editable)
                    self.assertNotIn("", mount)
                    self.assertIn("Edit config:ON" if editable else "Edit config:OFF", result.stdout)

    def test_home_writable_for_both_user_mappings(self):
        for runtime in ("docker", "podman"):
            for rootless in (False, True):
                with self.subTest(runtime=runtime, rootless=rootless):
                    _, args = self.launch(runtime, rootless=rootless)
                    mounts = self.mounts(args)
                    # A rootful uid cannot traverse the image's mode 700 /root, so
                    # it needs a writable tmpfs there. Rootless is uid 0 already and
                    # must keep the image's own HOME contents.
                    homes = [fields for fields in mounts if "tmpfs-mode=1777" in fields]
                    if rootless:
                        self.assertEqual(homes, [])
                    else:
                        self.assertEqual([fields for fields in homes if "dst=/root" == fields[1]], homes)
                    self.assertEqual("--user" in args, not rootless)
                    self.assertEqual("XDG_STATE_HOME=/root/.state" in args, not rootless)
