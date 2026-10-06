"""Command construction and truthful launch summaries."""
import json
import subprocess
import unittest

from launcher_fixture import ROOT, LauncherTestCase


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = LauncherTestCase()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def launch(self, runtime, *options, guarded=False):
        self.fixture.log.write_text("")
        command = ["bash", str(ROOT / "opencode-sandbox"), f"--runtime={runtime}"]
        command += ([f"--guard={ROOT / 'build/opencode-guard'}"]
                    if guarded else ["--no-guard"])
        command += list(options)
        env = dict(self.fixture.env, NETWORK="inherited-network")
        result = subprocess.run(command, cwd=self.fixture.project, env=env, input="y\n",
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        calls = [json.loads(line) for line in self.fixture.log.read_text().splitlines()]
        runs = [call for call in calls if call[:1] == ["run"]]
        self.assertEqual(len(runs), 1)
        return output, runs[0]

    def test_guarded_and_unguarded_command_vectors(self):
        for runtime in ("docker", "podman"):
            for guarded in (False, True):
                for options in ([], ["--opencode-model=a b", "--opencode-model="]):
                    with self.subTest(runtime=runtime, guarded=guarded, options=options):
                        _, args = self.launch(runtime, *options, guarded=guarded)
                        image = args.index("ghcr.io/anomalyco/opencode:latest")
                        expected = (["opencode"] if guarded else [])
                        expected += [option.replace("--opencode-", "--", 1) for option in options]
                        self.assertEqual(args[image + 1:], expected)

    def test_summary_ignores_inherited_network_and_substring_lookalikes(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                output, _ = self.launch(runtime, "--container-label=--network none")
                self.assertIn("Network:ON", output)
                self.assertNotIn("inherited-network", output)
                self.assertIn("Guard:OFF", output)
                self.assertNotIn("blocked", output)
                self.assertIn(f"Project:{self.fixture.project} (read/write)", output)

    def test_summary_omits_supplied_options(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                output, _ = self.launch(runtime, "--no-network", "--container-network=host",
                    "--container-entrypoint=/bin/sh", "--container-mount=type=bind,src=/tmp,dst=/extra",
                    "--opencode-model=example", guarded=True)
                self.assertIn("Network:ON", output)
                self.assertIn("Network request:host", output)
                self.assertIn("Guard:ON", output)
                self.assertIn(str(ROOT / "build/opencode-guard"), output)
                self.assertNotIn("--model=example", output)
                self.assertNotIn("--entrypoint=/bin/sh", output)
                self.assertNotIn("--mount=", output)
                self.assertNotIn("OpenCode options", output)
                self.assertNotIn("Container options", output)
