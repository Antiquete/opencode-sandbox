"""Launcher routing and lifecycle contracts using recording runtimes."""
import json
import subprocess
import unittest

from launcher_fixture import ROOT, LauncherTestCase


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = LauncherTestCase()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def launch(self, *options, confirm="y\n", **environment):
        self.fixture.log.write_text("")
        result = subprocess.run(
            ["bash", str(ROOT / "opencode-sandbox"), *options],
            cwd=self.fixture.project, env=dict(self.fixture.env, **environment),
            input=confirm, text=True, capture_output=True, timeout=5,
        )
        calls = [json.loads(line) for line in self.fixture.log.read_text().splitlines()]
        return result, [call for call in calls if call[:1] == ["run"]]

    def test_namespaces_preserve_argument_boundaries(self):
        result, runs = self.launch(
            "--runtime=docker", "--no-guard", "--no-pull", "--no-network",
            "--opencode-model=two words", "--opencode-empty=", "--opencode-value=a=b",
            "--opencode-model=last", "--container-label=two words",
            "--container-label=", "--container-label=a=b",
            "unknown", "--model=ignored", "--docker-label=ignored",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(runs), 1)
        args = runs[0]
        image = args.index("ghcr.io/anomalyco/opencode:latest")
        self.assertEqual(args[image + 1:], [
            "--model=two words", "--empty=", "--value=a=b", "--model=last",
        ])
        self.assertEqual([arg for arg in args[:image] if arg.startswith("--label=")],
                         ["--label=two words", "--label=", "--label=a=b"])
        self.assertIn("-it", args)
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertFalse(any("ignored" in arg or arg == "unknown" for arg in args))

    def test_auto_selection_and_exact_runsc_registration(self):
        cases = [
            ({}, "docker", "ON"),
            ({"TEST_RUNTIMES": "runc\nrunsc-other"}, "podman", "OFF"),
            ({"TEST_DOCKER_INFO_FAIL": "1"}, "podman", "OFF"),
            ({"TEST_RUNTIMES": "runc", "TEST_PODMAN_INFO_FAIL": "1"}, "docker", "OFF"),
        ]
        for environment, runtime, gvisor in cases:
            with self.subTest(environment=environment):
                result, runs = self.launch("--no-guard", confirm="n\n", **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Runtime:{runtime}", result.stdout)
                self.assertIn(f"gVisor:{gvisor}", result.stdout)
                self.assertFalse(runs)

    def test_unavailable_explicit_runtime_or_protection_refuses(self):
        cases = [
            (("--runtime=docker",), {"TEST_DOCKER_INFO_FAIL": "1"}, "not usable"),
            (("--gvisor",), {"TEST_RUNTIMES": "runsc-other"}, "needs Docker"),
            (("--runtime=podman", "--gvisor"), {}, "needs Docker"),
        ]
        for options, environment, error in cases:
            with self.subTest(options=options, environment=environment):
                result, runs = self.launch("--no-guard", *options, **environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stdout)
                self.assertNotIn("Continue?", result.stdout)
                self.assertFalse(runs)

    def test_cancellation_and_runtime_exit_status(self):
        for confirm in ("n\n", ""):
            with self.subTest(confirm=confirm):
                result, runs = self.launch("--runtime=docker", "--no-guard", confirm=confirm)
                self.assertEqual(result.returncode, 0)
                self.assertIn("Cancelled.", result.stdout)
                self.assertFalse(runs)
        result, runs = self.launch("--runtime=docker", "--no-guard", TEST_DOCKER_RUN_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(runs), 1)
