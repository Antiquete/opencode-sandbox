"""Launcher CLI: routing, runtime identity, guard discovery and launch summary."""
import json
import shutil
import subprocess
import unittest

from launcher_fixture import ROOT, LauncherTestCase


class ExecutionTests(LauncherTestCase):
    """Exact run vectors and the confirmation summary."""

    def launch(self, runtime, *options, guarded=False):
        self.log.write_text("")
        command = ["bash", str(ROOT / "opencode-sandbox"), f"--runtime={runtime}"]
        command += ([f"--guard={ROOT / 'build/opencode-guard'}"]
                    if guarded else ["--no-guard"])
        command += list(options)
        env = dict(self.env, NETWORK="inherited-network")
        result = subprocess.run(command, cwd=self.project, env=env, input="y\n",
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        runs = [call for call in calls if call[:1] == ["run"]]
        self.assertEqual(len(runs), 1)
        return result.stdout, runs[0]

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

    def test_unknown_arguments_are_rejected(self):
        for argument in ("--model=example", "--container-memory", "stray"):
            with self.subTest(argument=argument):
                self.log.write_text("")
                result = subprocess.run(
                    ["bash", str(ROOT / "opencode-sandbox"), "--runtime=docker",
                     "--no-guard", argument],
                    cwd=self.project, env=self.env, input="y\n",
                    text=True, capture_output=True, timeout=5,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("Error:", result.stderr)
                self.assertEqual(self.log.read_text(), "")

    def test_logins_are_shared_between_sandboxes(self):
        shared = self.home / ".local/share/opencode-sandbox"
        (self.project / ".opencode-sandbox/auth.json").write_text('{"old":"login"}')
        _, args = self.launch("docker")
        self.assertEqual((shared / "auth.json").read_text(), '{"old":"login"}')
        for name in ("auth.json", "mcp-auth.json"):
            with self.subTest(name=name):
                self.assertTrue(any(
                    f'"src={shared / name}"' in arg and
                    f"dst=/root/.local/share/opencode/{name}" in arg
                    for arg in args))

    def test_summary_ignores_inherited_network_and_substring_lookalikes(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                output, _ = self.launch(runtime, "--container-label=--network none")
                self.assertIn("Network:ON", output)
                self.assertNotIn("inherited-network", output)
                self.assertIn("Guard:OFF", output)
                self.assertNotIn("blocked", output)
                self.assertIn(f"Project:{self.project} (read/write)", output)

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


class RoutingTests(LauncherTestCase):
    """Runtime selection and lifecycle contracts."""

    def launch(self, *options, confirm="y\n", **environment):
        self.log.write_text("")
        result = subprocess.run(
            ["bash", str(ROOT / "opencode-sandbox"), *options],
            cwd=self.project, env=dict(self.env, **environment),
            input=confirm, text=True, capture_output=True, timeout=5,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, [call for call in calls if call[:1] == ["run"]]

    def test_namespaces_preserve_argument_boundaries(self):
        result, runs = self.launch(
            "--runtime=docker", "--no-guard", "--no-pull", "--no-network",
            "--opencode-model=two words", "--opencode-empty=", "--opencode-value=a=b",
            "--opencode-model=last", "--container-label=two words",
            "--container-label=", "--container-label=a=b",
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


class RuntimeIdentityTests(LauncherTestCase):
    """Runtime identity preflight."""

    def launch(self, runtime, rootless, fail=False):
        self.log.write_text("")
        env = dict(
            self.env,
            TEST_DOCKER_SECURITY_OPTIONS='["name=rootless"]' if rootless else "[]",
            TEST_PODMAN_ROOTLESS=str(rootless).lower(),
            **{
                f"TEST_{runtime.upper()}_INFO_FAIL": "0",
                f"TEST_{runtime.upper()}_INFO_FORMAT_FAIL": "1" if fail else "0",
            },
        )
        result = subprocess.run(
            ["bash", str(ROOT / "opencode-sandbox"), f"--runtime={runtime}", "--no-guard"],
            cwd=self.project, env=env, input="n\n", text=True,
            capture_output=True, timeout=5,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        identity_queries = [
            call for call in calls
            if call[:1] == ["info"] and "--format" in call
            and any("SecurityOptions" in arg or "Rootless" in arg for arg in call)
        ]
        self.assertTrue(identity_queries)
        self.assertFalse(any(call[:1] == ["run"] for call in calls))
        return result

    def test_successful_identity_query_reaches_consent(self):
        for runtime in ("docker", "podman"):
            for rootless in (False, True):
                with self.subTest(runtime=runtime, rootless=rootless):
                    result = self.launch(runtime, rootless)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Continue?", result.stdout)
                    self.assertIn("Cancelled.", result.stdout)

    def test_failed_identity_query_stops_even_with_valid_output(self):
        for runtime in ("docker", "podman"):
            for rootless in (False, True):
                with self.subTest(runtime=runtime, rootless=rootless):
                    result = self.launch(runtime, rootless, fail=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"cannot determine whether {runtime} is rootless", result.stdout)
                    self.assertNotIn("Continue?", result.stdout)

    def test_rootless_gvisor_warns_without_rejecting_launch(self):
        for rootless in (False, True):
            for explicit in (False, True):
                with self.subTest(rootless=rootless, explicit=explicit):
                    env = dict(self.env, TEST_DOCKER_SECURITY_OPTIONS='["name=rootless"]' if rootless else "[]")
                    result = subprocess.run(
                        ["bash", str(ROOT / "opencode-sandbox"), *(["--gvisor"] if explicit else [])],
                        cwd=self.project, env=env, input="n\n", text=True,
                        capture_output=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Continue?", result.stdout)
                    gvisor = explicit or not rootless
                    self.assertIn("gVisor:ON" if gvisor else "gVisor:OFF", result.stdout)
                    self.assertIn("Guard:OFF" if gvisor else "Guard:ON", result.stdout)
                    self.assertEqual("Warning: rootless gVisor" in result.stdout, rootless and explicit)


class GuardDiscoveryTests(LauncherTestCase):
    """Guard override validation with an isolated launcher copy."""

    def setUp(self):
        super().setUp()
        self.launcher = self.base / "opencode-sandbox"
        shutil.copy2(ROOT / "opencode-sandbox", self.launcher)
        self.guard = self.base / "build" / "opencode-guard"
        self.guard.parent.mkdir()
        self.guard.write_text("#!/bin/sh\nexit 0\n")
        self.guard.chmod(0o755)

    def launch(self, *options):
        return subprocess.run(
            ["bash", str(self.launcher), "--runtime=docker", *options],
            cwd=self.project, env=self.env,
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
