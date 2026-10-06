"""Runtime identity preflight tests using recording runtimes."""
import json
import subprocess

from launcher_fixture import ROOT, LauncherTestCase


class RuntimeIdentityTests(LauncherTestCase):
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
