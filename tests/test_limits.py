"""Default limits, forwarded overrides, and guard memory composition."""
import json
import subprocess
import unittest

import test_runtime


class LimitTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_runtime.RuntimeIdentityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def launch(self, runtime, *options):
        self.fixture.log.write_text("")
        env = dict(self.fixture.env, MEM_LIMIT="8g", CPUS_LIMIT="16",
                   PIDS_LIMIT="9999", DNS_SERVER="9.9.9.9")
        result = subprocess.run(
            ["bash", str(test_runtime.ROOT / "opencode-sandbox"),
             f"--runtime={runtime}", "--no-guard", *options],
            cwd=self.fixture.project, env=env, input="y\n", text=True,
            capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.fixture.log.read_text().splitlines()]
        runs = [call for call in calls if call[:1] == ["run"]]
        self.assertEqual(len(runs), 1)
        return result, runs[0]

    def values(self, args, name):
        values = []
        for i, arg in enumerate(args):
            if arg == name:
                values.append(args[i + 1])
            elif arg.startswith(name + "="):
                values.append(arg[len(name) + 1:])
        return values

    def test_fixed_defaults_ignore_ambient_resource_variables(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                result, args = self.launch(runtime)
                for option, expected in (("--memory", "4g"), ("--memory-swap", "4g"),
                                         ("--cpus", "2"), ("--pids-limit", "1024"),
                                         ("--dns", "1.1.1.1")):
                    self.assertEqual(self.values(args, option), [expected])
                self.assertIn("OPENCODE_GUARD_MEMORY=4g", self.values(args, "--env"))
                self.assertIn("4g RAM | 2 CPUs | 1024 processes", result.stdout)

    def test_repeated_overrides_and_memory_swap_coupling(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                result, args = self.launch(runtime, "--container-memory=512m",
                    "--container-memory=1.5GB", "--container-cpus=0.5",
                    "--container-pids-limit=256", "--container-label=a",
                    "--container-label=b", "--container-dns=8.8.8.8", "--container-dns=9.9.9.9")
                self.assertEqual(self.values(args, "--memory")[-1], "1.5GB")
                self.assertEqual(self.values(args, "--memory-swap"), ["1.5GB"])
                self.assertEqual(self.values(args, "--cpus")[-1], "0.5")
                self.assertEqual(self.values(args, "--pids-limit")[-1], "256")
                self.assertEqual(self.values(args, "--dns"), ["8.8.8.8", "9.9.9.9"])
                self.assertEqual(self.values(args, "--label"), ["a", "b"])
                self.assertIn("OPENCODE_GUARD_MEMORY=1.5GB", self.values(args, "--env"))
                self.assertIn("1.5GB RAM | 0.5 CPUs | 256 processes", result.stdout)

    def test_explicit_swap_and_guard_environment_override_follow_defaults(self):
        for runtime in ("docker", "podman"):
            with self.subTest(runtime=runtime):
                _, args = self.launch(runtime, "--container-memory=512m",
                    "--container-memory-swap=1g", "--container-env=OPENCODE_GUARD_MEMORY=256m")
                self.assertEqual(self.values(args, "--memory-swap"), ["512m", "1g"])
                guard_env = [value for value in self.values(args, "--env")
                             if value.startswith("OPENCODE_GUARD_MEMORY=")]
                self.assertEqual(guard_env, ["OPENCODE_GUARD_MEMORY=512m", "OPENCODE_GUARD_MEMORY=256m"])
