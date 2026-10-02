"""Launcher regression tests using fake Docker and Podman executables."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def make_fake_runtime(directory, name):
    runtime = directory / name
    runtime.write_text((ROOT / "tests" / "fake_runtime.py").read_text())
    runtime.chmod(0o755)
    return runtime


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="launcher-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        make_fake_runtime(self.bin, "docker")
        make_fake_runtime(self.bin, "podman")
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / ".opencode-sandbox").mkdir(mode=0o700)
        self.config = self.base / "shared-config"
        self.config.mkdir()
        (self.config / "opencode.json").write_text('{"permission":"allow"}\n')
        self.log = self.base / "runtime.log"
        self.log.write_text("")
        self.guard = self.base / "guard-stub"
        self.guard.write_bytes(b"#!/bin/sh\n")
        self.guard.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            OPENCODE_CONFIG_DIR=str(self.config),
            OPENCODE_RUNTIME="docker",
            OPENCODE_IMAGE="test/opencode:local",
            OPENCODE_GUARD=str(self.guard),
            TEST_DOCKER_SECURITY_OPTIONS="[]",
            TEST_RUNTIME_LOG=str(self.log),
        )

    def launch(
        self, *args, runtime="docker", env_extra=None, launcher=None, input_text="y\n"
    ):
        env = dict(self.env, OPENCODE_RUNTIME=runtime)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", str(launcher or ROOT / "opencode-sandbox"), *args],
            cwd=self.project,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=60,
        )

    def run_args(self, *args, **kwargs):
        self.log.write_text("")
        result = self.launch(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [
            call
            for call in map(json.loads, self.log.read_text().splitlines())
            if call and call[0] == "run"
        ]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def launch_without_run(self, *args, **kwargs):
        self.log.write_text("")
        result = self.launch(*args, **kwargs)
        calls = list(map(json.loads, self.log.read_text().splitlines()))
        self.assertFalse(any(call[:1] == ["run"] for call in calls))
        return result

    @staticmethod
    def mounts(args):
        """Return values passed to --mount in a recorded runtime call."""
        return [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]

    def test_shared_config_mounts_and_container_limits_are_retained(self):
        args = self.run_args()
        self.assertEqual(args[args.index("--pull") + 1], "always")
        envs = [args[i + 1] for i, arg in enumerate(args) if arg == "--env"]
        self.assertIn("OPENCODE_GUARD_MEMORY=4g", envs)
        mounts = self.mounts(args)
        shared_sources = (
            self.project,
            self.project / ".opencode-sandbox",
            self.config,
        )
        for mount in mounts:
            if mount.startswith("type=bind") and any(
                f"src={path}," in mount for path in shared_sources
            ):
                self.assertIn("bind-recursive=disabled", mount)
                self.assertIn("bind-propagation=rprivate", mount)
        config = next(m for m in mounts if "dst=/root/.config/opencode," in m)
        self.assertIn("readonly", config)
        state = next(m for m in mounts if "dst=/root/.local/share/opencode," in m)
        self.assertNotIn("readonly", state)
        mask = next(m for m in mounts if "dst=/workspace/.opencode-sandbox," in m)
        self.assertTrue(mask.startswith("type=tmpfs,"))
        self.assertIn("readonly", mask)
        for dst in (
            "/sys/devices",
            "/sys/module",
            "/sys/bus/pci",
            "/sys/bus/usb",
            "/sys/bus/scsi",
            "/sys/block",
            "/sys/class/dmi/id",
            "/sys/kernel",
            "/sys/power",
            "/sys/fs/pstore",
        ):
            mask = next(m for m in mounts if f"dst={dst}," in m)
            self.assertTrue(mask.startswith("type=tmpfs,"))
            self.assertIn("readonly", mask)
        self.assertTrue(
            any("dst=/etc/resolv.conf," in m and "readonly" in m for m in mounts)
        )
        self.assertTrue(
            any("dst=/etc/hosts," in m and "readonly" in m for m in mounts)
        )
        for flag in ("--hostname", "--ipc", "--cgroupns", "--pids-limit", "--memory-swap"):
            self.assertIn(flag, args)
        self.assertEqual(
            args[args.index("--memory") + 1],
            args[args.index("--memory-swap") + 1],
        )
        self.assertEqual(args[args.index("--cpus") + 1], "2")
        self.assertIn("core=0", args[args.index("--ulimit") + 1])
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        security_opts = [
            args[i + 1] for i, arg in enumerate(args) if arg == "--security-opt"
        ]
        self.assertIn("no-new-privileges:true", security_opts)
        self.assertNotIn("--cap-add", args)

    def test_offline_mode_keeps_the_image_pull_disabled(self):
        args = self.run_args("--offline")
        self.assertEqual(args[args.index("--pull") + 1], "never")

    def test_podman_does_not_copy_hidden_state_into_mask(self):
        args = self.run_args("--runtime", "podman")
        mounts = self.mounts(args)
        expected_masks = [
            path
            for path in ("/proc/cmdline", "/proc/cpuinfo", "/proc/meminfo")
            if Path(path).exists()
        ]
        if expected_masks:
            self.assertIn("mask=" + ":".join(expected_masks), args)
        for mount in mounts:
            if mount.startswith("type=tmpfs"):
                self.assertIn("notmpcopyup", mount)
            if mount.startswith("type=bind") and any(
                f"src={path}," in mount
                for path in (self.project, self.project / ".opencode-sandbox", self.config)
            ):
                self.assertIn("bind-nonrecursive", mount)

    def test_auto_runtime_falls_back_to_podman_when_docker_is_unavailable(self):
        args = self.run_args(
            runtime="auto", env_extra={"TEST_DOCKER_INFO_FAIL": "1"}
        )
        calls = list(map(json.loads, self.log.read_text().splitlines()))
        self.assertEqual(
            [call for call in calls if call[:1] == ["info"]],
            [
                ["info", "--format", "{{json .SecurityOptions}}"],
                ["info", "--format", "{{.Host.Security.Rootless}}"],
            ],
        )
        self.assertIn("bind-nonrecursive", " ".join(self.mounts(args)))
        self.assertIn("no-new-privileges", args)
        self.assertNotIn("no-new-privileges:true", args)

    def test_runtime_errors_cover_missing_cli_and_unreachable_runtimes(self):
        minimal_bin = self.base / "minimal-bin"
        minimal_bin.mkdir()
        for command in ("bash", "dirname", "readlink", "find", "mkdir"):
            (minimal_bin / command).symlink_to(shutil.which(command))
        missing_cli = self.launch_without_run(
            runtime="docker", env_extra={"PATH": str(minimal_bin)}
        )
        self.assertNotEqual(missing_cli.returncode, 0)
        self.assertIn("docker' CLI was not found", missing_cli.stdout)

        gvisor_without_runtime = self.launch_without_run(
            "--gvisor", runtime="podman", env_extra={"TEST_PODMAN_INFO_FAIL": "1"}
        )
        self.assertNotEqual(gvisor_without_runtime.returncode, 0)
        self.assertIn("--gvisor requires Docker", gvisor_without_runtime.stdout)
        self.assertNotIn("cannot reach the podman daemon", gvisor_without_runtime.stdout)

        gvisor_missing_cli = self.launch_without_run(
            "--gvisor", runtime="docker", env_extra={"PATH": str(minimal_bin)}
        )
        self.assertNotEqual(gvisor_missing_cli.returncode, 0)
        self.assertIn("docker' CLI was not found", gvisor_missing_cli.stdout)

        unreachable = self.launch_without_run(
            env_extra={"TEST_DOCKER_INFO_FAIL": "1"}
        )
        self.assertNotEqual(unreachable.returncode, 0)
        self.assertIn("cannot reach the docker daemon", unreachable.stdout)

        no_runtime = self.launch_without_run(
            runtime="auto",
            env_extra={
                "TEST_DOCKER_INFO_FAIL": "1",
                "TEST_PODMAN_INFO_FAIL": "1",
            },
        )
        self.assertNotEqual(no_runtime.returncode, 0)
        self.assertIn("no container runtime found", no_runtime.stdout)

        unknown_runtime = self.launch_without_run(runtime="unsupported")
        self.assertNotEqual(unknown_runtime.returncode, 0)
        self.assertIn("unknown runtime 'unsupported'", unknown_runtime.stdout)

    def test_runtime_uid_mapping_handles_rootful_and_rootless_modes(self):
        cases = (
            ("docker", (), {"TEST_DOCKER_SECURITY_OPTIONS": "[]"}),
            (
                "podman",
                ("--runtime", "podman"),
                {"TEST_PODMAN_ROOTLESS": "false"},
            ),
        )
        for runtime, runtime_args, env_extra in cases:
            with self.subTest(runtime=runtime):
                args = self.run_args(
                    *runtime_args,
                    runtime=runtime,
                    env_extra=env_extra,
                )
                if os.getuid() == 0:
                    self.assertNotIn("--user", args)
                else:
                    self.assertEqual(
                        args[args.index("--user") + 1],
                        f"{os.getuid()}:{os.getgid()}",
                    )
                    self.assertEqual(args[args.index("--env") + 1], "HOME=/root")
                    root_tmpfs = next(
                        m for m in self.mounts(args) if "dst=/root," in m
                    )
                    self.assertIn("tmpfs-size=1073741824", root_tmpfs)
                    self.assertIn("tmpfs-mode=1777", root_tmpfs)

        for runtime, env_extra in (
            ("docker", {"TEST_DOCKER_SECURITY_OPTIONS": '["name=rootless"]'}),
            ("podman", {"TEST_PODMAN_ROOTLESS": "true"}),
        ):
            with self.subTest(runtime=runtime, rootless=True):
                args = self.run_args(runtime=runtime, env_extra=env_extra)
                self.assertNotIn("--user", args)

    def test_guard_mount_and_exact_entrypoint_argv(self):
        guard_link = self.base / "guard-link"
        guard_link.symlink_to(self.guard)
        args = self.run_args(
            "--", "run", "hello world", env_extra={"OPENCODE_GUARD": str(guard_link)}
        )
        self.assertEqual(
            args[args.index("--entrypoint") + 1], "/opt/opencode-sandbox/guard"
        )
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        guard_mount = next(
            m for m in self.mounts(args) if "dst=/opt/opencode-sandbox/guard," in m
        )
        self.assertIn(f"src={self.guard.resolve()},", guard_mount)
        self.assertIn("readonly", guard_mount)
        image_index = args.index("test/opencode:local")
        self.assertEqual(
            args[image_index:],
            ["test/opencode:local", "opencode", "run", "hello world"],
        )

    def test_gvisor_bypasses_guard_and_preserves_forwarded_argv(self):
        args = self.run_args(
            "--gvisor",
            "--",
            "run",
            "hello world",
            env_extra={"OPENCODE_GUARD": str(self.base / "missing-guard")},
        )
        self.assertNotIn("--entrypoint", args)
        self.assertNotIn("/opt/opencode-sandbox/guard", " ".join(self.mounts(args)))
        self.assertIn("runsc", args[args.index("--runtime") + 1])
        image_index = args.index("test/opencode:local")
        self.assertEqual(
            args[image_index:], ["test/opencode:local", "run", "hello world"]
        )
        calls = list(map(json.loads, self.log.read_text().splitlines()))
        self.assertEqual(len([call for call in calls if call[:1] == ["info"]]), 1)

        args = self.run_args(
            "--gvisor",
            env_extra={"TEST_DOCKER_SECURITY_OPTIONS": '["name=rootless"]'},
        )
        self.assertNotIn("--user", args)
        calls = list(map(json.loads, self.log.read_text().splitlines()))
        info_calls = [call for call in calls if call[:1] == ["info"]]
        self.assertEqual(len(info_calls), 1)
        self.assertIn("Runtimes", info_calls[0][info_calls[0].index("--format") + 1])

    def test_gvisor_requires_an_exact_runsc_registration(self):
        result = self.launch_without_run(
            "--gvisor", env_extra={"TEST_RUNTIMES": "runc\nmy-runsc"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs the 'runsc' runtime", result.stdout)

    def test_default_guard_comes_from_launcher_build_directory(self):
        install = self.base / "install"
        build = install / "build"
        build.mkdir(parents=True)
        default_guard = build / "opencode-guard"
        default_guard.write_bytes(b"#!/bin/sh\n")
        default_guard.chmod(0o755)
        launcher = install / "opencode-sandbox"
        shutil.copy(ROOT / "opencode-sandbox", launcher)
        self.log.write_text("")
        result = self.launch(launcher=launcher, env_extra={"OPENCODE_GUARD": ""})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [
            call
            for call in map(json.loads, self.log.read_text().splitlines())
            if call and call[0] == "run"
        ]
        self.assertEqual(len(runs), 1)
        guard_mount = next(
            m for m in self.mounts(runs[0]) if "dst=/opt/opencode-sandbox/guard," in m
        )
        self.assertIn(f"src={default_guard},", guard_mount)

    def test_missing_or_non_executable_guard_fails_closed(self):
        missing = self.launch_without_run(
            env_extra={"OPENCODE_GUARD": str(self.base / "absent")}
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("guard", missing.stdout + missing.stderr)
        non_executable = self.base / "non-executable-guard"
        non_executable.write_text("not executable\n")
        rejected = self.launch_without_run(
            env_extra={"OPENCODE_GUARD": str(non_executable)}
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_guard_cannot_live_under_writable_project_or_config(self):
        project_guard = self.project / "guard"
        project_guard.write_bytes(b"#!/bin/sh\n")
        project_guard.chmod(0o755)
        rejected = self.launch_without_run(
            env_extra={"OPENCODE_GUARD": str(project_guard)}
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("writable project", rejected.stdout + rejected.stderr)

        config_guard = self.config / "guard"
        config_guard.write_bytes(b"#!/bin/sh\n")
        config_guard.chmod(0o755)
        self.assertEqual(
            self.launch(env_extra={"OPENCODE_GUARD": str(config_guard)}).returncode,
            0,
        )
        rejected = self.launch_without_run(
            "--config-rw", env_extra={"OPENCODE_GUARD": str(config_guard)}
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("writable shared config", rejected.stdout + rejected.stderr)

    def test_guard_mount_path_rejects_csv_unsafe_characters(self):
        unsafe_guard = self.base / "guard,unsafe"
        unsafe_guard.write_bytes(b"#!/bin/sh\n")
        unsafe_guard.chmod(0o755)
        result = self.launch_without_run(
            env_extra={"OPENCODE_GUARD": str(unsafe_guard)}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container mount paths", result.stdout + result.stderr)

        raw_link = self.base / "guard,link"
        raw_link.symlink_to(self.guard)
        result = self.launch_without_run(env_extra={"OPENCODE_GUARD": str(raw_link)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container mount paths", result.stdout + result.stderr)

        newline_target = self.base / "guard\n"
        newline_target.write_bytes(b"#!/bin/sh\n")
        newline_target.chmod(0o755)
        guard_link = self.base / "guard-link"
        guard_link.symlink_to(newline_target)
        result = self.launch_without_run(
            env_extra={"OPENCODE_GUARD": str(guard_link)}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container mount paths", result.stdout + result.stderr)

    def test_cancellation_prevents_network_creation_and_container_launch(self):
        result = self.launch(
            "--docker-network",
            "new-network",
            input_text="n\n",
            env_extra={"TEST_NET_MISSING": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Cancelled.", result.stdout)
        calls = list(map(json.loads, self.log.read_text().splitlines()))
        self.assertFalse(any(call[:2] == ["network", "create"] for call in calls))
        self.assertFalse(any(call[:1] == ["run"] for call in calls))

    def test_launch_files_are_cleaned_after_runtime_failure(self):
        existing = set(Path("/tmp").glob("opencode-launch.*"))
        result = self.launch(env_extra={"TEST_DOCKER_RUN_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(set(Path("/tmp").glob("opencode-launch.*")), existing)

    def test_unsafe_network_modes_rejected(self):
        for bad in ("host;evil", "a b", "net,other", "--privileged"):
            result = self.launch_without_run("--docker-network", bad)
            self.assertNotEqual(result.returncode, 0)

    def test_host_network_skips_host_sysctl_overrides(self):
        args = self.run_args(
            "--docker-network", "host", env_extra={"TEST_NETWORK_DRIVER": "host"}
        )
        self.assertEqual(args[args.index("--network") + 1], "host")
        self.assertNotIn("--sysctl", args)

    def test_no_network_keeps_main_launcher_behavior(self):
        args = self.run_args("--no-network")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--dns") + 1], "1.1.1.1")

    def test_config_rw_grants_writable_config_and_overlap_is_rejected(self):
        args = self.run_args("--config-rw")
        config = next(
            m for m in self.mounts(args) if "dst=/root/.config/opencode," in m
        )
        self.assertNotIn("readonly", config)
        self.assertIn(",rw,", config)
        state = next(
            m for m in self.mounts(args) if "dst=/root/.local/share/opencode," in m
        )
        self.assertNotIn("readonly", state)
        for overlap in (str(self.project), str(self.project / "sub"), str(self.base)):
            (self.project / "sub").mkdir(exist_ok=True)
            result = self.launch_without_run(env_extra={"OPENCODE_CONFIG_DIR": overlap})
            self.assertNotEqual(result.returncode, 0, overlap)
        link = self.base / "config-link"
        link.symlink_to(self.project)
        result = self.launch_without_run(
            env_extra={"OPENCODE_CONFIG_DIR": str(link)}
        )
        self.assertNotEqual(result.returncode, 0)

    def test_image_and_gvisor_validation(self):
        self.assertNotEqual(
            self.launch(env_extra={"OPENCODE_IMAGE": "--privileged"}).returncode, 0
        )
        self.assertNotEqual(
            self.launch(env_extra={"OPENCODE_GVISOR": "yes"}).returncode, 0
        )

    def test_symlinked_state_and_ipc_files_rejected(self):
        target = self.base / "real-state"
        target.mkdir()
        (self.project / ".opencode-sandbox").rmdir()
        (self.project / ".opencode-sandbox").symlink_to(target)
        self.assertNotEqual(self.launch_without_run().returncode, 0)
        (self.project / ".opencode-sandbox").unlink()
        (self.project / ".opencode-sandbox").mkdir(mode=0o700)

        sock = self.project / "agent.sock"
        server = socket.socket(socket.AF_UNIX)
        try:
            server.bind(str(sock))
            self.assertNotEqual(self.launch_without_run().returncode, 0)
        finally:
            server.close()
            sock.unlink()

        fifo = self.project / "pipe"
        os.mkfifo(fifo)
        try:
            self.assertNotEqual(self.launch_without_run().returncode, 0)
        finally:
            fifo.unlink()

    def test_launcher_inside_project_rejected(self):
        in_project = self.project / "opencode-sandbox"
        shutil.copy(ROOT / "opencode-sandbox", in_project)
        result = subprocess.run(
            ["bash", str(in_project)],
            cwd=self.project,
            env=self.env,
            input="y\n",
            text=True,
            capture_output=True,
            timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the writable project", result.stdout + result.stderr)

    def test_dns_flag_is_forwarded_to_runtime(self):
        args = self.run_args(
            "--docker-network", "somenet", env_extra={"TEST_NETWORK_DRIVER": "userbr"}
        )
        self.assertEqual(args[args.index("--dns") + 1], "1.1.1.1")
        args = self.run_args(env_extra={"OPENCODE_DNS": "9.9.9.9"})
        self.assertEqual(args[args.index("--dns") + 1], "9.9.9.9")

    def test_cpu_and_memory_limits_remain_configurable(self):
        args = self.run_args()
        self.assertEqual(args[args.index("--cpuset-cpus") + 1], "0-1")
        self.assertEqual(args[args.index("--cpuset-mems") + 1], "0")
        args = self.run_args(
            env_extra={
                "OPENCODE_MEMORY": "8g",
                "OPENCODE_GUARD_MEMORY": "1g",
                "OPENCODE_CPUS": "4",
            }
        )
        self.assertEqual(args[args.index("--memory") + 1], "8g")
        self.assertEqual(args[args.index("--memory-swap") + 1], "8g")
        envs = [args[i + 1] for i, arg in enumerate(args) if arg == "--env"]
        self.assertIn("OPENCODE_GUARD_MEMORY=8g", envs)
        self.assertNotIn("OPENCODE_GUARD_MEMORY=1g", envs)
        self.assertEqual(args[args.index("--cpus") + 1], "4")
        self.assertEqual(args[args.index("--cpuset-cpus") + 1], "0-3")
        args = self.run_args(env_extra={"OPENCODE_CPUS": "1.5"})
        self.assertEqual(args[args.index("--cpuset-cpus") + 1], "0-1")
        args = self.run_args(env_extra={"OPENCODE_CPUS": "1"})
        self.assertEqual(args[args.index("--cpuset-cpus") + 1], "0-0")
        self.assertNotEqual(
            self.launch(env_extra={"OPENCODE_MEMORY": "plenty"}).returncode, 0
        )


if __name__ == "__main__":
    unittest.main()
