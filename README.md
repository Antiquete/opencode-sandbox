# OPENCODE SANDBOX

[![CI](https://github.com/Antiquete/opencode-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Antiquete/opencode-sandbox/actions/workflows/ci.yml)

<p align="center">
  <img src="icon.svg" alt="OpenCode Sandbox" width="128">
</p>

Worried about letting an agentic AI run rampant on your system, wreak havoc,
or steal your files? Worry not! The opencode-sandbox is here!

Let any agentic AI run wild, do anything, install packages, mess with the system, anything, everything. Whatever it does stays inside the sandbox.

All containers share config. No need to redo preferences, agents, skills, mcps, anything!

Session remains preserved, start where you left off. Only the container resets, not opencode data.

## REQUIREMENTS

- **Docker/Podman:** Main container runtime
- **Bash:** Launcher shell
- **gVisor (optional):** Kernel separation (`runsc` registered with Docker)

#### Development Tools

- **cc:** Compile the seccomp guard
- **make:** Build the seccomp guard
- **python3:** Tests

## INSTALL

#### Arch AUR

```sh
# Source build
yay -S opencode-sandbox-git
# Prebuilt package
yay -S opencode-sandbox-bin
```

#### Packages

```sh
# Debian/Ubuntu
sudo apt install ./opencode-sandbox_*_amd64.deb
# Fedora
sudo dnf install ./opencode-sandbox-*.rpm
# Arch
sudo pacman -U ./opencode-sandbox-*-x86_64.pkg.tar.zst
# Gentoo
sudo emerge opencode-sandbox
```

#### Manual

```sh
tar -xzf opencode-sandbox-*.tar.gz
cd opencode-sandbox-*/
mkdir -p ~/.local/bin/build
cp opencode-sandbox opencode-project-init ~/.local/bin/
cp build/opencode-guard ~/.local/bin/build/
```

- **Guard lookup:** `build/opencode-guard` beside the launcher, then `/usr/lib/opencode-sandbox/guard`
- **Custom guard:** `--guard=PATH`

## USAGE

```sh
cd ~/code/myproject
opencode-project-init
opencode-sandbox
opencode-sandbox --opencode-model=some-model
```

- **Terminal:** Interactive session required

#### Options

| Option | Effect |
| --- | --- |
| `--edit-config` | Allow writes to shared host config<br>Default: Read-only |
| `--no-pull` | Use the cached image<br>Default: Pull always |
| `--no-network` | Request no network<br>Default: Runtime default |
| `--no-guard` | Disable the guard<br>Default: Guard enabled unless using gVisor |
| `--runtime=docker` / `--runtime=podman` | Select the runtime<br>Default: Automatic<br>↳ Rootless: Podman → Docker<br>↳ Rootful: Docker + gVisor → Podman → Docker |
| `--guard=PATH` | Select the guard; empty uses automatic discovery<br>Default: Automatic discovery |
| `--gvisor` | Require Docker's registered `runsc` runtime; skip the guard<br>Default: Used with rootful Docker + runsc |
| `--container-key=value` | Forward `--key=value` to the runtime |
| `--opencode-key=value` | Forward `--key=value` to OpenCode |

#### Notes

- **Unrecognized arguments:** Ignored by default. Use `--opencode-` or `--container-` to set options

  ```sh
  opencode-sandbox --model=provider/model          # Ignored
  opencode-sandbox --opencode-model=provider/model # Passed to OpenCode
  ```

- **Container options:** Can change the sandbox's protections without those changes appearing in the confirmation prompt

  ```sh
  # Gives the container more host access
  opencode-sandbox --container-privileged=true
  ```

- **Rootless gVisor:** Add `--gvisor` to use it with rootless Docker; it is not selected automatically.
  The tested `runsc` needs `--ignore-cgroups` to start rootlessly; with that setting the requested
  memory, CPU, and PID limits are **not enforced** (a warning is printed). Rootful gVisor applies those limits.

  ```sh
  opencode-sandbox --runtime=docker --gvisor
  ```

## DEFAULT SETTINGS

- Image: `ghcr.io/anomalyco/opencode:latest`
- Project: Current directory, read/write
- Session data: `.opencode-sandbox/`, mounted at `/root/.local/share/opencode`
- Config: `$HOME/.config/opencode`, read-only unless `--edit-config` is given
- Requested limits: `4g` RAM, 2 CPUs, 1024 processes
- DNS: `1.1.1.1`

```sh
opencode-sandbox --container-memory=8g --container-cpus=4
opencode-sandbox --container-network=local-ai-net --container-dns=9.9.9.9
```

#### Notes

- **Named networks:** Create the network before using it
- **Session directory:** New directories use mode `0700` so only your user can access them. Existing permissions and directory symlinks are kept
- **Config setup:** Missing `.gitignore` is created for read-only startup. Plugin installation may require `--edit-config`

## SANDBOX PROTECTION

The launcher restricts container privileges, separates IPC and cgroup namespaces,
disables core dumps, and hides hardware information under `/sys`.

The guard blocks sensitive system files and system calls. It reports sandbox
identity and memory values instead of the host's, while allowing basic file
information checks.

## SECURITY MATRIX — CONTAINERIZER COMPARISON

| Surface | Docker + guard | Podman + guard | Docker+gVisor(runsc) |
| --- | --- | --- | --- |
| `*` (container isolation) | Container isolation | Container isolation | Container isolation |
| `/sys/class/dmi/id`<br>Board serial, UUID, vendor | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/sys/bus/pci`<br>GPU and PCI hardware | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/sys/block`<br>Disk model, size, type | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/sys/devices/virtual/block`<br>Device-mapper and encrypted disk details | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/sys/bus/usb`, `/sys/bus/scsi`<br>USB and SCSI hardware | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/sys/module`, `/sys/kernel`, `/sys/power`, `/sys/fs/pstore`<br>Kernel modules, power and persistent crash metadata | Blocked (tmpfs) | Blocked (tmpfs) | Blocked (tmpfs) |
| `/proc/cmdline`<br>Kernel boot options | Denied (guard) | Blocked (mask) | Synthetic (runsc) |
| `/proc/self/mountinfo`<br>Mount layout | Denied (guard) | Denied (guard) | Synthetic (runsc) |
| `uname`<br>Kernel identity | Synthetic (guard) | Synthetic (guard) | Synthetic (runsc) |
| `/proc/version`<br>Kernel build information | Denied (guard) | Denied (guard) | Synthetic (runsc) |
| `/proc/sys/kernel/random/boot_id`<br>Host boot identifier | Denied (guard) | Denied (guard) | Synthetic (runsc) |
| `/proc/uptime`<br>System uptime | Denied (guard) | Denied (guard) | Synthetic (runsc) |
| `sysinfo`<br>Memory capacity and uptime | Synthetic (guard) | Synthetic (guard) | Partial (runsc)\* |
| `/proc/cpuinfo`<br>File access only, not direct CPU queries | Denied (guard) | Blocked (mask) | Partial (runsc)\* |
| `/proc/meminfo`<br>Host memory and swap | Denied (guard) | Blocked (mask) | Partial (runsc)\* |
| Direct CPU queries (`CPUID`, affinity)<br>CPU model, features, available CPUs | Exposed | Exposed | Exposed |

\* **gVisor notes (runsc, Systrap):**
- `/proc/cpuinfo`
  - **Visible:** `vendor_id`, `model`, `cpu MHz`, `flags` (partial), CPU count (rootless: `--ignore-cgroups`)
  - **Blocked(Synthetic):** `model name`, `stepping`
- `/proc/meminfo`
  - **Visible:** Host `MemTotal` (rootless: `--ignore-cgroups`)
  - **Blocked(Synthetic):** Host memory usage, host `SwapTotal`
- `sysinfo`
  - **Visible:** Host memory capacity (`MemTotal`), current host free RAM
  - **Blocked(Synthetic):** Uptime, swap, process count
- `/proc/sys/kernel/random/boot_id`
  - **Synthetic:** Fresh random value per sandbox; differs between runs and never matches the host

### Limitations

Container isolation is not hardware anonymity or a guarantee against escapes.

- **Shared files:** The agent can access the directory where you run the sandbox
  and its session data. Common OpenCode config is read-only unless you use `--edit-config`
- **Networking:** The network is reachable and your public IP is visible unless you use `--no-network`
- **Container options:** Direct `--container-` options can weaken or override sandbox protections

## DEVELOPMENT

- **Build:** `make` compiles the guard to `build/opencode-guard`
- **Tests:** `make test` builds the guard and runs the Python tests
- **Test coverage:** Launcher argument handling, guard behavior, project initialization and package contents
- **Package tests:** Missing package tools skip locally but are required in CI

Shell scripts use `shfmt`. Enable the formatting hook with:

```sh
git config core.hooksPath .githooks
```

## PLANNED FEATURES

- **Kata VM:** VM-backed container isolation

## LICENSE

GPL-3.0-or-later — see [LICENSE](LICENSE).
