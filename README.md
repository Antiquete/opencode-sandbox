# OpenCode Isolated Sandbox

Run [OpenCode](https://opencode.ai) inside a locked-down Docker container so it
has access to only the current project - never your full home directory,
`~/.ssh`, other projects, or the Docker socket.

## Requirements

- **bash** — the scripts rely on bash features (arrays, `pipefail`, ANSI
  escapes). macOS and most Linux distros ship bash; on a minimal system
  install it (e.g. `apk add bash` on Alpine).
- **docker** CLI in your `PATH`.
- **A running Docker daemon** — the sandbox won't start without it.
- **POSIX userland tools** — `basename`, `tr`, `sed`, `cut`, `cksum`, `printf`,
  `mkdir`. These ship with every stock Linux/macOS install; no setup needed.
- **An OpenCode image** published as `ghcr.io/anomalyco/opencode:latest`
  (pulled on each run unless `--offline` is used).
- **Docker network permissions** (only when using `--docker-network` to create
  a missing network): the host user must be allowed to create Docker networks.

The script checks bash, the `docker` CLI, the daemon, and problem path
characters up front and prints a clear message if something is missing.

## Setup

Initialize a project once before first use. Run this from the project directory:

```sh
opencode-project-init
```

This creates a `.opencode/` directory in the project, where OpenCode's
persistent state is stored between sessions. It refuses to run in `$HOME` or `/`.

## Launching

From the same project directory:

```sh
opencode-sandbox
```

You'll see a summary of what OpenCode can and cannot access. Confirm with `y`
to start the container (interactive TTY).

Pass arguments straight through to OpenCode:

```sh
opencode-sandbox --model some-model run "fix the typos in src/"
opencode-sandbox --continue
```

Everything after the script name that isn't a script-level flag is forwarded to
OpenCode inside the container.

## Options

| Flag | Description |
| --- | --- |
| `--offline` | Skip the image pull (`docker run --pull never`); use whatever image is already present. Useful on offline/unreliable networks. |
| `--docker-network <name>` | Attach the container to a named Docker network (created automatically if it doesn't exist). Defaults to Docker's default network. Useful for reaching a provider on another container (e.g. a local LLM server on `llm-net`), or `host` to reach services bound to the host's `localhost`. |
| anything else | Forwarded to OpenCode, e.g. `--model`, `--continue`, `run`, `--help`. |

Example with a custom network:

```sh
# same network as a local Ollama/LM Studio container
opencode-sandbox --docker-network llm-net
```

## Security model

The container is launched with:

- all Linux capabilities dropped (`--cap-drop ALL`)
- privilege escalation blocked (`--security-opt no-new-privileges:true`)
- resource limits: 8 GB RAM, 4 CPUs, 512 processes
- interactive read/write access to the current project only
- state persisted under `<project>/.opencode`
- shared config at `~/.config/opencode` (read/write)

It does **not** receive `~/.ssh`, the Docker socket, or any other host paths.