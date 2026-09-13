# OpenCode Isolated Sandbox

Run [OpenCode](https://opencode.ai) inside a locked-down Docker container so it
has access to only the current project - never your full home directory,
`~/.ssh`, other projects, or the Docker socket.

## Requirements

- `bash`
- `docker`
- An OpenCode image published as `ghcr.io/anomalyco/opencode:latest`
  (pulled automatically on each run)

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