# OpenCode Sandbox

Run [OpenCode](https://opencode.ai) inside a locked-down Docker container so it
has access to only the current project - never your full home directory,
`~/.ssh`, other projects, or the Docker socket.

## Requirements

- **bash**
- **docker** CLI and a running Docker daemon
- an OpenCode image published as `ghcr.io/anomalyco/opencode:latest`
  (pulled on each run unless `--offline`)

The scripts check bash, the docker CLI, the daemon, and problem path characters
up front and print a clear message if something is missing.

## Setup

Initialize a project once before first use. Run this from the project directory:

```sh
opencode-project-init
```

This creates a `.opencode-sandbox/` directory in the project, where OpenCode's
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
| `--docker-network <name>` | Attach the container to a named Docker network (created automatically if it doesn't exist; requires permission to create networks). Defaults to Docker's default network. Useful for reaching a provider on another container (e.g. a local LLM server on `llm-net`), or `host` to reach services bound to the host's `localhost`. |
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
- interactive read/write access to the current project only
- state persisted under `<project>/.opencode-sandbox`, reachable inside the container
  only at its data path (`/root/.local/share/opencode`); it is masked out of the
  project tree so the agent can't poke at it as project content
- shared config at `~/.config/opencode` (read/write)

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).