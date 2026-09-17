# OpenCode Sandbox

[![CI](https://github.com/Antiquete/opencode-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Antiquete/opencode-sandbox/actions/workflows/ci.yml)

<p align="center">
  <img src="icon.svg" alt="OpenCode Sandbox" width="128">
</p>

Worried about letting an agentic AI run rampant on your system, wreak havoc,
or steal your files? Worry not! The opencode-sandbox is here!

Let any agentic AI run wild, do anything, install packages, mess with the system, anything, everything. Whatever it does stays inside the sandbox.

All containers share config. No need to redo preferences, agents, skills, mcps, anything!

Session remains preserved, start where you left off. Only the container resets, not opencode data.

## Requirements

- **docker** CLI and a running Docker daemon

## Installing

### AUR (Arch)

```sh
yay -S opencode-sandbox-git
```

### Direct install

```sh
# Debian / Ubuntu
sudo apt install ./opencode-sandbox_*_all.deb
# Fedora
sudo dnf install ./opencode-sandbox-*.noarch.rpm
# Arch
sudo pacman -U ./opencode-sandbox-*-any.pkg.tar.zst
# Gentoo
sudo emerge opencode-sandbox
```

### Manual

```sh
tar -xzf opencode-sandbox-*.tar.gz
cp opencode-sandbox-*/{opencode-sandbox,opencode-project-init} ~/.local/bin
```

## Usage

`opencode-project-init` - set up a project for sandboxing.
`opencode-sandbox` - start an isolated OpenCode session in the current project.

```sh
cd ~/code/myproject
opencode-project-init   # one time, creates the sandbox folder
opencode-sandbox        # opens the sandbox
opencode-sandbox --model some-model run "fix the typos in src/"
opencode-sandbox --continue
```

- The `.opencode-sandbox/` folder in your project holds the sandbox session data.
- Everything after the script name is passed through to OpenCode.

## Options

| Flag                      | Description                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--offline`               | Skip the image pull (`docker run --pull never`); use whatever image is already present. Useful on offline/unreliable networks.                                                                                                                                                                                                     |
| `--docker-network <name>` | Attach the container to a named Docker network (created automatically if it doesn't exist; requires permission to create networks). Defaults to Docker's default network. Useful for reaching a provider on another container (e.g. a local LLM server on `local-ai-net`), or `host` to reach services bound to the host's `localhost`. |
| anything else             | Forwarded to OpenCode, e.g. `--model`, `--continue`, `run`, `--help`.                                                                                                                                                                                                                                                              |

Example with a custom network:

```sh
# same network as a local Ollama/LM Studio container
opencode-sandbox --docker-network local-ai-net
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
