# box

Run Claude Code inside an Apple [Containerization](https://github.com/apple/containerization)
microVM with allowlist-only internet egress.

Each session is a separate Linux VM (its own kernel) on Virtualization.framework.
All outbound traffic is forced through a Squid proxy that only permits an
editable hostname allowlist, and Claude runs as a non-root user that cannot
flush the firewall or bypass the proxy.

box is a Swift binary built directly on Apple's Containerization framework: it
boots and manages the VM itself rather than shelling out to the `container` CLI.
It embeds the container build context and a default allowlist (base64,
materialized to `~/.box` on first run).

## Requirements

- Apple silicon, macOS 26, and Xcode 26 (Containerization requires all three)
- The [`container`](https://github.com/apple/container) CLI — run `container system start`
  once to install the guest kernel (box reuses it); box also builds images with
  `container build` (docker is no longer required — it survives only as an
  automatic fallback if `container build` fails and docker happens to be installed)

## Install

```sh
git clone https://github.com/liammackie/box ~/g/box
cd ~/g/box
make install            # swift build -c release + codesign (virtualization entitlement)
```

> The binary is codesigned with the `com.apple.security.virtualization` entitlement
> (required for vmnet). Keep the repo **out of** `~/Documents` and `~/Desktop`: a
> macOS 26 vmnet bug fails network creation for binaries located there.

## Usage

```sh
box build        # build the image (container build → OCI → framework store)
box login        # one-time OAuth login; persisted in ~/.box/agent-home
cd ~/your/project
box              # launch Claude scoped to this directory
```

| Command | Does |
|---|---|
| `box` / `run` | Launch Claude Code in `$PWD` (with `--dangerously-skip-permissions` by default — the VM is the boundary; see `skipPermissions`) |
| `box shell` | Bash shell inside the box — attaches to the box already running here, or boots one (`--new` forces a separate VM) |
| `box exec [--box <id>] [cmd…]` | Run a command (default: a shell) inside a RUNNING box — background servers, tails, etc. in the same microVM |
| `box login` | Run Claude's interactive login |
| `box allow <domain>…` | Add domain(s) to the allowlist (running boxes reload live) |
| `box denied` | Show recently blocked hosts and the session(s) that hit them |
| `box build [--no-cache]` | Build the image |
| `box ls` | List running boxes |
| `box config` | Show the resolved config and its file path |
| `box version` / `box --version` | Show box, claude-code, containerization, vminit versions |
| `box update [--to <ver>]` | Rebuild with a newer Claude Code (default: latest) |

Claude Code is baked into the image at build time, so without intervention a box
would keep running whatever version the last build captured (the guest can't
self-update: the npm global dir is root-owned and egress is allowlisted). By
default box therefore compares the image's claude-code against the host's
`claude --version` at every launch and, when the image is older, rebuilds the
(fast, layer-cached) Claude layer pinned to the host version before booting.
Disable with `"syncClaudeVersion": false`.

## When something is blocked

The agent gets a 403 page naming the host. To allow it:

```sh
box allow registry.terraform.io     # effective immediately, no restart
box denied                           # see exactly what got blocked, and by which session
```

`box denied` aggregates the per-box logs, so each blocked host shows the box
id(s) (`box-<dir>-<pid>`) it was denied in. A `-` session means the denial came
from a box running an older image with no per-session log.

A leading dot (`.example.com`) matches the domain and all subdomains. Don't list
both `.example.com` and `example.com`. Squid rejects that as a conflict.

### How live reload works (no daemon)

Without the `container` apiserver there's no daemon to exec into a running box,
so the guest is self-managing: the entrypoint polls the host-mounted
allowlist (every 2s, by checksum) and runs `squid -k reconfigure` when it
changes. So `box allow` just edits `~/.box/config/allowlist.txt` and every
running box picks it up live. The squid access log is written to a host-mounted
dir so `box denied` can read it from the Mac side.

## Shell completions

box ships completion scripts for bash, zsh, and fish via ArgumentParser. Emit one
on demand:

```sh
box --generate-completion-script zsh    # or bash, fish
```

Or generate all three into `completions/` with `make completions`, then install
the one for your shell, e.g.:

```sh
make completions
# zsh: drop _box on your fpath
cp completions/_box "${fpath[1]}/_box"
# bash:
source completions/box.bash
# fish:
cp completions/box.fish ~/.config/fish/completions/box.fish
```

## Configuration (`~/.config/box/config.json`)

Optional. Honors `XDG_CONFIG_HOME`; a missing file or missing keys fall back to
defaults. `box config` prints the resolved values.

```json
{
  "mountClaudeConfig": true,
  "claudeConfigReadOnly": false,
  "extraMounts": [
    { "source": "~/notes", "destination": "/opt/notes", "readOnly": true }
  ]
}
```

| Key | Default | Effect |
|---|---|---|
| `mountClaudeConfig` | `false` | Mount the host `~/.claude` directory at `/home/agent/.claude`, so your settings, `CLAUDE.md`, commands, agents, etc. apply inside the box. |
| `claudeConfigReadOnly` | `false` | Mount `~/.claude` read-only. |
| `mountHooks` | `true` | Mount (read-only) the host files that hook commands in Claude settings reference, so host-configured hooks also run inside the box. `~/…` and `$HOME/…` references appear under the guest home; absolute paths under your home appear at the same path. Only paths under your home are mirrored, sensitive dirs (`~/.ssh` etc.) are refused, and `$CLAUDE_PROJECT_DIR/…` needs no mount (the workspace is already there). |
| `syncClaudeVersion` | `true` | At launch, compare the image's baked claude-code to the host's `claude --version` and, when the image is older, rebuild the Claude layer pinned to the host version before booting. Any failure warns and runs the existing image. |
| `skipPermissions` | `true` | Launch claude with `--dangerously-skip-permissions`. The microVM + egress allowlist is box's permission boundary, so per-tool prompts inside it add friction without isolation. Your own permission flags always win; `box login` is unaffected. |
| `disableTelemetry` | `true` | Set `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` in the guest (Statsig, Sentry, version-check fetches). The in-guest auto-updater is disabled regardless — box manages the version. |
| `clipboardSync` | `true` | Mirror the host clipboard's IMAGE content into the box while it runs, so pasting an image into Claude works (a guest `xclip` shim serves it). Images only — clipboard text is never synced. |
| `extraMounts` | `[]` | Extra host dirs to expose (`source` supports `~`; `readOnly` optional). |

> [!WARNING]
> Mounting `~/.claude` **read-write** (the default when enabled) lets the
> sandboxed agent modify your real Claude config, including writing hooks into
> `settings.json` that execute on the **host** later. That is a path out of the
> sandbox. Set `claudeConfigReadOnly: true` if that matters to you (Claude then
> can't persist session state back to `~/.claude`). With `mountClaudeConfig`
> enabled, the box's login also persists into `~/.claude` rather than the
> isolated `~/.box/agent-home`.
>
> `~/.claude.json` is **not** mounted automatically: it lives at your home root,
> and a single-file mount would share all of `$HOME` into the VM. Stage it into
> a dedicated directory and use `extraMounts` if you need it. Likewise, an
> `extraMounts` entry pointing at a *file* exposes that file's parent directory
> to the VM, so prefer mounting directories.
>
> `mountHooks` mounts the *parent directory* of each referenced hook script,
> read-only. Because hook commands live in settings files the agent can edit
> (the project `.claude/settings.json` in the workspace, and `~/.claude` when mounted), a
> compromised agent could name host paths to have them mounted on the *next*
> launch. That's why hook mounts are always read-only, restricted to your home
> directory, refused for sensitive dirs, and announced on stderr at launch.

## Architecture

```
Sources/box/
  BoxCommand.swift     CLI (argument-parser); delegates to BoxKit.Commands
Sources/BoxKit/        library (logic; importable by tests)
  Commands.swift       public facade behind each subcommand
  Runner.swift         boots the VM via ContainerManager; mounts, caps, DNS, TTY
  ImageBridge.swift    container build → OCI → ImageStore.load (docker fallback);
                       launch-time claude-code version sync
  HookMounts.swift     hook-command path extraction → read-only mounts
  ClipboardSync.swift  host clipboard image → per-run mount (paste-in-box)
  BoxExec.swift        exec-into-running-box control socket (server + client)
  Config.swift         ~/.config/box/config.json (mounts, options)
  Allowlist.swift      pure allowlist merge logic
  Assets.swift         materialize embedded assets into the box dir
  Environment.swift    paths, kernel discovery, subprocess helpers
  Version.swift        version reporting + image.json sidecar (`box version`/`update`)
  VersionStamp.swift   generated git-describe stamp — `make version-stamp`
  EmbeddedAssets.swift generated (base64 of assets/files/*) — `make gen-assets`
Tests/BoxKitTests/     Swift Testing: Allowlist, Assets, Config, Version
assets/files/
  Dockerfile           Node + native Claude Code + Squid + iptables; non-root agent (uid 501)
  xclip-shim.sh        guest clipboard shim serving the host-synced image
  squid.conf           proxy config: hostname allowlist + custom deny page
  deny.html            the "blocked, here's the fix" 403 page
  entrypoint.sh        start squid, lock iptables, poll allowlist, drop to agent
  allowlist.txt        default egress allowlist (seeded on first run)
```

Mapping to the framework (replacing the old `container run` flags):

| Need | Framework API |
|---|---|
| run image | `ContainerManager.create(id, image:, …)` |
| `NET_ADMIN` for iptables | `config.process.capabilities = .allCapabilities` |
| bind mounts | `config.mounts.append(.share(source:destination:options:))` |
| pin DNS | `config.dns = DNS(nameservers:)` (overrides the vmnet gateway default) |
| interactive TTY | `config.process.setTerminalIO(terminal:)` + `container.resize` |
| guest kernel | reused from `~/Library/Application Support/com.apple.container/kernels` |
| guest init | `vminit` pulled once (`BOX_VMINIT` to override) |

## Environment

- `BOX_DIR` — box/runtime dir (default `~/.box`)
- `BOX_DNS` — resolvers (default `1.1.1.1 1.0.0.1`; vmnet gateway DNS is unreliable here)
- `BOX_KERNEL` — explicit kernel path (default: the `container`-installed kernel)
- `BOX_VMINIT` — vminit image reference

## Security model

- The microVM is the isolation boundary; the agent sees only the workspace
  (the current directory, mounted at its REAL host path so guest paths match
  host paths) and the persisted agent home.
- `box exec` sessions run as the agent with EMPTY capabilities and
  no_new_privileges (strictly weaker than the entrypoint), so an attached
  shell can't touch iptables or widen the boundary.
- Egress: iptables defaults to DROP; only Squid's uid may leave the VM, so the
  agent has no direct route out and must use the proxy, which enforces the
  hostname allowlist. Claude runs as a non-root user with no `NET_ADMIN`.
- Squid filters by hostname **without TLS interception**, so a broad entry like
  `.github.com` is a potential exfiltration path; keep the allowlist tight.
- DNS (port 53) egress is allowed for resolution; DNS-tunnel exfil is out of scope.
