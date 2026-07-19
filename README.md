# box

Run Claude Code inside an Apple [Containerization](https://github.com/apple/containerization)
microVM with allowlist-only internet egress.

Each session is a separate Linux VM (its own kernel) on Virtualization.framework.
All outbound traffic is forced through **box-proxy**, a TLS-intercepting sidecar
that permits only an editable hostname allowlist, and Claude runs as a non-root
user that cannot flush the firewall or bypass the proxy. The proxy runs in a
daemon-owned sidecar shared across boxes — start it with `box system start`
(see below).

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
box system start # boot the daemon + shared egress sidecar (required, once per boot)
box build        # build the image (container build → OCI → framework store)
box login        # one-time OAuth login; persisted in ~/.box/agent-home
cd ~/your/project
box              # launch Claude scoped to this directory
```

The first launch seeds a starter config at `~/.config/box/config.json` with
`"mountClaudeConfig": "ro"`, so your `~/.claude` settings apply read-only inside
boxes. Edit or delete it freely — box never overwrites an existing config.

| Command | Does |
|---|---|
| `box` / `run` | Launch Claude Code in `$PWD` (with `--dangerously-skip-permissions` by default — the VM is the boundary; see `skipPermissions`). `--allow-local <port>` opens scoped egress to a Mac-local port (reachable in the box as `host.box:<port>`); `--devcontainer` builds the agent VM on the project's `.devcontainer` base for this run without trusting it (auto-enabled once trusted — see [Devcontainers](#devcontainers-and-toolchains)) |
| `box shell` | Bash shell inside the box — attaches to the box already running here, or boots one (`--new` forces a separate VM) |
| `box exec [--box <id>] [cmd…]` | Run a command (default: a shell) inside a RUNNING box — background servers, tails, etc. in the same microVM |
| `box login` | Run Claude's interactive login |
| `box allow <domain>…` | Add domain(s) to the allowlist (running boxes reload live) |
| `box denied` | Show recently blocked hosts and the session(s) that hit them |
| `box log [--follow] [--denied]` | Show or tail the egress audit log (allowed + denied requests) |
| `box ls` | List running boxes |
| `box stop <id>` / `box rm <id>` | Stop a running box gracefully / stop it and remove its state |
| `box prune` | Remove stale box markers; `--all` also wipes agent home, image store, logs |
| `box build [--no-cache]` | Build the image |
| `box update [--to <ver>]` | Rebuild with a newer Claude Code (default: latest) |
| `box trust [--show] [--allowlist-only]` / `box untrust` | Approve this project's `.box/` + devcontainer at their current content (or revoke) |
| `box config` | Show the resolved config, where each value came from, and the project's trust status |
| `box fs allow\|deny\|policy` | Show or hide subpaths of the broad read-only roots, live |
| `box secret …` | Declare credentials Claude can use but never see — box-proxy injects them into matching requests (header/cookie/query, scoped by host + path) so the agent never holds the value |
| `box net init` / `box net ip` | One-time (sudo): install `/etc/resolver/box` so `<box-id>.box` resolves on the Mac / print a box's guest IP |
| `box system start\|stop\|status` | Manage the daemon that owns the shared egress sidecar (required for `box run`) |
| `box doctor [--online]` | Diagnose the host setup and box readiness |
| `box completions [shell] [--install]` | Print (or install) shell completions for bash, zsh, or fish |
| `box version` / `box --version` | Show box, claude-code, containerization, vminit versions |

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

`box denied` aggregates the sidecar logs, so each blocked host shows the session
it was denied in: the box id (`box-<dir>-<pid>`) for a dedicated sidecar, or
`shared-proxy` for boxes on the shared one. A `-` session means the denial came
from an old log with no session attribution.

A leading dot (`.example.com`) matches the domain and all subdomains; a bare
`example.com` matches only that exact host.

### How live reload works

box-proxy is self-managing: it re-reads the host-mounted allowlists (every 2s, by
mtime/size) and applies changes in place. So `box allow` just edits
`~/.box/config/allowlist.txt` and every attached box picks it up live. (Polling,
not inotify — inotify doesn't cross virtiofs.)

## The box daemon (egress proxy)

box runs **all** egress through **box-proxy**, a TLS-intercepting forward proxy
(built on [hudsucker](https://github.com/omjadas/hudsucker)) — there is no in-VM
proxy and no co-located single-VM mode. Every `box run` is an agent VM whose
egress is iptables-locked to a box-proxy sidecar. By default that sidecar is
**shared**: one long-lived `box daemon` process owns a single sidecar VM that
every box uses.

For each request box-proxy does one of three things, from the allowlist that
applies to that box:

- **deny** — the host isn't allowed → a 403, before any upstream connection.
- **pass-through** — the host is allowed *and pinned* (the Anthropic/Claude API,
  npm, GitHub) → the TLS connection is tunneled untouched, so cert-pinned
  lifelines are never intercepted.
- **bump** — the host is allowed and not pinned → box-proxy decrypts it (with an
  auto-generated CA the guest trusts), injects any scoped `box secret`, logs the
  full URL, and re-encrypts upstream.

TLS interception is **on by default** — that's what lets `box secret` injection
work with no setup, and it verifies the real SNI/Host rather than trusting the
CONNECT authority.

**The daemon is a required service** (like `container system start`) — start it
explicitly:

```sh
box system start     # boot the daemon + shared box-proxy sidecar
box system status    # show the sidecar and attached boxes
box system stop       # tear it down (refused while boxes are attached; --force overrides)
```

`box run` errors with a `box system start` hint if the daemon is down — there is
**no auto-start and no fallback**.

- The daemon creates the vmnet network and boots the sidecar once, then leases
  each box an address on that network. Boxes connect to the sidecar's IP
  directly — Apple's vmnet lets guests on one network reach each other, so
  there's no host relay. Each box's egress firewall permits only the sidecar,
  so boxes can't reach each other.
- **Per-box egress is isolated on the shared sidecar.** Because boxes connect
  directly, box-proxy sees each box's real source IP and enforces a *per-source*
  allowlist: the daemon writes each box's trusted project allowlist into its own
  policy slot, and box-proxy grants that source its domains (plus the global
  allowlist) — never another box's. Changes reload live.
- If the daemon dies, attached boxes keep running but lose egress until
  restarted (their network vanished with it). A crashed daemon's stale sidecar
  is reclaimed automatically on the next `box system start`.
- **Dedicated sidecar (opt-in, or automatic).** Set `dedicatedProxy` in config to
  give a box its own sidecar VM instead of the shared one — stronger isolation,
  and it doesn't need the daemon. A box that **defines secrets** gets one
  automatically (the shared sidecar can't safely hold one box's secret values),
  as do devcontainer boxes.
- **Every sidecar writes an egress access log** under `~/.box/logs/`:
  `shared-proxy/access.log` for the shared sidecar, `<box-id>/access.log` for
  dedicated ones. `box log --follow` tails it live; `box denied` aggregates it.

> [!NOTE]
> box-proxy is compiled from an embedded Rust crate (`proxy/`) as part of `box
> build`. Injected secret values never appear in the access log (only the
> pre-injection URL), and the CA signing key never leaves the sidecar. The access
> logs are not yet rotated.

## Devcontainers and toolchains

box picks the agent image for you:

- **Toolchains.** With no `toolchains` key in config, box detects the project's
  language from markers in the current directory (`go.mod` → go, `Cargo.toml` →
  rust, `*.csproj`/`*.fsproj`/`global.json` → dotnet) and layers that SDK into
  the image, logging one line when it does. An explicit `toolchains` list wins
  outright; `"toolchains": []` disables detection. Detection can only pick from
  box's curated registry — a repo can never add its own egress domains this way.
- **Devcontainers.** If the project has a `.devcontainer` and you've run
  `box trust`, box builds the agent VM on that base automatically (with its own
  dedicated sidecar). Detected but untrusted → box says so once and uses the
  base image. `--devcontainer` builds on it for a single run without trust.
  Editing `devcontainer.json` re-blocks it until you re-trust — the hash gate
  exists because `postCreateCommand` runs at build time, outside box's egress
  allowlist. `box trust --allowlist-only` never approves a devcontainer.

## Shell completions

```sh
box completions            # print the script for your shell ($SHELL)
box completions zsh        # or bash, fish
box completions --install  # write it to the shell's completion dir instead
```

`--install` writes `~/.zfunc/_box` (zsh — with an fpath hint if your `.zshrc`
needs one), `~/.local/share/bash-completion/completions/box`, or
`~/.config/fish/completions/box.fish`. `make completions` still generates all
three into `completions/`.

## Configuration (`~/.config/box/config.json`)

Optional. Honors `XDG_CONFIG_HOME`; a missing file or missing keys fall back to
defaults. `box config` prints the resolved values.

```json
{
  "mountClaudeConfig": "ro",
  "extraMounts": [
    { "source": "~/notes", "destination": "/opt/notes", "readOnly": true }
  ]
}
```

| Key | Default | Effect |
|---|---|---|
| `mountClaudeConfig` | `"off"` | `"off"` \| `"ro"` \| `"rw"` — mount the host `~/.claude` at `/home/agent/.claude` (read-only or writable), so your settings, `CLAUDE.md`, commands, agents, etc. apply inside the box. The code default is `off`, but the seeded starter config sets `ro`. Host `hooks` and `statusLine` are automatically disabled **inside the box** (via a guest-only Claude managed-settings file): they invoke host binaries/paths absent from the Linux VM, so they'd only fail. Pure JSON config (model, theme, permissions, …) applies normally. |
| `toolchains` | *(detect)* | Override toolchain auto-detection (`"dotnet"`, `"go"`, `"rust"`). Key absent → detect from project markers; explicit list wins; `[]` disables. |
| `syncClaudeVersion` | `true` | At launch, compare the image's baked claude-code to the host's `claude --version` and, when the image is older, rebuild the Claude layer pinned to the host version before booting. Any failure warns and runs the existing image. |
| `skipPermissions` | `true` | Launch claude with `--dangerously-skip-permissions`. The microVM + egress allowlist is box's permission boundary, so per-tool prompts inside it add friction without isolation. Your own permission flags always win; `box login` is unaffected. |
| `disableTelemetry` | `true` | Set `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` in the guest (Statsig, Sentry, version-check fetches). The in-guest auto-updater is disabled regardless — box manages the version. |
| `clipboardSync` | `true` | Mirror the host clipboard's IMAGE content into the box while it runs, so pasting an image into Claude works (a guest `xclip` shim serves it). Images only — clipboard text is never synced. |
| `dedicatedProxy` | `false` | Give this box its OWN box-proxy egress sidecar VM instead of sharing the daemon-owned one — stronger isolation, higher cost, and it doesn't need `box system start`. Default false: boxes share one sidecar (see [The box daemon](#the-box-daemon-egress-proxy)). A box that defines secrets gets a dedicated sidecar automatically. |
| `extraMounts` | `[]` | Extra host dirs to expose (`source` supports `~`; `readOnly` optional). |
| `readOnlyRoots` | `[]` | Host dirs exposed read-only under `/mnt/<basename>`; carve visibility live with `box fs allow`/`deny`. |
| `env` / `envFile` | `{}` / — | Env vars (or a dotenv file; `env` wins) injected into the agent process at launch. |
| `cpus` / `memory` / `rootfsSize` | `4` / `"4g"` / `"8g"` | VM sizing. |

> [!WARNING]
> Mounting `~/.claude` **writable** (`"rw"`) lets the sandboxed agent modify
> your real Claude config, including writing hooks into `settings.json` that
> execute on the **host** later. That is a path out of the sandbox — prefer
> `"ro"` (what the starter config seeds). Read-only means Claude can't persist
> session state back to `~/.claude`; with `"rw"`, the box's login also persists
> into `~/.claude` rather than the isolated `~/.box/agent-home`.
>
> `~/.claude.json` is **not** mounted automatically: it lives at your home root,
> and a single-file mount would share all of `$HOME` into the VM. Stage it into
> a dedicated directory and use `extraMounts` if you need it. Likewise, an
> `extraMounts` entry pointing at a *file* exposes that file's parent directory
> to the VM, so prefer mounting directories.

## Architecture

```
Sources/box/
  BoxCommand.swift     CLI (argument-parser); delegates to BoxKit.Commands
Sources/BoxKit/        library (logic; importable by tests)
  Commands.swift       public facade behind each subcommand
  Runner.swift         boots the VM via ContainerManager; mounts, caps, DNS, TTY
  ImageBridge.swift    container build → OCI → ImageStore.load (docker fallback);
                       launch-time claude-code version sync
  ManagedSettings.swift guest-only managed-settings.json (disables host hooks/statusline)
  Daemon.swift         `box system`: owns the shared box-proxy sidecar + vmnet network,
                       leases addresses to boxes over a unix socket (required service)
  DaemonClient.swift   client side of the daemon protocol (lease/release/status/stop/start)
  SharedVmnet.swift    cross-process vmnet network sharing (create/serialize/rehydrate)
  BoxNet.swift         `<box-id>.box` name resolution (net sidecar + lazy DNS resolver)
  Devcontainer.swift   parse .devcontainer, compose the dev-VM image, autoDecision gate
  Toolchains.swift     curated toolchain registry (dotnet/go/rust) + project-marker detection
  Trust.swift          content-hash approval for project .box/ + devcontainer (fail-closed)
  FsPolicy.swift       dynamic read-only-root visibility rules (`box fs`)
  EgressLog.swift      pure egress access-log parser for `box log`/`denied`
  Diagnostics.swift    `box doctor` checks (pure probes over injectable seams)
  SecretStore.swift    secret requirements + value bindings (global/project registry)
  SecretInjection.swift secret validation/scoping + box-proxy secrets.json rendering
  ClipboardSync.swift  host clipboard image → per-run mount (paste-in-box)
  BoxExec.swift        exec-into-running-box control socket (server + client)
  Config.swift         layered config (global ⊕ project) + starter-config seeding
  Allowlist.swift      pure allowlist merge logic
  Assets.swift         materialize embedded assets into the box dir
  Environment.swift    paths, kernel discovery, subprocess helpers
  Version.swift        version reporting + image.json sidecar (`box version`/`update`)
  VersionStamp.swift   generated git-describe stamp — `make version-stamp`
  EmbeddedAssets.swift generated (base64 of assets/files/*) — `make gen-assets`
Tests/BoxKitTests/     Swift Testing suites over the pure cores above
proxy/                 box-proxy: the Rust/hudsucker MITM egress sidecar (embedded
                       into the image + compiled by the Dockerfile's build stage)
assets/files/
  Dockerfile           Rust build stage → Node + native Claude Code + box-proxy + iptables
  xclip-shim.sh        guest clipboard shim serving the host-synced image
  entrypoint.sh        role-aware: proxy (runs box-proxy) | client (agent, egress locked to the sidecar)
  allowlist.txt        default egress allowlist (seeded on first run)
  box-layers.dockerfile the devcontainer CLIENT layers (claude + agent user; no proxy)
```

### Design notes

- **Pre-v0.1.0 clean breaks.** Config keys and command names change without
  shims or aliases until v0.1.0. Stale values fail decode; the tolerant loader
  warns on stderr and falls back to defaults.
- **Starter config over opinionated defaults.** Code defaults stay conservative
  (`mountClaudeConfig: off`); the first `box`/`box shell`/`box login` seeds
  `~/.config/box/config.json` with `"mountClaudeConfig": "ro"` instead. Seeding
  never overwrites, and `box config` never seeds.
- **Toolchain detection is registry-bounded.** Markers map to ids in the curated
  `Toolchains.registry`, each with a fixed egress-domain set merged into the
  allowlist. Repo content can only *select* one of the known SDK sets — it can
  never inject its own domains or Dockerfile fragments.
- **Devcontainer trust gates a build, not a run.** `postCreateCommand` becomes
  build-time `RUN` layers during `container build`, which run *outside* box's
  egress allowlist — so auto-enabling requires an approved content-hash of
  `devcontainer.json` (fail-closed; any edit re-blocks). Detection alone never
  builds; `--devcontainer` is explicit per-run consent; `--allowlist-only`
  never approves it.

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
- Egress: in the agent VM iptables defaults to DROP with the only allowed route
  being the box-proxy sidecar's address, so the agent has no direct route out and
  must use the proxy, which enforces the hostname allowlist. Claude runs as a
  non-root user with no `NET_ADMIN`.
- box-proxy **decrypts allowlisted (non-pinned) hosts by default**, enforcing on
  the verified TLS SNI / Host rather than the CONNECT authority — so a spoofed
  CONNECT can't domain-front past a broad entry like `.github.com`. Pinned hosts
  (Anthropic/Claude API, npm, GitHub) are tunneled without interception, so a
  broad allowlist entry there is still a potential exfil path — keep it tight.
  The forging CA's signing key stays in the sidecar; the agent VM only trusts the
  public cert.
- DNS (port 53) egress is allowed for resolution; DNS-tunnel exfil is out of scope.
