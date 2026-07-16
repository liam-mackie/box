import Containerization
import ContainerizationOS
import Foundation

/// Boots a microVM from our image and runs a command inside it, reproducing the
/// old `container run` flags via the framework: all capabilities (for the
/// in-guest iptables firewall), our bind mounts, pinned DNS, and an interactive
/// TTY. The in-guest entrypoint still brings up squid + iptables and drops to
/// the non-root agent — unchanged.
enum Runner {
    static func runBox(
        command: [String], interactive: Bool,
        claudeRun: Bool = false
    ) async throws -> Int32 {
        try Assets.materialize()

        let cwd = FileManager.default.currentDirectoryPath
        let cwdURL = URL(fileURLWithPath: cwd)
        let id = "box-\(URL(fileURLWithPath: cwd).lastPathComponent)-\(getpid())"

        // Per-project trust gate (fail-closed): discover the nearest `.box/`,
        // hash its live components, and honor the project config layer ONLY when
        // its config component's hash matches an approved `box trust` record. The
        // allowlist component is gated separately (see `allowlistMounts`). With no
        // trusted project this resolves to global-only.
        let discovered = ProjectTrust.discover(cwd: cwdURL)
        let trust = ProjectTrust.evaluate(discovered)
        var cfg = Config.loadLayered(cwd: cwdURL, trustProjectConfig: trust.configTrusted).config
        // Even under a trusted config, reject any project `extraMounts` whose
        // symlink-resolved source escapes to a sensitive host path (~/.ssh etc.).
        cfg.extraMounts = filterSensitiveMounts(cfg.extraMounts)

        let command = effectiveCommand(
            command, claudeRun: claudeRun,
            skipPermissions: cfg.skipPermissions)

        let store = try ImageStore(path: Box.storeDir)
        // Launch-time claude-code sync (best-effort; see syncClaudeWithHost).
        if cfg.syncClaudeVersion {
            await ImageBridge.syncClaudeWithHost(store: store, toolchains: cfg.toolchains)
        }
        let image = try await ImageBridge.ensure(store: store, toolchains: cfg.toolchains)
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)

        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: try VmnetNetwork()
        )

        // Interactive terminal in raw mode, restored on exit.
        var term: Terminal?
        if interactive {
            let t = try Terminal.current
            try t.setraw()
            term = t
        }
        defer { term?.tryReset() }

        let entrypoint = "/usr/local/bin/entrypoint.sh"
        let dns = Box.dnsServers
        let logsDir = Box.logsDir.path
        let agentHome = Box.agentHome.path
        let configDir = Box.configDir.path

        // Resource limits, config-driven (with sensible defaults).
        let rootfsBytes = try Box.parseSize(cfg.rootfsSize)
        let memoryBytes = try Box.parseSize(cfg.memory)

        // All host→guest mounts, assembled from independently-owned helpers so each
        // capability (allowlist, ~/.claude, read-only roots, env file) lives in its
        // own function rather than inline here. The framework sorts mounts by
        // destination depth, so append order doesn't matter.
        // The project allowlist is honored only when its component is trusted
        // (gated separately from config). Pass its source path so `allowlistMounts`
        // can stage a snapshot of the trusted content.
        let trustedProjectAllowlist: String? =
            (trust.allowlistTrusted && discovered?.allowlistHash != nil)
            ? discovered?.allowlistURL.path : nil
        let mounts = buildMounts(
            cfg: cfg, cwd: cwd, agentHome: agentHome,
            configDir: configDir, logsDir: logsDir, id: id,
            projectAllowlist: trustedProjectAllowlist)

        let container = try await manager.create(
            id,
            image: image,
            rootfsSizeInBytes: rootfsBytes
        ) { config in
            // Full capabilities so the entrypoint can program iptables.
            config.process.capabilities = .allCapabilities
            // Always run via our entrypoint; image CMD is the default command.
            config.process.arguments = [entrypoint] + command
            // The workspace mounts at its REAL host path (not /workspace), so
            // paths inside the box match the host: Claude's per-project state,
            // trust records, and absolute paths in hook commands all line up.
            config.process.workingDirectory = cwd
            // Tell the guest its box id so the entrypoint tees squid's access log
            // into a per-box dir under /var/log/box (read by `box log --box <id>`).
            config.process.environmentVariables.append("BOX_ID=\(id)")
            // Claude Code behavior flags; the entrypoint's `gosu agent env …`
            // preserves its environment, so these reach the agent process.
            config.process.environmentVariables.append(contentsOf: guestEnv(cfg))
            // Forward the host's TERM (and COLORTERM) to the primary process so
            // Claude Code can negotiate the CSI-u extended-key protocol —
            // WITHOUT a real TERM the guest falls back to a degraded input mode
            // where Shift+Enter (newline) and Ctrl+L (clear) are dead. `box exec`
            // already forwards TERM per-connection (see ExecServer.startProcess);
            // the primary process inherited none, which is why those keys broke
            // only in the main box session and not in `box exec` or host claude.
            // The entrypoint's `gosu agent env …` preserves it to the agent.
            if interactive {
                config.process.environmentVariables.append(
                    "TERM=\(env("TERM") ?? "xterm-256color")")
                if let colorterm = env("COLORTERM") {
                    config.process.environmentVariables.append("COLORTERM=\(colorterm)")
                }
            }
            // Resource limits (config-driven).
            config.cpus = cfg.cpus
            config.memoryInBytes = memoryBytes
            // Override the vmnet-gateway DNS the framework sets by default.
            config.dns = DNS(nameservers: dns)
            config.mounts.append(contentsOf: mounts)
            if let term { config.process.setTerminalIO(terminal: term) }
        }

        RunState.add(id: id, cwd: cwd)
        // Host→guest clipboard image bridge; cancelled + cleaned in the defer.
        let clipboardTask = ClipboardSync.startPolling(cfg, id: id)
        defer {
            clipboardTask?.cancel()
            try? FileManager.default.removeItem(at: ClipboardSync.hostDir(forBoxID: id))
            RunState.remove(id: id)
            // Remove the per-box secrets directory (env file lives inside it) so no
            // secret lingers on disk after the run (no-op if absent).
            try? FileManager.default.removeItem(at: Box.secretDir(forBoxID: id))
            // Remove the per-run trusted-project-allowlist snapshot dir (no-op if absent).
            try? FileManager.default.removeItem(
                at: Box.runDir.appendingPathComponent("proj-allow-\(id)"))
            // Best-effort end-of-session egress summary from this box's log.
            if let summary = try? EgressLog.sessionSummaryLine(forBoxID: id) {
                FileHandle.standardError.write(Data((summary + "\n").utf8))
            }
            try? manager.delete(id)
        }

        // Graceful teardown on SIGTERM/SIGINT (daemonless companion to `box stop`).
        // Swift installs no signal handler, so by default these terminate the
        // process immediately — skipping the `defer` above and orphaning the VM +
        // marker. We install `DispatchSourceSignal`s instead: each fires its
        // handler (rather than the default disposition) when the signal arrives.
        // `DispatchSourceSignal` does NOT change the C-level disposition, so we
        // also `signal(_, SIG_IGN)` to suppress the default kill; the dispatch
        // source still observes the delivery. The handler stays thin — it just
        // kicks off the idempotent `container.stop()`, which tears the VM down so
        // the blocking `container.wait()` below returns and `runBox` unwinds
        // normally (running the `defer`). The trailing `container.stop()` is then
        // a no-op. `box stop --kill` (SIGKILL) is deliberately uncatchable: that
        // path leaves a stale marker for `box prune`/`box rm` to reap.
        let signalQueue = DispatchQueue(label: "box.signal")
        var signalSources: [DispatchSourceSignal] = []
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
            src.setEventHandler {
                // Restore the terminal eagerly so a stop mid-session doesn't leave
                // the host shell in raw mode (the `defer` also resets, belt-and-braces).
                term?.tryReset()
                Task { try? await container.stop() }
            }
            src.resume()
            signalSources.append(src)
        }
        defer { for src in signalSources { src.cancel() } }

        try await container.create()
        try await container.start()
        // Per-box exec control server, so `box exec`/`box shell` from another
        // terminal can open extra processes in THIS VM (daemonless attach).
        let execServer = ExecServer.start(container: container, cfg: cfg, cwd: cwd)
        defer { execServer?.stop() }

        // Terminal sizing. The one-shot resize seeds the guest pty with the
        // current size; the SIGWINCH source keeps it in sync afterward. Without
        // ongoing propagation the guest pty stays at its launch size, so shrinking
        // the host pane (window resize, tmux/zellij split) leaves Claude's TUI
        // drawing its prompt below the now-smaller viewport — the prompt appears
        // to vanish. `box exec`/`box shell` already do this (see BoxExec). SIGWINCH
        // defaults to ignore, so the SIG_IGN just mirrors the teardown sources
        // above; `resize` is async, so the thin handler hops onto a Task like they
        // do, and the source joins `signalSources` for cancellation on exit.
        if let term {
            try? await container.resize(to: try term.size)
            signal(SIGWINCH, SIG_IGN)
            let winch = DispatchSource.makeSignalSource(signal: SIGWINCH, queue: signalQueue)
            winch.setEventHandler {
                if let size = try? term.size {
                    Task { try? await container.resize(to: size) }
                }
            }
            winch.resume()
            signalSources.append(winch)
        }

        let status = try await container.wait()
        try await container.stop()
        return status.exitCode
    }

    /// The command actually run in the guest. For a plain `box run` (claudeRun)
    /// with `skipPermissions` on, `--dangerously-skip-permissions` is inserted
    /// right after `claude` — the microVM + egress allowlist is box's permission
    /// boundary, so per-tool prompts inside it add friction without isolation.
    /// The user's own args win: if they passed any permission-related flag
    /// (`--dangerously-skip-permissions` or `--permission-mode …`), nothing is
    /// added. Pure, so the insertion rule is unit-testable.
    static func effectiveCommand(
        _ command: [String], claudeRun: Bool, skipPermissions: Bool
    ) -> [String] {
        guard claudeRun, skipPermissions, command.first == "claude" else { return command }
        let hasPermissionFlag = command.contains {
            $0 == "--dangerously-skip-permissions" || $0 == "--permission-mode"
                || $0.hasPrefix("--permission-mode=")
        }
        guard !hasPermissionFlag else { return command }
        var out = command
        out.insert("--dangerously-skip-permissions", at: 1)
        return out
    }

    /// Claude Code behavior env for the guest.
    ///
    /// Always set: `DISABLE_AUTOUPDATER` — box itself keeps the image in
    /// lockstep with the host's claude (`syncClaudeVersion`) and the guest
    /// install isn't agent-writable, so the in-guest updater could only ever
    /// fail noisily — and `IS_SANDBOX=1`, which is simply true here (the
    /// microVM is the sandbox) and is Claude Code's own signal for
    /// sandboxed-environment behavior.
    ///
    /// Under `disableTelemetry`: `DISABLE_TELEMETRY` (Statsig),
    /// `DISABLE_ERROR_REPORTING` (Sentry), and the umbrella
    /// `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, which also suppresses
    /// version-check fetches and other nonessential egress.
    static func guestEnv(_ cfg: Config) -> [String] {
        var env = ["DISABLE_AUTOUPDATER=1", "IS_SANDBOX=1"]
        if cfg.disableTelemetry {
            env += [
                "DISABLE_TELEMETRY=1",
                "DISABLE_ERROR_REPORTING=1",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
            ]
        }
        return env
    }

    /// Assemble the full host→guest mount list. Each capability contributes via
    /// its own helper so features can be developed independently:
    ///  - base mounts (workspace, agent home, logs) are fixed here
    ///  - `allowlistMounts` exposes the egress allowlist (refined by per-project allowlists)
    ///  - `userMounts` handles ~/.claude + configured extraMounts
    ///  - `readOnlyRootMounts` handles broad read-only roots (e.g. ~/g)
    ///  - `envMounts` handles the per-run secret env file
    ///  - `caMounts` exposes the opt-in MITM CA (only when `tlsInspect` is set)
    static func buildMounts(
        cfg: Config, cwd: String, agentHome: String,
        configDir: String, logsDir: String, id: String,
        projectAllowlist: String? = nil
    ) -> [Containerization.Mount] {
        var m: [Containerization.Mount] = []
        // Workspace at its real host path — see the workingDirectory note above.
        m.append(.share(source: cwd, destination: cwd))
        m.append(.share(source: agentHome, destination: "/home/agent"))
        m += allowlistMounts(configDir: configDir, projectAllowlist: projectAllowlist, id: id)
        m.append(.share(source: logsDir, destination: "/var/log/box"))
        m += userMounts(cfg)
        m += hookMounts(cfg, cwd: cwd)
        m += readOnlyRootMounts(cfg)
        m += envMounts(cfg, id: id)
        m += caMounts(cfg, id: id)
        m += ClipboardSync.mounts(cfg, id: id)
        return m
    }

    /// Read-only mounts for host files referenced by hook commands in Claude
    /// settings (`mountHooks`, default on) — see `HookMounts` for the mapping
    /// rules and guardrails. Scans the settings the guest will actually honor:
    /// the project `.claude/settings(.local).json` (visible via the workspace
    /// mount) always, and the host `~/.claude/settings.json` only when
    /// `mountClaudeConfig` shares it into the guest.
    static func hookMounts(_ cfg: Config, cwd: String) -> [Containerization.Mount] {
        guard cfg.mountHooks else { return [] }
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        var settingsFiles = [
            URL(fileURLWithPath: cwd).appendingPathComponent(".claude/settings.json"),
            URL(fileURLWithPath: cwd).appendingPathComponent(".claude/settings.local.json"),
        ]
        if cfg.mountClaudeConfig {
            settingsFiles.append(
                URL(fileURLWithPath: home)
                    .appendingPathComponent(".claude/settings.json"))
        }

        var refs: [HookMounts.PathRef] = []
        for url in settingsFiles {
            guard let data = try? Data(contentsOf: url) else { continue }
            for command in HookMounts.hookCommands(inSettingsJSON: data) {
                refs += HookMounts.pathRefs(
                    inCommand: command, hostHome: home,
                    guestHome: "/home/agent")
            }
        }
        guard !refs.isEmpty else { return [] }

        let resolution = HookMounts.resolve(
            refs: refs, hostHome: home, guestHome: "/home/agent",
            mountClaudeConfig: cfg.mountClaudeConfig,
            // The workspace is mounted at its own host path, so absolute refs
            // inside the project need no extra mount.
            alreadyMounted: [Config.MountSpec(source: cwd, destination: cwd, readOnly: false)],
            exists: { fm.fileExists(atPath: $0) },
            isDirectory: {
                var isDir: ObjCBool = false
                return fm.fileExists(atPath: $0, isDirectory: &isDir) && isDir.boolValue
            },
            isSensitive: {
                let resolved = URL(fileURLWithPath: $0).resolvingSymlinksInPath().path
                return Trust.isSensitiveSource(resolved, home: home)
            })

        // Only the skips worth acting on get a warning; `missing` is normal
        // (guest-only paths in commands) and stays quiet.
        for s in resolution.skipped {
            switch s.reason {
            case .sensitive:
                FileHandle.standardError.write(
                    Data(
                        "box: not mounting hook path \(s.path): sensitive source\n".utf8))
            case .homeRoot:
                FileHandle.standardError.write(
                    Data(
                        ("box: not mounting hook path \(s.path): would expose the whole home "
                            + "directory (move the script into a subdirectory)\n").utf8))
            case .missing:
                break
            }
        }
        guard !resolution.specs.isEmpty else { return [] }
        FileHandle.standardError.write(
            Data(
                ("box: mounting hook paths (ro): "
                    + resolution.specs.map { "\($0.source) -> \($0.destination)" }
                    .joined(separator: ", ") + "\n").utf8))
        return resolution.specs.map {
            Containerization.Mount.share(
                source: $0.source, destination: $0.destination,
                options: ["ro"])
        }
    }

    /// Guest directory the trusted project allowlist snapshot is mounted at. The
    /// entrypoint reads `<this>/allowlist.project.txt` as squid's second ACL file.
    /// A dedicated hidden dir (not under the squid-scanned `/etc/box`) so we never
    /// expose anything but this single file.
    static let projectAllowlistMountDir = "/run/box-allowlist"
    /// Guest path of the project allowlist file the entrypoint renders into the ACL.
    static var projectAllowlistGuestPath: String {
        projectAllowlistMountDir + "/allowlist.project.txt"
    }

    /// Mounts exposing the egress allowlist. The GLOBAL config dir is always shared
    /// read-only at `/etc/box`, so `/etc/box/allowlist.txt` stays the global,
    /// live-editable file (`box allow`). When a project allowlist has been *trusted*
    /// (`projectAllowlist` is its host path), we additionally stage a snapshot of
    /// its trusted content into a dedicated per-run directory and mount that dir
    /// read-only at `projectAllowlistMountDir`, exposing exactly one file —
    /// `allowlist.project.txt` — to the guest. We mount a per-run *directory* (not
    /// the host file directly) because the framework shares a single-file source by
    /// exposing its *parent* dir; sharing the project's real `.box/` dir would leak
    /// `config.json` and any siblings. We snapshot rather than live-mount so the
    /// in-VM allowlist is exactly the trusted content — a mid-session host edit
    /// (which would invalidate the trust hash) cannot silently take effect.
    static func allowlistMounts(
        configDir: String,
        projectAllowlist: String? = nil,
        id: String = ""
    ) -> [Containerization.Mount] {
        var mounts: [Containerization.Mount] = [
            .share(source: configDir, destination: "/etc/box", options: ["ro"])
        ]
        guard let source = projectAllowlist else { return mounts }

        let fm = FileManager.default
        let dir = Box.runDir.appendingPathComponent("proj-allow-\(id)")
        let dst = dir.appendingPathComponent("allowlist.project.txt")
        do {
            try? fm.removeItem(at: dir)  // clear any stale dir from a crashed run
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let contents = (try? String(contentsOfFile: source, encoding: .utf8)) ?? ""
            try Data(contents.utf8).write(to: dst, options: [.atomic])
        } catch {
            let msg = "box: failed to stage trusted project allowlist: \(error); skipping\n"
            FileHandle.standardError.write(Data(msg.utf8))
            try? fm.removeItem(at: dir)
            return mounts
        }
        mounts.append(
            .share(source: dir.path, destination: projectAllowlistMountDir, options: ["ro"]))
        return mounts
    }

    /// Reject any `extraMounts` whose symlink-resolved source escapes to a sensitive
    /// host path (credentials, box's own state, system config). Applied even to a
    /// trusted project config, so trust can't be leveraged to mount `~/.ssh`.
    static func filterSensitiveMounts(_ mounts: [Config.ExtraMount]) -> [Config.ExtraMount] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return mounts.filter { m in
            let resolved = URL(fileURLWithPath: expandTilde(m.source))
                .resolvingSymlinksInPath().path
            if Trust.isSensitiveSource(resolved, home: home) {
                let msg =
                    "box: refusing extraMount \(m.source) -> \(m.destination): "
                    + "source resolves to a sensitive path (\(resolved))\n"
                FileHandle.standardError.write(Data(msg.utf8))
                return false
            }
            return true
        }
    }

    /// Hidden guest prefix the broad read-only roots are mounted under. The agent
    /// never sees these directly; its working view at `/mnt/<basename>` is built
    /// by root-owned bind-mounts of only the *allowed* subpaths of the matching
    /// `/mnt/.roots/<basename>` (see the entrypoint's fs-policy reconcile). We
    /// mount at this hidden source — rather than at `/mnt/<basename>` directly —
    /// so visibility can be carved live (`box fs-allow`/`fs-deny`) without a
    /// restart: the framework locks the *mount list* at boot, but root inside the
    /// guest can freely bind/unbind subpaths of an already-present mount.
    static let readOnlyRootsHiddenPrefix = "/mnt/.roots"

    /// Broad read-only roots (e.g. all of ~/g), each mounted READ-ONLY under the
    /// HIDDEN `/mnt/.roots/<basename>` so the agent can reference sibling repos
    /// without being able to tamper with them — and so their visibility can be
    /// toggled live. The pure `readOnlyRoots → specs` mapping (basename
    /// derivation, collision disambiguation, tilde expansion) lives on `Config`
    /// and still computes `/mnt/<basename>` destinations; this wrapper supplies
    /// the real-filesystem existence check, warns about missing sources, RELOCATES
    /// each destination under the hidden prefix, and turns each into a `["ro"]`
    /// virtiofs share. The entrypoint reconstructs `/mnt/<basename>` from these.
    static func readOnlyRootMounts(_ cfg: Config) -> [Containerization.Mount] {
        let result = cfg.readOnlyRootMounts {
            FileManager.default.fileExists(atPath: $0)
        }
        for source in result.skipped {
            FileHandle.standardError.write(
                Data("box: readOnlyRoots entry \(source) does not exist; skipping\n".utf8))
        }
        return result.specs.map {
            // `$0.destination` is `/mnt/<basename>` (incl. `-2`/`-3` collision
            // suffixes); relocate it under the hidden prefix → `/mnt/.roots/<…>`.
            let hidden = Runner.hiddenRootDestination(forVisible: $0.destination)
            return Containerization.Mount.share(
                source: $0.source, destination: hidden,
                options: ["ro"])
        }
    }

    /// Map a visible `/mnt/<basename>` destination (as produced by the pure
    /// `Config.readOnlyRootMounts`, including collision suffixes) to its hidden
    /// counterpart `/mnt/.roots/<basename>`. Anything not under `/mnt/` is left
    /// alone (defensive; shouldn't occur).
    static func hiddenRootDestination(forVisible destination: String) -> String {
        let mntPrefix = "/mnt/"
        guard destination.hasPrefix(mntPrefix) else { return destination }
        return readOnlyRootsHiddenPrefix + "/" + String(destination.dropFirst(mntPrefix.count))
    }

    /// Guest path the per-box secrets directory is mounted at. The entrypoint
    /// sources `<this>/env` just before dropping to the agent.
    static let secretMountDir = "/run/box-secrets"

    /// Per-run secret env file mount. Merges `cfg.env` (higher precedence) over the
    /// parsed `cfg.envFile` (dotenv), writes the result as `KEY=VALUE` lines to a
    /// `0600` file inside a DEDICATED per-box directory, and mounts that directory
    /// read-only. We mount the directory (not the file) because the framework
    /// shares a single-file source by exposing its *parent* dir — sharing the file
    /// directly would leak every sibling in `run/` (other boxes' markers / env
    /// files). The dedicated dir holds only this box's `env`, so nothing else is
    /// exposed. Returns `[]` (no mount) when the merged env is empty.
    static func envMounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        var dotenv: [String: String] = [:]
        if let path = cfg.envFile {
            if let text = try? String(contentsOfFile: expandTilde(path), encoding: .utf8) {
                dotenv = EnvInjection.parseDotenv(text)
            } else {
                FileHandle.standardError.write(
                    Data("box: envFile \(expandTilde(path)) is unreadable; skipping it\n".utf8))
            }
        }
        let merged = EnvInjection.mergedEnv(configEnv: cfg.env, dotenv: dotenv)
        guard !merged.isEmpty else { return [] }

        let dir = Box.secretDir(forBoxID: id)
        let file = Box.envFile(forBoxID: id)
        let fm = FileManager.default
        do {
            try? fm.removeItem(at: dir)  // clear any stale dir from a crashed run
            // Dir is 0700 (only the host user can list it); file is 0600.
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try Data(EnvInjection.serialize(merged).utf8).write(to: file, options: [.atomic])
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            FileHandle.standardError.write(
                Data("box: failed to stage env secrets: \(error); skipping env injection\n".utf8))
            try? fm.removeItem(at: dir)
            return []
        }
        // Log KEY NAMES only — never values — so a glance at stderr can't leak secrets.
        FileHandle.standardError.write(
            Data("box: injecting env keys: \(merged.keys.sorted().joined(separator: ", "))\n".utf8))
        return [.share(source: dir.path, destination: secretMountDir, options: ["ro"])]
    }

    /// Guest path the opt-in MITM CA directory is mounted at (read-only). The
    /// entrypoint reads `ca.crt`/`ca.key`/`bump-hosts.txt` from here; their
    /// presence is the signal to turn on bumping (absence ⇒ SNI splice only).
    static let caMountDir = "/run/box-ca"

    /// Host paths of the CA material `box ca init` writes into `Box.caDir`.
    static var caCertURL: URL { Box.caDir.appendingPathComponent("ca.crt") }
    static var caKeyURL: URL { Box.caDir.appendingPathComponent("ca.key") }

    /// The hosts that will ACTUALLY be MITM-bumped, given the requested list.
    /// Pure (filesystem-free) so it's unit-testable. Trims/drops blanks and—
    /// critically—drops any host that matches the always-spliced safety set
    /// (Anthropic/Claude API, npm, git): bumping those would break the agent's own
    /// auth or cert-pinned clients, so we refuse even if a user lists them. The
    /// default (empty `bumpHosts`) yields `[]`, i.e. nothing is bumped.
    static func caBumpHosts(_ requested: [String]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        for raw in requested {
            let h = raw.trimmingCharacters(in: .whitespaces).lowercased()
            if h.isEmpty { continue }
            if isAlwaysSpliced(h) { continue }
            if seen.insert(h).inserted { out.append(h) }
        }
        return out
    }

    /// Hosts/domains we NEVER bump, even if explicitly requested — bumping them
    /// would break Claude Code's own auth (Anthropic/Claude API) or cert-pinned
    /// package/SCM clients (npm, git). Matches the host itself and any subdomain,
    /// and tolerates a user-supplied leading dot (".anthropic.com").
    static func isAlwaysSpliced(_ host: String) -> Bool {
        let h = host.hasPrefix(".") ? String(host.dropFirst()) : host
        let pinned = [
            "anthropic.com", "claude.ai", "claude.com",
            "npmjs.org", "npmjs.com",
            "github.com", "githubusercontent.com",
        ]
        return pinned.contains { h == $0 || h.hasSuffix("." + $0) }
    }

    /// Opt-in MITM CA mount. Returns no mount unless `tlsInspect` is set AND the
    /// `box ca init` material exists in `Box.caDir`. When enabled, stages a
    /// per-run directory holding a copy of `ca.crt`, `ca.key`, and a
    /// `bump-hosts.txt` (the filtered `bumpHosts`), and mounts that directory
    /// READ-ONLY at `caMountDir`. We stage a dedicated dir (not `Box.caDir`
    /// directly) for the same reason as the env/allowlist mounts — the framework
    /// shares a single file by exposing its parent, and we want to expose exactly
    /// these three files, nothing else. The CA key is sensitive but is a copy of a
    /// file already persistent in `Box.caDir`, so no NEW secret reaches disk; the
    /// guest entrypoint re-stages it `root:proxy 0640` so the agent can't read it.
    static func caMounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        guard cfg.tlsInspect else { return [] }
        let fm = FileManager.default
        guard fm.fileExists(atPath: caCertURL.path), fm.fileExists(atPath: caKeyURL.path) else {
            FileHandle.standardError.write(
                Data(
                    ("box: tlsInspect is set but no CA found in \(Box.caDir.path); "
                        + "run `box ca init` first. Continuing with SNI splice only.\n").utf8))
            return []
        }
        let dir = Box.runDir.appendingPathComponent("ca-\(id)", isDirectory: true)
        do {
            try? fm.removeItem(at: dir)  // clear any stale dir from a crashed run
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try fm.copyItem(at: caCertURL, to: dir.appendingPathComponent("ca.crt"))
            try fm.copyItem(at: caKeyURL, to: dir.appendingPathComponent("ca.key"))
            let bump = caBumpHosts(cfg.bumpHosts)
            let body = bump.isEmpty ? "" : bump.joined(separator: "\n") + "\n"
            try Data(body.utf8).write(
                to: dir.appendingPathComponent("bump-hosts.txt"), options: [.atomic])
        } catch {
            FileHandle.standardError.write(
                Data(
                    "box: failed to stage MITM CA: \(error); continuing with SNI splice only.\n"
                        .utf8))
            try? fm.removeItem(at: dir)
            return []
        }
        FileHandle.standardError.write(
            Data(
                ("box: TLS inspection ON — bumping: "
                    + (caBumpHosts(cfg.bumpHosts).isEmpty
                        ? "(none listed; splice-only)"
                        : caBumpHosts(cfg.bumpHosts).joined(separator: ", ")) + "\n").utf8))
        return [.share(source: dir.path, destination: caMountDir, options: ["ro"])]
    }

    /// Resolve config-driven mounts (host ~/.claude + extra mounts) to shares.
    private static func userMounts(_ config: Config) -> [Containerization.Mount] {
        let claudeDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude").path
        let exists = FileManager.default.fileExists(atPath: claudeDir)
        if config.mountClaudeConfig && !exists {
            FileHandle.standardError.write(
                Data("box: mountClaudeConfig is set but \(claudeDir) is missing; skipping\n".utf8))
        }
        return config.resolvedMounts(claudeDir: claudeDir, claudeExists: exists).map {
            Containerization.Mount.share(
                source: $0.source, destination: $0.destination,
                options: $0.readOnly ? ["ro"] : [])
        }
    }
}

/// Tracks running boxes via per-run marker files, so `ls` works without a daemon.
enum RunState {
    static func add(id: String, cwd: String) {
        try? Assets.materialize()
        try? Data(cwd.utf8).write(to: Box.runDir.appendingPathComponent(id))
    }

    static func remove(id: String) {
        try? FileManager.default.removeItem(at: Box.runDir.appendingPathComponent(id))
    }

    /// Returns live (id, cwd) pairs, pruning markers whose process is gone.
    static func list() -> [(id: String, cwd: String)] {
        let fm = FileManager.default
        let entries = (try? fm.contentsOfDirectory(atPath: Box.runDir.path)) ?? []
        var out: [(String, String)] = []
        for id in entries {
            // Only `box-<dir>-<pid>` marker FILES count: the run dir also holds
            // per-run staging directories (`secret-*`, `proj-allow-*`, `clip-*`)
            // and the exec control sockets (`exec-<pid>.sock`), none of which
            // are boxes.
            guard id.hasPrefix("box-") else { continue }
            let marker = Box.runDir.appendingPathComponent(id)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: marker.path, isDirectory: &isDir), !isDir.boolValue
            else { continue }
            let cwd = (try? String(contentsOf: marker, encoding: .utf8)) ?? ""
            if let pid = pid(fromID: id), kill(pid, 0) != 0 {
                try? fm.removeItem(at: marker)  // stale
                continue
            }
            out.append((id, cwd))
        }
        return out
    }

    /// Remove markers whose embedded process is dead (`kill(pid,0)` fails),
    /// returning the removed ids (sorted) so callers can report counts. Only
    /// real run markers are considered: the per-run staging *directories*
    /// (`secret-*`, `proj-allow-*`) are skipped, since their trailing field is
    /// the box pid rather than their own process. Idempotent.
    @discardableResult
    static func pruneStale() -> [String] {
        let fm = FileManager.default
        let entries = (try? fm.contentsOfDirectory(atPath: Box.runDir.path)) ?? []
        var removed: [String] = []
        for id in entries {
            guard id.hasPrefix("box-") else { continue }  // see list()
            let marker = Box.runDir.appendingPathComponent(id)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: marker.path, isDirectory: &isDir), !isDir.boolValue
            else { continue }
            guard let pid = pid(fromID: id) else { continue }
            if kill(pid, 0) != 0 {
                try? fm.removeItem(at: marker)
                removed.append(id)
            }
        }
        return removed.sorted()
    }

    /// Signal the box's launching process. The VM is a child of that process
    /// (no daemon), and `runBox` installs a SIGTERM/SIGINT handler that runs the
    /// graceful-teardown `defer` (RunState.remove + manager.delete). So a plain
    /// SIGTERM stops the box cleanly; `kill: true` sends SIGKILL instead (the
    /// process dies without teardown, leaving a stale marker that `prune`/`rm`
    /// later reaps). Returns false when the id has no parseable pid or the
    /// process is already gone — there is nothing to signal in either case.
    @discardableResult
    static func stop(id: String, kill killHard: Bool) -> Bool {
        guard let pid = pid(fromID: id) else { return false }
        guard kill(pid, 0) == 0 else { return false }  // already dead
        return kill(pid, killHard ? SIGKILL : SIGTERM) == 0
    }

    /// Extract the pid the launching `box` process embedded in the id
    /// (`box-<dir>-<pid>`). `internal` (not `private`) so lifecycle commands can
    /// resolve a box's pid; the dir component may itself contain `-`, so we take
    /// the trailing numeric field.
    static func pid(fromID id: String) -> pid_t? {
        guard let last = id.split(separator: "-").last, let n = Int32(last) else { return nil }
        return n
    }
}
