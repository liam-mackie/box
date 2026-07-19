import Containerization
import ContainerizationOS
import Foundation

enum Runner {
    static func runBox(
        command: [String], interactive: Bool,
        claudeRun: Bool = false, allowLocal: [String] = [], devcontainer: Bool = false
    ) async throws -> Int32 {
        try Assets.materialize()

        let cwd = FileManager.default.currentDirectoryPath
        let cwdURL = URL(fileURLWithPath: cwd)
        let id = "box-\(cwdURL.lastPathComponent)-\(getpid())"
        let proxyId = "\(id)-proxy"

        let discovered = ProjectTrust.discover(cwd: cwdURL)
        let trust = ProjectTrust.evaluate(discovered)
        let merged = Config.loadLayered(cwd: cwdURL, trustProjectConfig: trust.configTrusted)
        var cfg = merged.config
        cfg.extraMounts = filterSensitiveMounts(cfg.extraMounts)

        let command = effectiveCommand(
            command, claudeRun: claudeRun,
            skipPermissions: cfg.skipPermissions)

        let trustedProjectAllowlist: String? =
            (trust.allowlistTrusted && discovered?.allowlistHash != nil)
            ? discovered?.allowlistURL.path : nil

        let secretPlan = computeSecretPlan(
            discovered: discovered, secretsTrusted: trust.secretsTrusted)
        if !secretPlan.unmet.isEmpty {
            log(
                "box: secrets need values: \(secretPlan.unmet.joined(separator: ", ")) "
                    + "— run `box secret setup` (the box runs without them for now).")
        }
        try Commands.ensureCA()

        let dcURL = discovered?.devcontainerURL
        let dcDecision = Devcontainer.autoDecision(
            flagged: devcontainer, detected: dcURL != nil,
            trusted: trust.devcontainerTrusted)

        let effectiveToolchains: [String]
        if dcDecision.usesDevcontainer {
            effectiveToolchains = cfg.toolchains
        } else {
            let detected = detectedToolchains(cwd: cwdURL)
            effectiveToolchains = Toolchains.effective(
                configured: cfg.toolchains, origin: merged.origins.toolchains, detected: detected)
            if merged.origins.toolchains == .default, !detected.isEmpty {
                log(
                    "box: detected toolchains from project markers: "
                        + "\(detected.joined(separator: ", ")) (set \"toolchains\": [] to disable)")
            }
        }

        let store = try ImageStore(path: Box.storeDir)
        if cfg.syncClaudeVersion {
            await ImageBridge.syncClaudeWithHost(store: store, toolchains: effectiveToolchains)
        }

        let image: Image
        var devcontainerClient = false
        if dcDecision.usesDevcontainer, let dcURL {
            let dcData = (try? Data(contentsOf: dcURL)) ?? Data()
            let spec = try Devcontainer.parse(dcData)
            image = try await ImageBridge.ensureDevcontainer(
                store: store, spec: spec, hashInputs: [dcData])
            devcontainerClient = true
        } else {
            switch dcDecision {
            case .baseWarnMissing:
                log("box: --devcontainer set but no .devcontainer found; using the base image")
            case .baseWithHint:
                log(
                    "box: .devcontainer found but not trusted — run 'box trust' to build on it, "
                        + "or pass --devcontainer for this run")
            default:
                break
            }
            image = try await ImageBridge.ensure(store: store, toolchains: effectiveToolchains)
        }
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)

        // Sidecar shape. DEFAULT is the shared daemon-owned Envoy sidecar (one
        // Envoy for all boxes, per-source isolation), which REQUIRES the daemon
        // to be running — like `container system start`, there is no auto-spawn
        // and no fallback: `lease` throws a `box system start` hint if it's down.
        // A box opts into a DEDICATED per-box sidecar with `dedicatedProxy`
        // (stronger isolation, no daemon needed); a devcontainer box always gets
        // one (its client image differs, so it can't be the shared sidecar).
        let wantDedicated =
            cfg.dedicatedProxy || devcontainerClient || !secretPlan.resolved.isEmpty
        var sharedLease: DaemonClient.Lease? = nil
        if !wantDedicated {
            let projectDomains = trustedProjectAllowlist.flatMap {
                try? String(contentsOfFile: $0, encoding: .utf8)
            }
            sharedLease = try DaemonClient.lease(
                boxID: id, projectAllowlist: projectDomains)
        }
        defer { if sharedLease != nil { DaemonClient.release(boxID: id) } }
        // Dedicated sidecar runs box's own image (Envoy). nil ⇒ shared.
        let proxyImage: Image? =
            wantDedicated ? try await ImageBridge.ensure(store: store) : nil

        let network: Network
        if let lease = sharedLease {
            network = try SharedVmnetNetwork(
                reference: SharedVmnet.network(fromToken: lease.token),
                ips: [lease.leaseIP])
        } else {
            network = try VmnetNetwork()
        }
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: network
        )

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

        let rootfsBytes = try Box.parseSize(cfg.rootfsSize)
        let memoryBytes = try Box.parseSize(cfg.memory)

        var clientEnv: [String] = []
        var proxyAddress: String? = nil
        var stopProxy: () async -> Void = {}
        if let proxyImage {
            let pMounts = proxyMounts(
                cfg: cfg, configDir: configDir, logsDir: logsDir, id: id,
                projectAllowlist: trustedProjectAllowlist, secretPlan: secretPlan)
            let proxy = try await manager.create(
                proxyId,
                image: proxyImage,
                rootfsSizeInBytes: rootfsBytes
            ) { config in
                config.process.capabilities = .allCapabilities
                config.process.arguments = [entrypoint, "sleep", "infinity"]
                config.process.environmentVariables.append("BOX_ROLE=proxy")
                config.process.environmentVariables.append("BOX_ID=\(id)")
                config.cpus = 1
                config.memoryInBytes = 1 << 30
                config.dns = DNS(nameservers: dns)
                config.mounts.append(contentsOf: pMounts)
            }
            try await proxy.create()
            try await proxy.start()
            stopProxy = { try? await proxy.stop() }
            guard let iface = proxy.interfaces.first else {
                await stopProxy()
                throw CBError("devcontainer proxy sidecar got no network interface")
            }
            // The dev VM dials the sidecar's vmnet IP DIRECTLY: guests on one
            // VmnetNetwork reach each other (verified — `box __netprobe`; the
            // old host relay was built on a firewall-confounded observation).
            // Cross-box isolation is unaffected: each `box run` creates its own
            // network, and only this run's two VMs are on it — which is also
            // why the sidecar's subnet-wide client gate stays sound.
            let address = "\(iface.ipv4Address.address):3128"
            proxyAddress = address
            clientEnv = ["BOX_ROLE=client", "BOX_PROXY_ADDR=\(address)"]
            log("box: dedicated egress sidecar (envoy) up at \(address)")
        }
        if let lease = sharedLease {
            // Daemon-owned sidecar: same client shape as split mode, but the
            // proxy VM belongs to `box daemon` and is shared across boxes.
            let address = "\(lease.sidecarIP):3128"
            proxyAddress = address
            clientEnv = ["BOX_ROLE=client", "BOX_PROXY_ADDR=\(address)"]
            log("box: attached to the shared proxy sidecar at \(address)")
        }

        // Every box is a client of its sidecar (shared or dedicated).
        let mounts: [Containerization.Mount] = clientMounts(
            cfg: cfg, cwd: cwd, agentHome: agentHome,
            configDir: configDir, id: id)

        let container = try await manager.create(
            id,
            image: image,
            rootfsSizeInBytes: rootfsBytes
        ) { config in
            config.process.capabilities = .allCapabilities
            config.process.arguments = [entrypoint] + command
            config.process.workingDirectory = cwd
            config.process.environmentVariables.append("BOX_ID=\(id)")
            config.process.environmentVariables.append(contentsOf: clientEnv)
            if !allowLocal.isEmpty {
                config.process.environmentVariables.append(
                    "BOX_LOCAL_EGRESS=\(allowLocal.joined(separator: ","))")
            }
            config.process.environmentVariables.append(contentsOf: guestEnv(cfg))
            if interactive {
                config.process.environmentVariables.append(
                    "TERM=\(env("TERM") ?? "xterm-256color")")
                if let colorterm = env("COLORTERM") {
                    config.process.environmentVariables.append("COLORTERM=\(colorterm)")
                }
            }
            config.cpus = cfg.cpus
            config.memoryInBytes = memoryBytes
            config.dns = DNS(nameservers: dns)
            config.mounts.append(contentsOf: mounts)
            if let term { config.process.setTerminalIO(terminal: term) }
        }

        RunState.add(id: id, cwd: cwd)
        let clipboardTask = ClipboardSync.startPolling(cfg, id: id)
        defer {
            clipboardTask?.cancel()
            BoxNet.remove(forBoxID: id)
            RunState.remove(id: id)
            for dir in [
                ClipboardSync.hostDir(forBoxID: id),
                ManagedSettings.hostDir(forBoxID: id),
                Box.secretDir(forBoxID: id),
                projectAllowlistStagingDir(id: id),
                caSidecarStagingDir(id: id),
                caCertStagingDir(id: id),
                injectStagingDir(id: id),
            ] {
                try? FileManager.default.removeItem(at: dir)
            }
            try? manager.delete(proxyId)
            if let summary = try? EgressLog.sessionSummaryLine(forBoxID: id) {
                log(summary)
            }
            try? manager.delete(id)
        }

        let signalQueue = DispatchQueue(label: "box.signal")
        var signalSources: [DispatchSourceSignal] = []
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
            src.setEventHandler {
                term?.tryReset()
                Task { try? await container.stop() }
            }
            src.resume()
            signalSources.append(src)
        }
        defer { for src in signalSources { src.cancel() } }

        try await container.create()
        try await container.start()
        if let iface = container.interfaces.first {
            let state = BoxNet.NetState(
                guestIP: "\(iface.ipv4Address.address)",
                gateway: iface.ipv4Gateway.map { "\($0)" })
            try? BoxNet.write(state, forBoxID: id)
            BoxNet.ensureResolver()
            if !BoxNet.resolverInstalled() {
                log("box: \(id).box will resolve after one-time setup — run: sudo box net init")
            }
        }

        let execProxyURL = proxyAddress.map { "http://\($0)" } ?? "http://127.0.0.1:3128"
        let execServer = ExecServer.start(
            container: container, cfg: cfg, cwd: cwd, proxyURL: execProxyURL)
        defer { execServer?.stop() }

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
        await stopProxy()
        return status.exitCode
    }

    static func detectedToolchains(cwd: URL) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: cwd.path)) ?? []
        return Toolchains.detected(fromFilenames: names)
    }

    struct SecretPlan {
        var resolved: [SecretInjection.Resolved] = []
        var unmet: [String] = []
        var bindings: [String: SecretSource] = [:]
    }

    static func resolveSecretValue(_ source: SecretSource) -> String? {
        switch source {
        case .env(let name):
            return env(name)
        case .keychain(let service, let account):
            guard
                let out = try? Sh.output([
                    "security", "find-generic-password", "-s", service, "-a", account, "-w",
                ])
            else { return nil }
            let trimmed = out.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
    }

    static func computeSecretPlan(
        discovered: ProjectTrust.Discovered?, secretsTrusted: Bool
    ) -> SecretPlan {
        let registry = SecretStore.load()
        var projectReqs: [SecretRequirement] = []
        if let d = discovered, secretsTrusted {
            projectReqs = SecretStore.loadProject(from: d.secretsURL).requirements
        }
        let effective = SecretInjection.effectiveRequirements(
            global: registry.requirements, project: projectReqs)
        var valid: [SecretRequirement] = []
        for req in effective {
            let errs = req.validationErrors(isPinned: isAlwaysSpliced)
            if errs.isEmpty {
                valid.append(req)
            } else {
                log("box: ignoring invalid secret \"\(req.name)\": \(errs.joined(separator: "; "))")
            }
        }
        let (resolved, unmet) = SecretInjection.partition(valid) { req in
            guard let src = registry.bindings[req.name] else { return nil }
            return resolveSecretValue(src)
        }
        return SecretPlan(resolved: resolved, unmet: unmet, bindings: registry.bindings)
    }

    static func isAlwaysSpliced(_ host: String) -> Bool {
        let h = host.hasPrefix(".") ? String(host.dropFirst()) : host
        let pinned = [
            "anthropic.com", "claude.ai", "claude.com",
            "npmjs.org", "npmjs.com",
            "github.com", "githubusercontent.com",
        ]
        return pinned.contains { h == $0 || h.hasSuffix("." + $0) }
    }

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

    static let caMountDir = "/run/box-ca"
    static let injectMountDir = "/run/box-inject"

    static func proxyMounts(
        cfg: Config, configDir: String, logsDir: String, id: String,
        projectAllowlist: String?, secretPlan: SecretPlan = SecretPlan()
    ) -> [Containerization.Mount] {
        var m: [Containerization.Mount] = []
        m += allowlistMounts(configDir: configDir, projectAllowlist: projectAllowlist, id: id)
        m.append(.share(source: logsDir, destination: "/var/log/box"))
        m += sidecarCAMounts(id: id)
        m += injectMounts(secretPlan, id: id)
        return m
    }

    static func clientMounts(
        cfg: Config, cwd: String, agentHome: String, configDir: String,
        id: String
    ) -> [Containerization.Mount] {
        var m: [Containerization.Mount] = []
        m.append(.share(source: cwd, destination: cwd))
        m.append(.share(source: agentHome, destination: "/home/agent"))
        m.append(.share(source: configDir, destination: "/etc/box", options: ["ro"]))
        m += userMounts(cfg)
        m += ManagedSettings.mounts(cfg, id: id)
        m += readOnlyRootMounts(cfg)
        m += envMounts(cfg, id: id)
        m += agentCACertMounts(id: id)
        m += ClipboardSync.mounts(cfg, id: id)
        return m
    }

    static func sidecarCAMounts(id: String) -> [Containerization.Mount] {
        let ca = Box.caDir
        let cert = ca.appendingPathComponent("ca.crt")
        let key = ca.appendingPathComponent("ca.key")
        let fm = FileManager.default
        guard fm.fileExists(atPath: cert.path), fm.fileExists(atPath: key.path) else {
            log("box: no MITM CA in \(ca.path); the sidecar cannot bump TLS")
            return []
        }
        let dir = caSidecarStagingDir(id: id)
        do {
            try resetStagingDir(dir)
            try fm.copyItem(at: cert, to: dir.appendingPathComponent("ca.crt"))
            try fm.copyItem(at: key, to: dir.appendingPathComponent("ca.key"))
        } catch {
            log("box: failed to stage the MITM CA for the sidecar: \(error)")
            try? fm.removeItem(at: dir)
            return []
        }
        return [.share(source: dir.path, destination: caMountDir, options: ["ro"])]
    }

    static func agentCACertMounts(id: String) -> [Containerization.Mount] {
        let cert = Box.caDir.appendingPathComponent("ca.crt")
        let fm = FileManager.default
        guard fm.fileExists(atPath: cert.path) else { return [] }
        let dir = caCertStagingDir(id: id)
        do {
            try resetStagingDir(dir)
            try fm.copyItem(at: cert, to: dir.appendingPathComponent("ca.crt"))
        } catch {
            log("box: failed to stage the MITM CA cert for the agent: \(error)")
            try? fm.removeItem(at: dir)
            return []
        }
        return [.share(source: dir.path, destination: caMountDir, options: ["ro"])]
    }

    static func injectMounts(_ plan: SecretPlan, id: String) -> [Containerization.Mount] {
        guard !plan.resolved.isEmpty else { return [] }
        let dir = injectStagingDir(id: id)
        let file = dir.appendingPathComponent("secrets.json")
        do {
            try resetStagingDir(dir)
            try Data(SecretInjection.renderHudsuckerConfig(plan.resolved).utf8)
                .write(to: file, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            log("box: failed to stage secret injection config: \(error); skipping injection")
            try? FileManager.default.removeItem(at: dir)
            return []
        }
        log("box: injecting secrets: \(SecretInjection.bootSummary(plan.resolved))")
        return [.share(source: dir.path, destination: injectMountDir, options: ["ro"])]
    }

    private static func caSidecarStagingDir(id: String) -> URL {
        Box.runDir.appendingPathComponent("ca-side-\(id)", isDirectory: true)
    }

    private static func caCertStagingDir(id: String) -> URL {
        Box.runDir.appendingPathComponent("ca-cert-\(id)", isDirectory: true)
    }

    private static func injectStagingDir(id: String) -> URL {
        Box.runDir.appendingPathComponent("inject-\(id)", isDirectory: true)
    }

    static let projectAllowlistMountDir = "/run/box-allowlist"
    static var projectAllowlistGuestPath: String {
        projectAllowlistMountDir + "/allowlist.project.txt"
    }

    static func allowlistMounts(
        configDir: String,
        projectAllowlist: String? = nil,
        id: String = ""
    ) -> [Containerization.Mount] {
        var mounts: [Containerization.Mount] = [
            .share(source: configDir, destination: "/etc/box", options: ["ro"])
        ]
        guard let source = projectAllowlist else { return mounts }

        let dir = projectAllowlistStagingDir(id: id)
        let dst = dir.appendingPathComponent("allowlist.project.txt")
        do {
            try resetStagingDir(dir)
            let contents = (try? String(contentsOfFile: source, encoding: .utf8)) ?? ""
            try Data(contents.utf8).write(to: dst, options: [.atomic])
        } catch {
            log("box: failed to stage trusted project allowlist: \(error); skipping")
            try? FileManager.default.removeItem(at: dir)
            return mounts
        }
        mounts.append(
            .share(source: dir.path, destination: projectAllowlistMountDir, options: ["ro"]))
        return mounts
    }

    static func filterSensitiveMounts(_ mounts: [Config.ExtraMount]) -> [Config.ExtraMount] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return mounts.filter { m in
            let resolved = URL(fileURLWithPath: expandTilde(m.source))
                .resolvingSymlinksInPath().path
            if Trust.isSensitiveSource(resolved, home: home) {
                log(
                    "box: refusing extraMount \(m.source) -> \(m.destination): "
                        + "source resolves to a sensitive path (\(resolved))")
                return false
            }
            return true
        }
    }

    static let readOnlyRootsHiddenPrefix = "/mnt/.roots"

    static func readOnlyRootMounts(_ cfg: Config) -> [Containerization.Mount] {
        let result = cfg.readOnlyRootMounts {
            FileManager.default.fileExists(atPath: $0)
        }
        for source in result.skipped {
            log("box: readOnlyRoots entry \(source) does not exist; skipping")
        }
        return result.specs.map {
            Containerization.Mount.share(
                source: $0.source,
                destination: hiddenRootDestination(forVisible: $0.destination),
                options: ["ro"])
        }
    }

    static func hiddenRootDestination(forVisible destination: String) -> String {
        let mntPrefix = "/mnt/"
        guard destination.hasPrefix(mntPrefix) else { return destination }
        return readOnlyRootsHiddenPrefix + "/" + String(destination.dropFirst(mntPrefix.count))
    }

    static let secretMountDir = "/run/box-secrets"

    static func envMounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        var dotenv: [String: String] = [:]
        if let path = cfg.envFile {
            if let text = try? String(contentsOfFile: expandTilde(path), encoding: .utf8) {
                dotenv = EnvInjection.parseDotenv(text)
            } else {
                log("box: envFile \(expandTilde(path)) is unreadable; skipping it")
            }
        }
        let merged = EnvInjection.mergedEnv(configEnv: cfg.env, dotenv: dotenv)
        guard !merged.isEmpty else { return [] }

        let dir = Box.secretDir(forBoxID: id)
        let file = Box.envFile(forBoxID: id)
        do {
            try resetStagingDir(dir)
            try Data(EnvInjection.serialize(merged).utf8).write(to: file, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            log("box: failed to stage env secrets: \(error); skipping env injection")
            try? FileManager.default.removeItem(at: dir)
            return []
        }
        log("box: injecting env keys: \(merged.keys.sorted().joined(separator: ", "))")
        return [.share(source: dir.path, destination: secretMountDir, options: ["ro"])]
    }

    private static func userMounts(_ config: Config) -> [Containerization.Mount] {
        let claudeDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude").path
        let exists = FileManager.default.fileExists(atPath: claudeDir)
        if config.mountClaudeConfig != .off && !exists {
            log("box: mountClaudeConfig is set but \(claudeDir) is missing; skipping")
        }
        return config.resolvedMounts(claudeDir: claudeDir, claudeExists: exists).map {
            Containerization.Mount.share(
                source: $0.source, destination: $0.destination,
                options: $0.readOnly ? ["ro"] : [])
        }
    }

    private static func projectAllowlistStagingDir(id: String) -> URL {
        Box.runDir.appendingPathComponent("proj-allow-\(id)")
    }

    private static func resetStagingDir(_ dir: URL) throws {
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}

enum RunState {
    static func add(id: String, cwd: String) {
        try? Assets.materialize()
        try? Data(cwd.utf8).write(to: Box.runDir.appendingPathComponent(id))
    }

    static func remove(id: String) {
        try? FileManager.default.removeItem(at: Box.runDir.appendingPathComponent(id))
    }

    static func list() -> [(id: String, cwd: String)] {
        var out: [(String, String)] = []
        for (id, marker) in markerFiles() {
            let cwd = (try? String(contentsOf: marker, encoding: .utf8)) ?? ""
            if let pid = pid(fromID: id), kill(pid, 0) != 0 {
                try? FileManager.default.removeItem(at: marker)
                continue
            }
            out.append((id, cwd))
        }
        return out
    }

    @discardableResult
    static func pruneStale() -> [String] {
        var removed: [String] = []
        for (id, marker) in markerFiles() {
            guard let pid = pid(fromID: id), kill(pid, 0) != 0 else { continue }
            try? FileManager.default.removeItem(at: marker)
            removed.append(id)
        }
        return removed.sorted()
    }

    @discardableResult
    static func stop(id: String, kill killHard: Bool) -> Bool {
        guard let pid = pid(fromID: id) else { return false }
        guard kill(pid, 0) == 0 else { return false }
        return kill(pid, killHard ? SIGKILL : SIGTERM) == 0
    }

    static func pid(fromID id: String) -> pid_t? {
        guard let last = id.split(separator: "-").last, let n = Int32(last) else { return nil }
        return n
    }

    private static func markerFiles() -> [(id: String, url: URL)] {
        let fm = FileManager.default
        let entries = (try? fm.contentsOfDirectory(atPath: Box.runDir.path)) ?? []
        return entries.compactMap { id in
            guard id.hasPrefix("box-") else { return nil }
            let url = Box.runDir.appendingPathComponent(id)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue else {
                return nil
            }
            return (id, url)
        }
    }
}
