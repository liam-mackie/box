import Foundation

/// User configuration, loaded from `$XDG_CONFIG_HOME/box/config.json`
/// (default `~/.config/box/config.json`). A missing file — or missing keys —
/// fall back to defaults, so partial configs are fine.
///
/// Config is *layered*: a global file plus an optional per-project `.box/config.json`
/// (discovered by walking up from the cwd). The project layer overrides the global
/// one only for keys it actually sets — see `ConfigLayer` / `merge`. The fully
/// resolved value is a `Config`; `MergedConfig` additionally carries per-value
/// provenance so callers (e.g. `box config`) can report `[global]`/`[project]`/`[default]`.
public struct Config: Sendable, Equatable {
    /// Mount the host's `~/.claude` directory into the box so settings,
    /// CLAUDE.md, commands, agents, etc. apply as they do on the host.
    public var mountClaudeConfig: Bool
    /// Mount `~/.claude` read-only (safer, but Claude can't persist state there).
    public var claudeConfigReadOnly: Bool
    /// Additional host directories to expose in the box.
    public var extraMounts: [ExtraMount]
    /// Virtual CPUs assigned to the microVM.
    public var cpus: Int
    /// Guest memory as a size string (e.g. "4g"); parsed via `Box.parseSize`.
    public var memory: String
    /// Root filesystem size as a size string (e.g. "8g"); parsed via `Box.parseSize`.
    public var rootfsSize: String
    /// Environment variables injected into the agent process (KEY: VALUE).
    public var env: [String: String]
    /// Path to a dotenv-style file whose entries are injected (lower precedence than `env`).
    public var envFile: String?
    /// Language toolchains baked into a layered variant image (e.g. ["dotnet","go","rust"]).
    public var toolchains: [String]
    /// Host directories exposed as broad read-only roots under `/mnt`.
    public var readOnlyRoots: [String]
    /// Opt-in TLS inspection (MITM): mount the `box ca init` CA into the guest and
    /// let squid forge leaf certs for `bumpHosts`. OFF by default. Everything not
    /// in `bumpHosts` is still only peeked-and-spliced (SNI), never decrypted.
    public var tlsInspect: Bool
    /// Hosts squid is allowed to MITM-bump (decrypt) when `tlsInspect` is on. Only
    /// these are bumped; everything else — especially the Anthropic/Claude API,
    /// npm, and git — is spliced so cert-pinned / auth-sensitive clients keep working.
    public var bumpHosts: [String]
    /// Keep the image's baked claude-code at least as new as the host's `claude`.
    /// Checked at launch; a stale image triggers a fast CLAUDE_VERSION-layer
    /// rebuild (best-effort — no docker ⇒ warn and run the existing image).
    public var syncClaudeVersion: Bool
    /// Mount (read-only) the host files that hook commands in Claude settings
    /// reference, so hooks configured on the host also run inside the box.
    public var mountHooks: Bool
    /// Launch claude with `--dangerously-skip-permissions`. Defaults ON: the
    /// microVM + egress allowlist is box's permission boundary, so per-tool
    /// prompts inside it are friction without isolation value. `box run` only —
    /// explicit args the user passes always win.
    public var skipPermissions: Bool
    /// Disable Claude Code's nonessential traffic inside the box (Statsig
    /// telemetry, Sentry error reporting). The in-guest auto-updater is disabled
    /// regardless of this key — box itself keeps the version in sync with the
    /// host, and the guest install isn't agent-writable anyway.
    public var disableTelemetry: Bool
    /// Mirror the host clipboard's IMAGE content into the box (read-only, per
    /// run) so pasting an image into Claude works. Images only — text (which is
    /// where passwords live) is never synced.
    public var clipboardSync: Bool

    // Defaults, kept in one place so both `init` and the tolerant decoders agree.
    public enum Defaults {
        public static let mountClaudeConfig = false
        public static let claudeConfigReadOnly = false
        public static let extraMounts: [ExtraMount] = []
        public static let cpus = 4
        public static let memory = "4g"
        public static let rootfsSize = "8g"
        public static let env: [String: String] = [:]
        public static let envFile: String? = nil
        public static let toolchains: [String] = []
        public static let readOnlyRoots: [String] = []
        public static let tlsInspect = false
        public static let bumpHosts: [String] = []
        public static let syncClaudeVersion = true
        public static let mountHooks = true
        public static let skipPermissions = true
        public static let disableTelemetry = true
        public static let clipboardSync = true
    }

    public struct ExtraMount: Sendable, Equatable {
        public var source: String
        public var destination: String
        public var readOnly: Bool

        public init(source: String, destination: String, readOnly: Bool = false) {
            self.source = source
            self.destination = destination
            self.readOnly = readOnly
        }
    }

    public init(
        mountClaudeConfig: Bool = Defaults.mountClaudeConfig,
        claudeConfigReadOnly: Bool = Defaults.claudeConfigReadOnly,
        extraMounts: [ExtraMount] = Defaults.extraMounts,
        cpus: Int = Defaults.cpus,
        memory: String = Defaults.memory,
        rootfsSize: String = Defaults.rootfsSize,
        env: [String: String] = Defaults.env,
        envFile: String? = Defaults.envFile,
        toolchains: [String] = Defaults.toolchains,
        readOnlyRoots: [String] = Defaults.readOnlyRoots,
        tlsInspect: Bool = Defaults.tlsInspect,
        bumpHosts: [String] = Defaults.bumpHosts,
        syncClaudeVersion: Bool = Defaults.syncClaudeVersion,
        mountHooks: Bool = Defaults.mountHooks,
        skipPermissions: Bool = Defaults.skipPermissions,
        disableTelemetry: Bool = Defaults.disableTelemetry,
        clipboardSync: Bool = Defaults.clipboardSync
    ) {
        self.mountClaudeConfig = mountClaudeConfig
        self.claudeConfigReadOnly = claudeConfigReadOnly
        self.extraMounts = extraMounts
        self.cpus = cpus
        self.memory = memory
        self.rootfsSize = rootfsSize
        self.env = env
        self.envFile = envFile
        self.toolchains = toolchains
        self.readOnlyRoots = readOnlyRoots
        self.tlsInspect = tlsInspect
        self.bumpHosts = bumpHosts
        self.syncClaudeVersion = syncClaudeVersion
        self.mountHooks = mountHooks
        self.skipPermissions = skipPermissions
        self.disableTelemetry = disableTelemetry
        self.clipboardSync = clipboardSync
    }

    /// Location of the global config file (honors XDG_CONFIG_HOME).
    public static var fileURL: URL {
        let base: URL
        // `BoxKit.env(_:)` is the module-level getenv helper, not the `env`
        // config property (which would otherwise shadow it inside this type).
        if let x = BoxKit.env("XDG_CONFIG_HOME") {
            base = URL(fileURLWithPath: x)
        } else {
            base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config")
        }
        return base.appendingPathComponent("box", isDirectory: true)
            .appendingPathComponent("config.json")
    }

    /// A resolved host→guest mount derived from the config.
    public struct MountSpec: Equatable, Sendable {
        public let source: String
        public let destination: String
        public let readOnly: Bool
    }

    /// Result of mapping `readOnlyRoots` to mounts: the kept (existing) specs plus
    /// the sources that were skipped because they don't exist, so the caller can warn.
    public struct ReadOnlyRootMounts: Equatable, Sendable {
        public let specs: [MountSpec]
        public let skipped: [String]
    }

    /// Pure mapping of `readOnlyRoots` → read-only mounts under `/mnt`.
    ///
    /// Each entry is `expandTilde`d and mounted READ-ONLY at `/mnt/<basename>`
    /// (e.g. `~/g` → `/mnt/g`). Existence is decided by the supplied `exists`
    /// predicate (not the real filesystem), so this stays FS-free and testable;
    /// non-existent sources are dropped from `specs` and reported in `skipped`.
    ///
    /// Basename collisions are disambiguated deterministically by suffixing the
    /// destination with `-2`, `-3`, … in input order, so two roots sharing a
    /// basename (e.g. `~/a/work` and `~/b/work`) never clobber each other
    /// (`/mnt/work`, `/mnt/work-2`). Blank entries are ignored.
    public func readOnlyRootMounts(exists: (String) -> Bool) -> ReadOnlyRootMounts {
        var specs: [MountSpec] = []
        var skipped: [String] = []
        var usedDestinations: Set<String> = []
        for raw in readOnlyRoots {
            let source = expandTilde(raw.trimmingCharacters(in: .whitespaces))
            if source.isEmpty { continue }
            guard exists(source) else {
                skipped.append(source)
                continue
            }
            let base = Config.sanitizedBasename(of: source)
            var destination = "/mnt/\(base)"
            var n = 2
            while usedDestinations.contains(destination) {
                destination = "/mnt/\(base)-\(n)"
                n += 1
            }
            usedDestinations.insert(destination)
            specs.append(MountSpec(source: source, destination: destination, readOnly: true))
        }
        return ReadOnlyRootMounts(specs: specs, skipped: skipped)
    }

    /// Last path component of an absolute path, sanitized into a single mount-safe
    /// segment: trailing slashes dropped (by `lastPathComponent`), any residual
    /// slashes folded to `-`, leading/trailing dashes trimmed, and a degenerate
    /// result (e.g. source `"/"`, whose component is itself `"/"`) falling back to
    /// `root`.
    static func sanitizedBasename(of source: String) -> String {
        let base = (source as NSString).lastPathComponent
        let folded = base.replacingOccurrences(of: "/", with: "-")
        let trimmed = folded.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "root" : trimmed
    }

    /// Pure mapping of config → mounts. `claudeExists` is supplied by the
    /// caller so this stays filesystem-free and unit-testable.
    public func resolvedMounts(claudeDir: String, claudeExists: Bool) -> [MountSpec] {
        var specs: [MountSpec] = []
        if mountClaudeConfig && claudeExists {
            specs.append(
                MountSpec(
                    source: claudeDir,
                    destination: "/home/agent/.claude",
                    readOnly: claudeConfigReadOnly))
        }
        for m in extraMounts {
            specs.append(
                MountSpec(
                    source: expandTilde(m.source),
                    destination: m.destination,
                    readOnly: m.readOnly))
        }
        return specs
    }

    /// Load the global config, returning defaults if the file is absent or invalid.
    public static func load() -> Config {
        guard let data = try? Data(contentsOf: fileURL) else { return Config() }
        do {
            return try JSONDecoder().decode(Config.self, from: data)
        } catch {
            FileHandle.standardError.write(
                Data("box: ignoring invalid \(fileURL.path): \(error)\n".utf8))
            return Config()
        }
    }
}

// Decoding tolerates missing keys (each falls back to its default).
extension Config: Decodable {
    enum CodingKeys: String, CodingKey {
        case mountClaudeConfig, claudeConfigReadOnly, extraMounts
        case cpus, memory, rootfsSize, env, envFile, toolchains, readOnlyRoots
        case tlsInspect, bumpHosts, syncClaudeVersion, mountHooks
        case skipPermissions, disableTelemetry, clipboardSync
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            mountClaudeConfig: try c.decodeIfPresent(Bool.self, forKey: .mountClaudeConfig)
                ?? Defaults.mountClaudeConfig,
            claudeConfigReadOnly: try c.decodeIfPresent(Bool.self, forKey: .claudeConfigReadOnly)
                ?? Defaults.claudeConfigReadOnly,
            extraMounts: try c.decodeIfPresent([ExtraMount].self, forKey: .extraMounts)
                ?? Defaults.extraMounts,
            cpus: try c.decodeIfPresent(Int.self, forKey: .cpus) ?? Defaults.cpus,
            memory: try c.decodeIfPresent(String.self, forKey: .memory) ?? Defaults.memory,
            rootfsSize: try c.decodeIfPresent(String.self, forKey: .rootfsSize)
                ?? Defaults.rootfsSize,
            env: try c.decodeIfPresent([String: String].self, forKey: .env) ?? Defaults.env,
            envFile: try c.decodeIfPresent(String.self, forKey: .envFile) ?? Defaults.envFile,
            toolchains: try c.decodeIfPresent([String].self, forKey: .toolchains)
                ?? Defaults.toolchains,
            readOnlyRoots: try c.decodeIfPresent([String].self, forKey: .readOnlyRoots)
                ?? Defaults.readOnlyRoots,
            tlsInspect: try c.decodeIfPresent(Bool.self, forKey: .tlsInspect)
                ?? Defaults.tlsInspect,
            bumpHosts: try c.decodeIfPresent([String].self, forKey: .bumpHosts)
                ?? Defaults.bumpHosts,
            syncClaudeVersion: try c.decodeIfPresent(Bool.self, forKey: .syncClaudeVersion)
                ?? Defaults.syncClaudeVersion,
            mountHooks: try c.decodeIfPresent(Bool.self, forKey: .mountHooks)
                ?? Defaults.mountHooks,
            skipPermissions: try c.decodeIfPresent(Bool.self, forKey: .skipPermissions)
                ?? Defaults.skipPermissions,
            disableTelemetry: try c.decodeIfPresent(Bool.self, forKey: .disableTelemetry)
                ?? Defaults.disableTelemetry,
            clipboardSync: try c.decodeIfPresent(Bool.self, forKey: .clipboardSync)
                ?? Defaults.clipboardSync
        )
    }
}

extension Config.ExtraMount: Decodable {
    enum CodingKeys: String, CodingKey { case source, destination, readOnly }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            source: try c.decode(String.self, forKey: .source),
            destination: try c.decode(String.self, forKey: .destination),
            readOnly: try c.decodeIfPresent(Bool.self, forKey: .readOnly) ?? false
        )
    }
}

// MARK: - Layered config (global ⊕ project)

/// A *partial* config: every field is optional, so we can tell "key absent"
/// from "key set to its default". Decoded tolerantly from a config file; the
/// nil-for-everything case is a valid (empty) layer.
public struct ConfigLayer: Sendable, Equatable {
    public var mountClaudeConfig: Bool?
    public var claudeConfigReadOnly: Bool?
    public var extraMounts: [Config.ExtraMount]?
    public var cpus: Int?
    public var memory: String?
    public var rootfsSize: String?
    public var env: [String: String]?
    public var envFile: String?
    public var toolchains: [String]?
    public var readOnlyRoots: [String]?
    public var tlsInspect: Bool?
    public var bumpHosts: [String]?
    public var syncClaudeVersion: Bool?
    public var mountHooks: Bool?
    public var skipPermissions: Bool?
    public var disableTelemetry: Bool?
    public var clipboardSync: Bool?

    public init(
        mountClaudeConfig: Bool? = nil,
        claudeConfigReadOnly: Bool? = nil,
        extraMounts: [Config.ExtraMount]? = nil,
        cpus: Int? = nil,
        memory: String? = nil,
        rootfsSize: String? = nil,
        env: [String: String]? = nil,
        envFile: String? = nil,
        toolchains: [String]? = nil,
        readOnlyRoots: [String]? = nil,
        tlsInspect: Bool? = nil,
        bumpHosts: [String]? = nil,
        syncClaudeVersion: Bool? = nil,
        mountHooks: Bool? = nil,
        skipPermissions: Bool? = nil,
        disableTelemetry: Bool? = nil,
        clipboardSync: Bool? = nil
    ) {
        self.mountClaudeConfig = mountClaudeConfig
        self.claudeConfigReadOnly = claudeConfigReadOnly
        self.extraMounts = extraMounts
        self.cpus = cpus
        self.memory = memory
        self.rootfsSize = rootfsSize
        self.env = env
        self.envFile = envFile
        self.toolchains = toolchains
        self.readOnlyRoots = readOnlyRoots
        self.tlsInspect = tlsInspect
        self.bumpHosts = bumpHosts
        self.syncClaudeVersion = syncClaudeVersion
        self.mountHooks = mountHooks
        self.skipPermissions = skipPermissions
        self.disableTelemetry = disableTelemetry
        self.clipboardSync = clipboardSync
    }

    /// Decode a layer from JSON, returning an empty layer (all nil) on absence
    /// or invalid JSON — same tolerant idiom as `Config.load`.
    public static func load(from url: URL) -> ConfigLayer {
        guard let data = try? Data(contentsOf: url) else { return ConfigLayer() }
        do {
            return try JSONDecoder().decode(ConfigLayer.self, from: data)
        } catch {
            FileHandle.standardError.write(
                Data("box: ignoring invalid \(url.path): \(error)\n".utf8))
            return ConfigLayer()
        }
    }
}

extension ConfigLayer: Decodable {
    enum CodingKeys: String, CodingKey {
        case mountClaudeConfig, claudeConfigReadOnly, extraMounts
        case cpus, memory, rootfsSize, env, envFile, toolchains, readOnlyRoots
        case tlsInspect, bumpHosts, syncClaudeVersion, mountHooks
        case skipPermissions, disableTelemetry, clipboardSync
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            mountClaudeConfig: try c.decodeIfPresent(Bool.self, forKey: .mountClaudeConfig),
            claudeConfigReadOnly: try c.decodeIfPresent(Bool.self, forKey: .claudeConfigReadOnly),
            extraMounts: try c.decodeIfPresent([Config.ExtraMount].self, forKey: .extraMounts),
            cpus: try c.decodeIfPresent(Int.self, forKey: .cpus),
            memory: try c.decodeIfPresent(String.self, forKey: .memory),
            rootfsSize: try c.decodeIfPresent(String.self, forKey: .rootfsSize),
            env: try c.decodeIfPresent([String: String].self, forKey: .env),
            envFile: try c.decodeIfPresent(String.self, forKey: .envFile),
            toolchains: try c.decodeIfPresent([String].self, forKey: .toolchains),
            readOnlyRoots: try c.decodeIfPresent([String].self, forKey: .readOnlyRoots),
            tlsInspect: try c.decodeIfPresent(Bool.self, forKey: .tlsInspect),
            bumpHosts: try c.decodeIfPresent([String].self, forKey: .bumpHosts),
            syncClaudeVersion: try c.decodeIfPresent(Bool.self, forKey: .syncClaudeVersion),
            mountHooks: try c.decodeIfPresent(Bool.self, forKey: .mountHooks),
            skipPermissions: try c.decodeIfPresent(Bool.self, forKey: .skipPermissions),
            disableTelemetry: try c.decodeIfPresent(Bool.self, forKey: .disableTelemetry),
            clipboardSync: try c.decodeIfPresent(Bool.self, forKey: .clipboardSync)
        )
    }
}

/// Where a resolved value came from, for `box config` provenance reporting.
public enum Origin: String, Sendable, Equatable {
    case `default`
    case global
    case project
}

extension Config {
    /// Merge a global and an (optional) project layer into a concrete `Config`.
    ///
    /// Field-level override: project wins for any key it sets, else global, else
    /// the built-in default. `extraMounts` are *appended* (global first, then
    /// project) and deduped by destination — project wins on a destination clash.
    /// Pure and filesystem-free.
    public static func merge(global: ConfigLayer, project: ConfigLayer?) -> Config {
        merged(global: global, project: project).config
    }

    /// Like `merge`, but also returns per-value provenance.
    public static func merged(global: ConfigLayer, project: ConfigLayer?) -> MergedConfig {
        let p = project ?? ConfigLayer()

        // For a scalar field: project value (if set) wins, else global, else default.
        func pick<T>(_ proj: T?, _ glob: T?, _ def: T) -> (T, Origin) {
            if let v = proj { return (v, .project) }
            if let v = glob { return (v, .global) }
            return (def, .default)
        }

        let (mountClaude, mountClaudeOrigin) =
            pick(p.mountClaudeConfig, global.mountClaudeConfig, Defaults.mountClaudeConfig)
        let (claudeRO, claudeROOrigin) =
            pick(p.claudeConfigReadOnly, global.claudeConfigReadOnly, Defaults.claudeConfigReadOnly)
        let (cpus, cpusOrigin) = pick(p.cpus, global.cpus, Defaults.cpus)
        let (memory, memoryOrigin) = pick(p.memory, global.memory, Defaults.memory)
        let (rootfsSize, rootfsOrigin) = pick(p.rootfsSize, global.rootfsSize, Defaults.rootfsSize)
        let (env, envOrigin) = pick(p.env, global.env, Defaults.env)
        // `envFile` is itself Optional, so the generic `pick` (which promotes a
        // `String?` to `String??` and reads `.some(nil)` as "present") would always
        // report `.project`. Resolve it explicitly: a nil layer value means "unset",
        // falling through global → default.
        let envFile: String?
        let envFileOrigin: Origin
        if let v = p.envFile {
            (envFile, envFileOrigin) = (v, .project)
        } else if let v = global.envFile {
            (envFile, envFileOrigin) = (v, .global)
        } else {
            (envFile, envFileOrigin) = (Defaults.envFile, .default)
        }
        let (toolchains, toolchainsOrigin) = pick(
            p.toolchains, global.toolchains, Defaults.toolchains)
        let (roRoots, roRootsOrigin) = pick(
            p.readOnlyRoots, global.readOnlyRoots, Defaults.readOnlyRoots)
        let (tlsInspect, tlsInspectOrigin) = pick(
            p.tlsInspect, global.tlsInspect, Defaults.tlsInspect)
        let (bumpHosts, bumpHostsOrigin) = pick(p.bumpHosts, global.bumpHosts, Defaults.bumpHosts)
        let (syncClaude, syncClaudeOrigin) =
            pick(p.syncClaudeVersion, global.syncClaudeVersion, Defaults.syncClaudeVersion)
        let (mountHooks, mountHooksOrigin) =
            pick(p.mountHooks, global.mountHooks, Defaults.mountHooks)
        let (skipPermissions, skipPermissionsOrigin) =
            pick(p.skipPermissions, global.skipPermissions, Defaults.skipPermissions)
        let (disableTelemetry, disableTelemetryOrigin) =
            pick(p.disableTelemetry, global.disableTelemetry, Defaults.disableTelemetry)
        let (clipboardSync, clipboardSyncOrigin) =
            pick(p.clipboardSync, global.clipboardSync, Defaults.clipboardSync)

        // extraMounts: append global then project, dedup by destination (project wins).
        let (mounts, mountsOrigin) = mergeExtraMounts(
            global: global.extraMounts, project: p.extraMounts)

        let config = Config(
            mountClaudeConfig: mountClaude,
            claudeConfigReadOnly: claudeRO,
            extraMounts: mounts,
            cpus: cpus,
            memory: memory,
            rootfsSize: rootfsSize,
            env: env,
            envFile: envFile,
            toolchains: toolchains,
            readOnlyRoots: roRoots,
            tlsInspect: tlsInspect,
            bumpHosts: bumpHosts,
            syncClaudeVersion: syncClaude,
            mountHooks: mountHooks,
            skipPermissions: skipPermissions,
            disableTelemetry: disableTelemetry,
            clipboardSync: clipboardSync
        )
        let origins = MergedConfig.Origins(
            mountClaudeConfig: mountClaudeOrigin,
            claudeConfigReadOnly: claudeROOrigin,
            extraMounts: mountsOrigin,
            cpus: cpusOrigin,
            memory: memoryOrigin,
            rootfsSize: rootfsOrigin,
            env: envOrigin,
            envFile: envFileOrigin,
            toolchains: toolchainsOrigin,
            readOnlyRoots: roRootsOrigin,
            tlsInspect: tlsInspectOrigin,
            bumpHosts: bumpHostsOrigin,
            syncClaudeVersion: syncClaudeOrigin,
            mountHooks: mountHooksOrigin,
            skipPermissions: skipPermissionsOrigin,
            disableTelemetry: disableTelemetryOrigin,
            clipboardSync: clipboardSyncOrigin
        )
        return MergedConfig(config: config, origins: origins)
    }

    /// Append global then project mounts, deduping by destination (project wins).
    /// Returns the merged list plus an origin: `.project` if the project layer
    /// contributed any mount, else `.global` if global did, else `.default`.
    static func mergeExtraMounts(
        global: [ExtraMount]?, project: [ExtraMount]?
    ) -> ([ExtraMount], Origin) {
        let g = global ?? []
        let p = project ?? []
        var byDest: [String: ExtraMount] = [:]
        var order: [String] = []
        for m in g {
            if byDest[m.destination] == nil { order.append(m.destination) }
            byDest[m.destination] = m
        }
        for m in p {  // project overrides any colliding destination
            if byDest[m.destination] == nil { order.append(m.destination) }
            byDest[m.destination] = m
        }
        let merged = order.compactMap { byDest[$0] }
        let origin: Origin = project != nil ? .project : (global != nil ? .global : .default)
        return (merged, origin)
    }
}

/// A fully-resolved config plus the origin of each value.
public struct MergedConfig: Sendable, Equatable {
    public var config: Config
    public var origins: Origins

    public struct Origins: Sendable, Equatable {
        public var mountClaudeConfig: Origin
        public var claudeConfigReadOnly: Origin
        public var extraMounts: Origin
        public var cpus: Origin
        public var memory: Origin
        public var rootfsSize: Origin
        public var env: Origin
        public var envFile: Origin
        public var toolchains: Origin
        public var readOnlyRoots: Origin
        public var tlsInspect: Origin
        public var bumpHosts: Origin
        public var syncClaudeVersion: Origin
        public var mountHooks: Origin
        public var skipPermissions: Origin
        public var disableTelemetry: Origin
        public var clipboardSync: Origin

        public init(
            mountClaudeConfig: Origin, claudeConfigReadOnly: Origin, extraMounts: Origin,
            cpus: Origin, memory: Origin, rootfsSize: Origin, env: Origin,
            envFile: Origin, toolchains: Origin, readOnlyRoots: Origin,
            tlsInspect: Origin, bumpHosts: Origin,
            syncClaudeVersion: Origin, mountHooks: Origin,
            skipPermissions: Origin, disableTelemetry: Origin, clipboardSync: Origin
        ) {
            self.mountClaudeConfig = mountClaudeConfig
            self.claudeConfigReadOnly = claudeConfigReadOnly
            self.extraMounts = extraMounts
            self.cpus = cpus
            self.memory = memory
            self.rootfsSize = rootfsSize
            self.env = env
            self.envFile = envFile
            self.toolchains = toolchains
            self.readOnlyRoots = readOnlyRoots
            self.tlsInspect = tlsInspect
            self.bumpHosts = bumpHosts
            self.syncClaudeVersion = syncClaudeVersion
            self.mountHooks = mountHooks
            self.skipPermissions = skipPermissions
            self.disableTelemetry = disableTelemetry
            self.clipboardSync = clipboardSync
        }
    }

    public init(config: Config, origins: Origins) {
        self.config = config
        self.origins = origins
    }
}

// MARK: - Project discovery & layered loading

extension Config {
    /// Walk UP from `cwd` looking for the nearest ancestor containing a `.box/`
    /// directory (like git's `.git` discovery), and return that `.box/` URL.
    /// Stops *before* `$HOME` (a `.box` literally at `$HOME` is the global dir,
    /// not a project) and at the filesystem root. Returns nil if none found.
    ///
    /// Pure-ish: takes the cwd and the stop boundary explicitly so it's testable
    /// without depending on the real `$HOME`.
    public static func projectConfigDir(startingFrom cwd: URL, stopAt: URL) -> URL? {
        let fm = FileManager.default
        var dir = cwd.standardizedFileURL
        let stop = stopAt.standardizedFileURL
        while true {
            // Never treat the stop boundary (or above) as a project root.
            if dir.path == stop.path { return nil }
            let candidate = dir.appendingPathComponent(".box", isDirectory: true)
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: candidate.path, isDirectory: &isDir), isDir.boolValue {
                return candidate
            }
            let parent = dir.deletingLastPathComponent().standardizedFileURL
            if parent.path == dir.path { return nil }  // hit filesystem root
            dir = parent
        }
    }

    /// Orchestrate layered loading: global config + (discovered) project config,
    /// merged with project precedence. Filesystem-aware.
    ///
    /// `trustProjectConfig` gates whether a discovered project layer is honored.
    /// It defaults to `false` (global-only); callers pass `true` only once the
    /// project's `config.json` has cleared the content-hash trust check (see
    /// `ProjectTrust`), so an untrusted project config is never applied.
    public static func loadLayered(cwd: URL, trustProjectConfig: Bool = false) -> MergedConfig {
        let global = ConfigLayer.load(from: fileURL)
        let home = FileManager.default.homeDirectoryForCurrentUser
        var project: ConfigLayer?
        if trustProjectConfig,
            let projectDir = projectConfigDir(startingFrom: cwd, stopAt: home)
        {
            project = ConfigLayer.load(from: projectDir.appendingPathComponent("config.json"))
        }
        return merged(global: global, project: project)
    }
}
