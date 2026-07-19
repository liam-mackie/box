import Foundation

/// Filesystem locations and tunables for the box. The box directory holds
/// runtime state: the framework image store, the live allowlist, the persisted
/// agent home, egress logs, and per-run state files.
public enum Box {
    /// Short tag used by `container` (the local build tag).
    ///
    /// Toolchain-keyed: an empty set is `box:latest`; a non-empty set appends the
    /// sorted/deduped toolchains as a tag suffix (e.g. `box:dotnet-go-rust`),
    /// so layered variant images get their own store key.
    public static func imageRef(toolchains: [String] = []) -> String {
        "box:" + imageTag(toolchains: toolchains)
    }
    /// Fully-qualified reference the framework ImageStore keys images under
    /// (docker.io/library is applied on load/normalize). Empty set ⇒
    /// `docker.io/library/box:latest`.
    public static func storeRef(toolchains: [String] = []) -> String {
        "docker.io/library/box:" + imageTag(toolchains: toolchains)
    }

    /// The image tag for a toolchain set: `latest` when empty, else the sorted,
    /// deduped, lowercased toolchains joined with `-`.
    static func imageTag(toolchains: [String]) -> String {
        let normalized = Set(toolchains.map { $0.lowercased() }).sorted()
        return normalized.isEmpty ? "latest" : normalized.joined(separator: "-")
    }

    /// vminit guest filesystem, version-matched to the pinned framework.
    /// Override with BOX_VMINIT if the tag is unavailable.
    public static var vminitRef: String {
        env("BOX_VMINIT") ?? "ghcr.io/apple/containerization/vminit:0.33.1"
    }

    public static var dir: URL {
        if let d = env("BOX_DIR") { return URL(fileURLWithPath: d) }
        return home.appendingPathComponent(".box")
    }

    public static var storeDir: URL { dir.appendingPathComponent("store") }
    public static var agentHome: URL { dir.appendingPathComponent("agent-home") }
    public static var configDir: URL { dir.appendingPathComponent("config") }
    public static var allowlist: URL { configDir.appendingPathComponent("allowlist.txt") }
    public static var logsDir: URL { dir.appendingPathComponent("logs") }
    public static var runDir: URL { dir.appendingPathComponent("run") }

    /// direnv-style content-hash approval records for project `.box/` components.
    public static var trustDir: URL { dir.appendingPathComponent("trust") }
    /// Host-edited dynamic filesystem visibility policy, polled guest-side.
    public static var fsPolicy: URL { configDir.appendingPathComponent("fs-policy.txt") }

    public static var caDir: URL { dir.appendingPathComponent("ca") }
    public static var secretsRegistryURL: URL { dir.appendingPathComponent("secrets.json") }

    /// Per-box log directory on the host (the Envoy access log is written here).
    public static func logDir(forBoxID id: String) -> URL {
        logsDir.appendingPathComponent(id)
    }

    /// Per-box DEDICATED secrets directory under `run/`. The framework shares a
    /// single-file virtiofs source by exposing its *parent* directory, so the
    /// secrets file must live alone in its own dir — sharing it must not leak
    /// sibling files (other boxes' run markers / env files). Cleaned up in the
    /// runner's `defer`.
    public static func secretDir(forBoxID id: String) -> URL {
        runDir.appendingPathComponent("secret-\(id)", isDirectory: true)
    }

    /// Per-box ephemeral env file (0600), written inside `secretDir`, mounted ro
    /// into the guest (as a directory) and deleted in the runner's `defer`.
    public static func envFile(forBoxID id: String) -> URL {
        secretDir(forBoxID: id).appendingPathComponent("env")
    }

    /// Public resolvers, since Apple's vmnet gateway DNS is unreliable here.
    public static var dnsServers: [String] {
        if let v = env("BOX_DNS"), !v.trimmingCharacters(in: .whitespaces).isEmpty {
            return v.split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init)
        }
        return ["1.1.1.1", "1.0.0.1"]
    }

    /// Reuse the kernel that `container system start` installed.
    public static func kernelPath() throws -> URL {
        if let p = env("BOX_KERNEL") { return URL(fileURLWithPath: p) }
        let kdir =
            home
            .appendingPathComponent("Library/Application Support/com.apple.container/kernels")
        let def = kdir.appendingPathComponent("default.kernel-arm64")
        if FileManager.default.fileExists(atPath: def.path) {
            return def.resolvingSymlinksInPath()
        }
        let names = (try? FileManager.default.contentsOfDirectory(atPath: kdir.path)) ?? []
        if let newest = names.filter({ $0.hasPrefix("vmlinux") }).sorted().last {
            return kdir.appendingPathComponent(newest)
        }
        throw CBError(
            "no kernel found under \(kdir.path); run `container system start` first, "
                + "or set BOX_KERNEL")
    }

    /// Parse a size string like "4g", "512M", "8gib", or a bare byte count into
    /// bytes. Suffixes k/m/g/t are 1024-based (binary); a trailing `i`/`b`/`ib`
    /// is accepted and ignored (so "4g", "4gb", "4gib" all mean 4 GiB). Bare
    /// digits are bytes. Case-insensitive. Used for memory / rootfsSize.
    public static func parseSize(_ s: String) throws -> UInt64 {
        let trimmed = s.trimmingCharacters(in: .whitespaces).lowercased()
        guard let match = trimmed.firstMatch(of: /^([0-9]+)\s*([kmgt]?i?b?)$/) else {
            throw CBError("invalid size: \"\(s)\" (expected e.g. 4g, 512m, 8gib, or a byte count)")
        }
        guard let value = UInt64(match.1) else {
            throw CBError("size out of range: \"\(s)\"")
        }
        let multiplier: UInt64
        switch match.2.first {
        case "k": multiplier = 1024
        case "m": multiplier = 1024 * 1024
        case "g": multiplier = 1024 * 1024 * 1024
        case "t": multiplier = 1024 * 1024 * 1024 * 1024
        default: multiplier = 1  // bare number or "b" => bytes
        }
        let (product, overflow) = value.multipliedReportingOverflow(by: multiplier)
        guard !overflow else { throw CBError("size out of range: \"\(s)\"") }
        return product
    }

    private static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
}

// Read via getenv (not ProcessInfo.environment) so runtime setenv — e.g. in
// tests setting BOX_DIR — is reflected.
func env(_ key: String) -> String? {
    guard let c = getenv(key) else { return nil }
    let v = String(cString: c)
    return v.isEmpty ? nil : v
}

public struct CBError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Expand a leading `~` to the current user's home directory.
func expandTilde(_ path: String) -> String {
    guard path == "~" || path.hasPrefix("~/") else { return path }
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return path == "~" ? home : home + "/" + path.dropFirst(2)
}

/// Minimal wrapper over `/usr/bin/env`-resolved subprocesses (docker, container, tar).
enum Sh {
    @discardableResult
    static func run(_ args: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = args
        try p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    static func checked(_ args: [String]) throws {
        let code = try run(args)
        guard code == 0 else {
            throw CBError("command failed (\(code)): \(args.joined(separator: " "))")
        }
    }

    static func output(_ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func exists(_ tool: String) -> Bool {
        (try? output(["which", tool]))?.isEmpty == false
    }
}
