import Containerization
import Foundation

/// Host/setup diagnostics for `box doctor`.
///
/// The checks are split from their effects so they're unit-testable: every
/// probe that touches the system (running a subprocess, reading an env var,
/// checking a path, resolving the running binary) goes through a `Probe` of
/// injectable closures. The default `Probe.live` wires those to the real
/// `Sh`/`env`/`FileManager` seams; tests pass a synthetic `Probe` to drive each
/// check deterministically without a real box or host.
public enum DiagnosticStatus: String, Sendable, Equatable {
    case pass
    case fail
    case warn

    /// Glyph rendered at the start of each line.
    public var glyph: String {
        switch self {
        case .pass: return "✔"
        case .fail: return "✖"
        case .warn: return "⚠"
        }
    }
}

/// The outcome of one check: a human name, a status, an optional detail line
/// (shown in `--verbose`), and a remediation hint (shown when not passing).
public struct DiagnosticResult: Sendable, Equatable {
    public let name: String
    public let status: DiagnosticStatus
    /// Extra context about what was observed (shown in verbose mode).
    public let detail: String?
    /// What the user should do about a failure/warning (shown when not `.pass`).
    public let remediation: String?
    /// Hard checks fail the command (nonzero exit); soft checks (warnings) don't.
    /// Only a `.fail` on a hard check exits nonzero — a `.warn` never does.
    public let hard: Bool

    public init(
        name: String,
        status: DiagnosticStatus,
        detail: String? = nil,
        remediation: String? = nil,
        hard: Bool
    ) {
        self.name = name
        self.status = status
        self.detail = detail
        self.remediation = remediation
        self.hard = hard
    }
}

/// Injectable system seams used by the checks, so they can be exercised in
/// tests. The default `live` value wires each closure to the real environment.
public struct Probe: Sendable {
    /// Machine hardware string (e.g. "arm64"), as `uname -m` would report.
    public var machine: @Sendable () -> String
    /// Major macOS version (e.g. 26), via `ProcessInfo` by default.
    public var macOSMajorVersion: @Sendable () -> Int
    /// Whether a CLI tool resolves on PATH (the `Sh.exists` seam).
    public var toolExists: @Sendable (String) -> Bool
    /// Whether the guest kernel is discoverable (`Box.kernelPath()` doesn't throw).
    public var kernelResolves: @Sendable () -> Bool
    /// Absolute path of the running binary (`_NSGetExecutablePath` + `realpath`).
    public var executablePath: @Sendable () -> String
    /// User's home directory path.
    public var homePath: @Sendable () -> String
    /// Combined stdout+stderr of a subprocess (codesign writes to stderr).
    public var commandOutput: @Sendable ([String]) -> String
    /// Whether a path exists on disk.
    public var pathExists: @Sendable (String) -> Bool
    /// Whether the image is present in the framework store. Async + throwing
    /// in reality; the closure flattens that to a Bool for the pure check layer.
    public var imageInStore: @Sendable () -> Bool
    /// Whether the vminit reference is reachable. Only run when `--online`.
    public var vminitReachable: @Sendable () -> Bool

    public init(
        machine: @escaping @Sendable () -> String,
        macOSMajorVersion: @escaping @Sendable () -> Int,
        toolExists: @escaping @Sendable (String) -> Bool,
        kernelResolves: @escaping @Sendable () -> Bool,
        executablePath: @escaping @Sendable () -> String,
        homePath: @escaping @Sendable () -> String,
        commandOutput: @escaping @Sendable ([String]) -> String,
        pathExists: @escaping @Sendable (String) -> Bool,
        imageInStore: @escaping @Sendable () -> Bool,
        vminitReachable: @escaping @Sendable () -> Bool
    ) {
        self.machine = machine
        self.macOSMajorVersion = macOSMajorVersion
        self.toolExists = toolExists
        self.kernelResolves = kernelResolves
        self.executablePath = executablePath
        self.homePath = homePath
        self.commandOutput = commandOutput
        self.pathExists = pathExists
        self.imageInStore = imageInStore
        self.vminitReachable = vminitReachable
    }

    /// The real seams: subprocesses via `Sh`, env via the module `env(_:)`
    /// helper, paths via `FileManager`, image lookup via the framework store.
    public static let live = Probe(
        machine: { Diagnostics.unameMachine() },
        macOSMajorVersion: { ProcessInfo.processInfo.operatingSystemVersion.majorVersion },
        toolExists: { Sh.exists($0) },
        kernelResolves: { (try? Box.kernelPath()) != nil },
        executablePath: { Diagnostics.runningExecutablePath() },
        homePath: { FileManager.default.homeDirectoryForCurrentUser.path },
        commandOutput: { Diagnostics.combinedOutput($0) },
        pathExists: { FileManager.default.fileExists(atPath: $0) },
        imageInStore: { Diagnostics.imagePresentInStore() },
        vminitReachable: { Diagnostics.vminitReferenceReachable() }
    )
}

public enum Diagnostics {
    /// The virtualization entitlement a codesigned box binary must carry, or the
    /// guest VM can't be created.
    static let virtualizationEntitlement = "com.apple.security.virtualization"

    /// Run every check and return the results in display order. `online`
    /// includes the network-dependent vminit reachability probe.
    public static func runAll(online: Bool, probe: Probe = .live) -> [DiagnosticResult] {
        var results: [DiagnosticResult] = [
            checkArch(probe),
            checkMacOS(probe),
            checkContainerCLI(probe),
            checkKernel(probe),
            checkDocker(probe),
            checkEntitlement(probe),
            checkLocation(probe),
            checkImage(probe),
        ]
        if online {
            results.append(checkVminit(probe))
        }
        results.append(checkLogin(probe))
        return results
    }

    // MARK: - Hard checks (a failure exits nonzero)

    static func checkArch(_ p: Probe) -> DiagnosticResult {
        let m = p.machine()
        let ok = m == "arm64"
        return DiagnosticResult(
            name: "CPU architecture is arm64",
            status: ok ? .pass : .fail,
            detail: "uname -m → \(m.isEmpty ? "(unknown)" : m)",
            remediation: ok
                ? nil
                : "box requires Apple silicon (arm64). Intel Macs can't run the arm64 microVM.",
            hard: true)
    }

    static func checkMacOS(_ p: Probe) -> DiagnosticResult {
        let v = p.macOSMajorVersion()
        let ok = v >= 26
        return DiagnosticResult(
            name: "macOS ≥ 26",
            status: ok ? .pass : .fail,
            detail: "major version \(v)",
            remediation: ok
                ? nil
                : "Apple Containerization needs macOS 26 or newer. Update macOS.",
            hard: true)
    }

    static func checkContainerCLI(_ p: Probe) -> DiagnosticResult {
        let ok = p.toolExists("container")
        return DiagnosticResult(
            name: "`container` CLI present",
            status: ok ? .pass : .fail,
            remediation: ok
                ? nil
                : "Install Apple's `container` CLI (it installs the guest kernel and is used to "
                    + "convert images). See https://github.com/apple/container.",
            hard: true)
    }

    static func checkKernel(_ p: Probe) -> DiagnosticResult {
        let ok = p.kernelResolves()
        return DiagnosticResult(
            name: "guest kernel discoverable",
            status: ok ? .pass : .fail,
            remediation: ok
                ? nil
                : "No guest kernel found. Run `container system start` (it installs the kernel), "
                    + "or set BOX_KERNEL to a vmlinux path.",
            hard: true)
    }

    static func checkDocker(_ p: Probe) -> DiagnosticResult {
        // Docker is only the fallback builder now (`container build` is the
        // primary path), so its absence is a soft warning, never a failure.
        let ok = p.toolExists("docker")
        return DiagnosticResult(
            name: "docker present (optional build fallback)",
            status: ok ? .pass : .warn,
            remediation: ok
                ? nil
                : "box builds images with `container build`; docker is only used as a "
                    + "fallback if that fails. Install docker if you need the fallback.",
            hard: false)
    }

    static func checkEntitlement(_ p: Probe) -> DiagnosticResult {
        let path = p.executablePath()
        guard !path.isEmpty else {
            return DiagnosticResult(
                name: "binary has the virtualization entitlement",
                status: .fail,
                detail: "could not resolve the running binary path",
                remediation: "Could not locate the running box binary to inspect its entitlements.",
                hard: true)
        }
        let output = p.commandOutput(["codesign", "-d", "--entitlements", "-", path])
        let ok = output.contains(virtualizationEntitlement)
        return DiagnosticResult(
            name: "binary has the virtualization entitlement",
            status: ok ? .pass : .fail,
            detail: path,
            remediation: ok
                ? nil
                : "The box binary isn't codesigned with \(virtualizationEntitlement). "
                    + "Without it the guest VM can't be created. Re-run the signing step "
                    + "(`make sign` / the codesign step in the build).",
            hard: true)
    }

    static func checkLocation(_ p: Probe) -> DiagnosticResult {
        let path = p.executablePath()
        let home = p.homePath()
        let bad = ["Documents", "Desktop"].first { sub in
            isUnder(path: path, root: home + "/" + sub)
        }
        let ok = bad == nil
        return DiagnosticResult(
            name: "binary not under ~/Documents or ~/Desktop",
            status: ok ? .pass : .fail,
            detail: path.isEmpty ? nil : path,
            remediation: ok
                ? nil
                : "The box binary is under ~/\(bad ?? "Documents"). macOS' vmnet networking breaks "
                    + "for binaries under the TCC-protected Documents/Desktop folders. Move box "
                    + "elsewhere (e.g. /usr/local/bin or ~/bin).",
            hard: true)
    }

    // MARK: - Soft checks (warnings; never fail the command)

    static func checkImage(_ p: Probe) -> DiagnosticResult {
        let ok = p.imageInStore()
        return DiagnosticResult(
            name: "image present in the framework store",
            status: ok ? .pass : .warn,
            remediation: ok
                ? nil
                : "No image in the store yet. Run `box build` (or just `box run`, which builds on "
                    + "first use).",
            hard: false)
    }

    static func checkVminit(_ p: Probe) -> DiagnosticResult {
        let ok = p.vminitReachable()
        return DiagnosticResult(
            name: "vminit reference reachable",
            status: ok ? .pass : .warn,
            detail: Box.vminitRef,
            remediation: ok
                ? nil
                : "Couldn't reach the vminit image reference (\(Box.vminitRef)). Check network "
                    + "access / registry auth, or set BOX_VMINIT.",
            hard: false)
    }

    static func checkLogin(_ p: Probe) -> DiagnosticResult {
        let ok = claudeCredentialsPresent(in: Box.agentHome.path, probe: p)
        return DiagnosticResult(
            name: "Claude login present",
            status: ok ? .pass : .warn,
            detail: Box.agentHome.path,
            remediation: ok
                ? nil
                : "No Claude credentials found in the agent home. Run `box login` to authenticate "
                    + "(persisted in the agent home).",
            hard: false)
    }

    // MARK: - Pure helpers (testable in isolation)

    /// True if `path` is `root` itself or lives under it. Compares normalized
    /// paths so trailing slashes / `.` segments don't matter, and requires a
    /// `/` boundary so `~/DocumentsX` doesn't match `~/Documents`.
    static func isUnder(path: String, root: String) -> Bool {
        guard !path.isEmpty, !root.isEmpty else { return false }
        let p = (path as NSString).standardizingPath
        let r = (root as NSString).standardizingPath
        return p == r || p.hasPrefix(r + "/")
    }

    /// Detect Claude credentials inside an agent-home directory. Claude Code
    /// stores auth in `.credentials.json` (and historically a `.claude.json`
    /// with an `oauthAccount`); the presence of any of these is treated as
    /// logged in. The agent home is mounted at `/home/agent` in the guest.
    static func claudeCredentialsPresent(in agentHome: String, probe p: Probe) -> Bool {
        let candidates = [
            agentHome + "/.claude/.credentials.json",
            agentHome + "/.credentials.json",
            agentHome + "/.claude.json",
        ]
        return candidates.contains { p.pathExists($0) }
    }

    // MARK: - Live seam implementations

    /// `uname -m` via `utsname`, avoiding a subprocess.
    static func unameMachine() -> String {
        var u = utsname()
        guard uname(&u) == 0 else { return "" }
        return withUnsafePointer(to: &u.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
    }

    /// Resolve the running binary path via `_NSGetExecutablePath` + `realpath`,
    /// so symlinks (e.g. a Homebrew shim) resolve to the real signed binary.
    static func runningExecutablePath() -> String {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var buffer = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else { return "" }
        // Resolve symlinks via realpath; both calls operate on the C buffer
        // directly to avoid the deprecated `String(cString: [CChar])` overload.
        if let resolved = realpath(buffer, nil) {
            defer { free(resolved) }
            return String(validatingCString: resolved) ?? ""
        }
        // Drop the trailing NUL before decoding the fixed-size C buffer.
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Combined stdout+stderr of a subprocess. `codesign -d --entitlements -`
    /// writes its diagnostic output to stderr, so we merge both streams.
    static func combinedOutput(_ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
        } catch {
            return ""
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Whether the box image is present in the framework store (no pull).
    static func imagePresentInStore() -> Bool {
        guard let store = try? ImageStore(path: Box.storeDir) else { return false }
        let result = LockedBool()
        let sem = DispatchSemaphore(value: 0)
        Task {
            let got = (try? await store.get(reference: Box.storeRef(), pull: false)) != nil
            result.set(got)
            sem.signal()
        }
        sem.wait()
        return result.value
    }

    /// Whether the vminit reference can be resolved (network probe; `--online`).
    /// Best-effort via the `container` CLI: an inspect that doesn't error, else
    /// a pull that succeeds.
    static func vminitReferenceReachable() -> Bool {
        guard Sh.exists("container") else { return false }
        let out = combinedOutput(["container", "image", "inspect", Box.vminitRef]).lowercased()
        if !out.isEmpty, !out.contains("error"), !out.contains("not found") {
            return true
        }
        return (try? Sh.run(["container", "image", "pull", Box.vminitRef])) == 0
    }
}

/// Tiny thread-safe Bool so the async store lookup can publish back to the
/// synchronous check layer without a data-race warning.
final class LockedBool: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = false
    func set(_ v: Bool) {
        lock.lock()
        stored = v
        lock.unlock()
    }
    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}
