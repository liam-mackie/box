import Foundation

/// Version reporting for `box version` / `box --version`.
///
/// Assembles the four versions box cares about: box itself (stamped from
/// `git describe` via the Makefile, see `make version-stamp` → `VersionStamp.swift`),
/// claude-code (cached in a host-side sidecar at `Box.dir/image.json`, since the
/// real version only exists inside the built image), the Containerization
/// framework (pinned in `Package.swift`), and vminit (`Box.vminitRef`).
public enum Version {
    /// Fallback used when the build wasn't version-stamped (no git tag, or
    /// `make version-stamp` wasn't run). Real builds overwrite `boxVersionStamp`.
    static let boxDefault = "0.0.0-dev"

    /// box's own version: the Makefile-stamped value if present, else the
    /// in-file default. Drives `box version` and `box --version`.
    public static var box: String {
        if let stamp = boxVersionStamp,
            !stamp.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            return stamp
        }
        return boxDefault
    }

    /// The Containerization framework version box is built against. Pinned
    /// `exact: "0.33.1"` in `Package.swift`; keep this in sync with that pin.
    public static let containerization = "0.33.1"

    /// A resolved set of versions, ready to print.
    public struct Info: Equatable {
        public let box: String
        public let claudeCode: String
        public let containerization: String
        public let vminit: String

        public init(box: String, claudeCode: String, containerization: String, vminit: String) {
            self.box = box
            self.claudeCode = claudeCode
            self.containerization = containerization
            self.vminit = vminit
        }
    }

    /// Assemble all versions.
    ///
    /// claude-code comes from the sidecar written at build/update time. When
    /// `refresh` is requested we would query the live version inside the box,
    /// but that requires booting a VM, so this code path never boots one — it
    /// just annotates the cached value. The actual live query happens in the
    /// (VM-touching) command layer, never here.
    public static func all(refresh: Bool) -> Info {
        let cached = Sidecar.read()?.claudeCode
        let claude: String
        if let cached, !cached.isEmpty {
            claude = refresh ? "\(cached) (cached; --refresh needs a running box)" : cached
        } else {
            claude = "unknown (build or `box update` to record it)"
        }
        return Info(
            box: box,
            claudeCode: claude,
            containerization: containerization,
            vminit: Box.vminitRef
        )
    }
}

// MARK: - Host claude-code detection (for the launch-time version sync)

extension Version {
    /// The claude-code version installed on the HOST, or nil when `claude` isn't
    /// on PATH (or prints something unrecognizable). This is the reference point
    /// for `syncClaudeVersion`: the host's claude auto-updates, so "at least the
    /// host's version" keeps the box from silently falling behind (the guest
    /// can't self-update — the global npm dir is root-owned and egress is
    /// allowlisted).
    public static func hostClaudeVersion() -> String? {
        guard Sh.exists("claude") else { return nil }
        guard let out = try? Sh.output(["claude", "--version"]) else { return nil }
        return parseClaudeVersionOutput(out)
    }

    /// Pull the leading semver out of `claude --version` output
    /// (e.g. "2.1.211 (Claude Code)" → "2.1.211"). Nil when no token looks like
    /// a dotted version.
    static func parseClaudeVersionOutput(_ out: String) -> String? {
        for rawToken in out.split(whereSeparator: { $0 == " " || $0 == "\n" }) {
            let token = String(rawToken)
            if token.contains("."),
                token.allSatisfy({
                    $0.isNumber || $0 == "." || $0 == "-"
                        || $0.isLetter
                }),
                token.first?.isNumber == true
            {
                return token
            }
        }
        return nil
    }

    /// Numeric-aware version ordering: true when `lhs` is strictly older than
    /// `rhs`. Dot-separated components compare numerically when both parse
    /// (missing components count as 0), falling back to string comparison for
    /// non-numeric parts (prerelease suffixes etc.). Unparseable garbage never
    /// reports "older" spuriously: equal strings are never older.
    public static func isOlder(_ lhs: String, than rhs: String) -> Bool {
        guard lhs != rhs else { return false }
        let a = lhs.split(separator: ".")
        let b = rhs.split(separator: ".")
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? String(a[i]) : "0"
            let y = i < b.count ? String(b[i]) : "0"
            if x == y { continue }
            if let xn = Int(x), let yn = Int(y) { return xn < yn }
            return x < y
        }
        return false
    }
}

/// Host-side sidecar recording versions baked into the built image, at
/// `Box.dir/image.json`. The real claude-code version only exists inside the
/// image; the build/update path captures it here so `box version` can report it
/// without booting a VM.
public struct Sidecar: Codable, Equatable {
    /// The resolved `@anthropic-ai/claude-code` version in the current image.
    public var claudeCode: String?
    /// The version requested at build time (e.g. "latest" or a pinned version).
    public var claudeRequested: String?

    public init(claudeCode: String? = nil, claudeRequested: String? = nil) {
        self.claudeCode = claudeCode
        self.claudeRequested = claudeRequested
    }

    /// `Box.dir/image.json`.
    public static var fileURL: URL { Box.dir.appendingPathComponent("image.json") }

    /// Read the sidecar, or `nil` if absent/unreadable/corrupt.
    public static func read() -> Sidecar? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? JSONDecoder().decode(Sidecar.self, from: data)
    }

    /// Write the sidecar (pretty-printed, stable key order).
    public func write() throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try enc.encode(self)
        try FileManager.default.createDirectory(
            at: Box.dir, withIntermediateDirectories: true)
        try data.write(to: Sidecar.fileURL)
    }
}

/// Pure assembly of docker `--build-arg` tokens, factored out so it's
/// unit-testable without invoking docker. Given an ordered list of
/// `(key, value)` pairs, returns the flattened `--build-arg KEY=VALUE …` tokens.
public func buildArgTokens(_ args: [(String, String)]) -> [String] {
    args.flatMap { ["--build-arg", "\($0.0)=\($0.1)"] }
}

/// The claude-code version tokens for a `box update --to <version>`: passes
/// `CLAUDE_VERSION=<version ?? "latest">` so only the Claude layer rebuilds.
public func claudeBuildArgs(to version: String?) -> [String] {
    buildArgTokens([("CLAUDE_VERSION", version ?? "latest")])
}
