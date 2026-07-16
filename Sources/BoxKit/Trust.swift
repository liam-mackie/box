import Crypto
import Foundation

/// direnv-style content-hash approval for per-project `.box/` components.
///
/// A project's `.box/` **never auto-applies**: box honors a component (its
/// allowlist, or its full config including the dangerous `extraMounts`/`env`/
/// `readOnlyRoots`) only when the live content hashes match an approved record.
/// `box trust` records the current hashes; any edit or `git pull` changes a hash
/// and re-blocks the component until re-trusted. Fail-closed: a missing record,
/// a missing component hash, or any mismatch yields "not trusted".
///
/// The hashing + evaluation core here is pure and filesystem-free (and so unit
/// tested directly); `TrustStore` is the thin JSON read/write wrapper keyed by
/// absolute project-dir path.
public enum Trust {
    /// Content hash for a single component: `sha256(path + "\n" + contents)`.
    ///
    /// Binding the absolute path into the digest means an identical allowlist
    /// copied into a different repo does not inherit the original's approval.
    public static func hash(path: String, contents: String) -> String {
        let digest = SHA256.hash(data: Data((path + "\n" + contents).utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Per-project approval: the hashes that were approved for each component.
    /// A `nil` component hash means that component was never approved (e.g.
    /// `box trust --allowlist-only` records `config == nil`).
    public struct Record: Codable, Equatable, Sendable {
        /// Approved hash of the project `.box/allowlist.txt`.
        public var allowlist: String?
        /// Approved hash of the project `.box/config.json` (gates the dangerous
        /// `extraMounts`/`env`/`readOnlyRoots`); `nil` under `--allowlist-only`.
        public var config: String?

        public init(allowlist: String? = nil, config: String? = nil) {
            self.allowlist = allowlist
            self.config = config
        }
    }

    /// The outcome of evaluating a live `.box/` against its approval record.
    public struct Decision: Equatable, Sendable {
        /// Honor the project allowlist (union it into the egress allowlist).
        public let allowlistTrusted: Bool
        /// Honor the project config (extraMounts/env/readOnlyRoots/etc.).
        public let configTrusted: Bool

        public init(allowlistTrusted: Bool, configTrusted: Bool) {
            self.allowlistTrusted = allowlistTrusted
            self.configTrusted = configTrusted
        }
    }

    /// Host paths a *trusted* project config must never be allowed to mount via
    /// `extraMounts` (they'd hand the agent secrets/credentials). Matched against
    /// the symlink-resolved source: an exact hit or any path *underneath* one of
    /// these (e.g. `~/.ssh/id_ed25519`) is rejected. Tilde-expansion of the home
    /// directory is supplied by the caller so this stays filesystem-free.
    public static func sensitivePrefixes(home: String) -> [String] {
        [
            home + "/.ssh",
            home + "/.aws",
            home + "/.gnupg",
            home + "/.config/gh",
            home + "/.box",  // box's own trust/store/login state
            home + "/Library/Keychains",
            "/etc",
            "/private/etc",
            "/var/db",
            "/private/var/db",
        ]
    }

    /// Whether a symlink-resolved source path is sensitive (equals or is nested
    /// under a sensitive prefix). Pure string comparison on the *already
    /// symlink-resolved* path the caller passes in.
    public static func isSensitiveSource(_ resolved: String, home: String) -> Bool {
        for prefix in sensitivePrefixes(home: home) {
            if resolved == prefix || resolved.hasPrefix(prefix + "/") { return true }
        }
        return false
    }

    /// Evaluate live hashes against a stored record. A component is trusted only
    /// on an exact hash match against a recorded (non-nil) approved hash. A nil
    /// `record` (no approval at all), a nil recorded component hash, or a nil
    /// live hash (component absent) all yield "not trusted" — fail-closed.
    public static func evaluate(
        record: Record?,
        liveAllowlistHash: String?,
        liveConfigHash: String?
    ) -> Decision {
        func trusted(_ approved: String?, _ live: String?) -> Bool {
            guard let approved, let live else { return false }
            return approved == live
        }
        guard let record else {
            return Decision(allowlistTrusted: false, configTrusted: false)
        }
        return Decision(
            allowlistTrusted: trusted(record.allowlist, liveAllowlistHash),
            configTrusted: trusted(record.config, liveConfigHash)
        )
    }
}

// MARK: - Trust store (thin FS wrapper)

/// Persists `Trust.Record`s as a JSON map keyed by absolute project-dir path,
/// at `Box.trustDir/trust.json`. Tolerant of a missing/invalid file (treated as
/// empty), in keeping with the rest of the config stack.
public enum TrustStore {
    /// Location of the on-disk trust map.
    public static var fileURL: URL { Box.trustDir.appendingPathComponent("trust.json") }

    /// The project-dir key: the absolute, symlink-resolved path of the directory
    /// that *contains* the `.box/` (i.e. the `.box`'s parent). Resolving symlinks
    /// keeps the key stable regardless of how the user `cd`'d in.
    public static func key(forProjectBoxDir boxDir: URL) -> String {
        boxDir.deletingLastPathComponent().resolvingSymlinksInPath().path
    }

    /// Load the full key→record map (empty if the file is absent/invalid).
    public static func loadAll() -> [String: Trust.Record] {
        guard let data = try? Data(contentsOf: fileURL) else { return [:] }
        return (try? JSONDecoder().decode([String: Trust.Record].self, from: data)) ?? [:]
    }

    /// The record approved for a given project `.box/` dir, if any.
    public static func record(forProjectBoxDir boxDir: URL) -> Trust.Record? {
        loadAll()[key(forProjectBoxDir: boxDir)]
    }

    /// Replace (or remove, when `record == nil`) the record for a project dir and
    /// write the map back atomically. Creates `Box.trustDir` if needed.
    public static func setRecord(_ record: Trust.Record?, forProjectBoxDir boxDir: URL) throws {
        try FileManager.default.createDirectory(at: Box.trustDir, withIntermediateDirectories: true)
        var all = loadAll()
        let k = key(forProjectBoxDir: boxDir)
        if let record { all[k] = record } else { all.removeValue(forKey: k) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(all).write(to: fileURL, options: .atomic)
    }
}

// MARK: - Discovery + live hashing (FS-aware glue)

/// Ties project discovery, live component hashing, and stored-record evaluation
/// together so the runner and `box trust`/`box config` agree on what's trusted.
/// The hashing/evaluation it relies on (`Trust.hash`/`Trust.evaluate`) stays
/// pure; this layer only reads files.
public enum ProjectTrust {
    /// A discovered project `.box/` plus its component files and live hashes.
    /// `*Hash` is nil when the corresponding file is absent.
    public struct Discovered: Sendable {
        /// The project `.box/` directory.
        public let boxDir: URL
        /// `.box/allowlist.txt` (may not exist).
        public let allowlistURL: URL
        /// `.box/config.json` (may not exist).
        public let configURL: URL
        /// Live `sha256(path+contents)` of the allowlist, or nil if absent.
        public let allowlistHash: String?
        /// Live `sha256(path+contents)` of the config, or nil if absent.
        public let configHash: String?
    }

    /// Hash a component file using its absolute path; nil if the file is absent.
    static func liveHash(of url: URL) -> String? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return Trust.hash(path: url.standardizedFileURL.path, contents: contents)
    }

    /// Discover the nearest project `.box/` walking up from `cwd` (stopping before
    /// `$HOME`), and compute its live component hashes. Returns nil if no project
    /// `.box/` is found.
    public static func discover(cwd: URL) -> Discovered? {
        let home = FileManager.default.homeDirectoryForCurrentUser
        guard let boxDir = Config.projectConfigDir(startingFrom: cwd, stopAt: home) else {
            return nil
        }
        let allowlistURL = boxDir.appendingPathComponent("allowlist.txt")
        let configURL = boxDir.appendingPathComponent("config.json")
        return Discovered(
            boxDir: boxDir,
            allowlistURL: allowlistURL,
            configURL: configURL,
            allowlistHash: liveHash(of: allowlistURL),
            configHash: liveHash(of: configURL)
        )
    }

    /// Evaluate a discovered project against its stored trust record. With no
    /// discovered project, nothing is trusted (global-only).
    public static func evaluate(_ discovered: Discovered?) -> Trust.Decision {
        guard let d = discovered else {
            return Trust.Decision(allowlistTrusted: false, configTrusted: false)
        }
        let record = TrustStore.record(forProjectBoxDir: d.boxDir)
        return Trust.evaluate(
            record: record,
            liveAllowlistHash: d.allowlistHash,
            liveConfigHash: d.configHash
        )
    }

    /// Convenience: discover from `cwd` and evaluate in one step.
    public static func evaluate(cwd: URL) -> Trust.Decision {
        evaluate(discover(cwd: cwd))
    }
}
