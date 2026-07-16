import Foundation

/// Mounting the host files that Claude-settings hooks reference (`mountHooks`,
/// on by default).
///
/// Hooks in a settings.json are arbitrary shell commands, usually pointing at
/// scripts on the HOST (`~/.claude/hooks/x.sh`, `/Users/you/g/dotfiles/lint.py`).
/// Inside the box those paths don't exist, so every hook silently breaks. This
/// module extracts the path-looking tokens from each hook command and mirrors
/// them into the guest READ-ONLY at the path the command will actually resolve:
///
///   * `~/…` and `$HOME/…` — the guest shell expands these against the guest
///     home, so the host file mounts under `/home/agent/…`.
///   * absolute paths under the host home — the command names the literal host
///     path, so the file mounts at that same absolute path in the guest.
///   * `$CLAUDE_PROJECT_DIR/…` — resolves inside the workspace, which is
///     already mounted; nothing to do.
///
/// Guardrails: only paths under the host home are mirrored (an absolute path
/// like `/usr/bin/python3` must not shadow the guest's own system dirs), a
/// script sitting at the home ROOT is refused (its parent-dir mount would be
/// the whole home directory), sensitive sources (~/.ssh etc.) are refused via
/// the caller-supplied predicate, and everything is read-only. We mount the
/// script's PARENT DIRECTORY (the framework shares a single file by exposing
/// its parent anyway), deduping refs covered by an already-selected mount or by
/// the `mountClaudeConfig` share.
///
/// The core is pure (filesystem via injected predicates) so the extraction,
/// mapping, and guardrails are unit-testable; `Runner.hookMounts` supplies the
/// real filesystem and the sensitive-path check.
public enum HookMounts {
    /// A single path reference found in a hook command: where it lives on the
    /// host and where the guest-side command will look for it.
    public struct PathRef: Equatable, Sendable {
        public let hostPath: String
        public let guestPath: String

        public init(hostPath: String, guestPath: String) {
            self.hostPath = hostPath
            self.guestPath = guestPath
        }
    }

    /// A candidate that was NOT mounted, and why — surfaced so the runner can
    /// warn about the cases worth a warning (sensitive, home-root).
    public struct Skipped: Equatable, Sendable {
        public let path: String
        public let reason: Reason

        public enum Reason: String, Equatable, Sendable {
            /// The path doesn't exist on the host (probably a guest-only path).
            case missing
            /// Mounting would require exposing the whole home directory.
            case homeRoot
            /// The source resolves under a sensitive prefix (~/.ssh, ~/.aws, …).
            case sensitive
        }

        public init(path: String, reason: Reason) {
            self.path = path
            self.reason = reason
        }
    }

    /// The outcome of resolving a set of refs: the mounts to add plus the
    /// candidates that were skipped.
    public struct Resolution: Equatable, Sendable {
        public var specs: [Config.MountSpec]
        public var skipped: [Skipped]

        public init(specs: [Config.MountSpec] = [], skipped: [Skipped] = []) {
            self.specs = specs
            self.skipped = skipped
        }
    }

    // MARK: - Extraction

    /// All hook command strings in a Claude settings JSON. The `hooks` section
    /// maps event names to matcher groups, each holding `hooks` entries of
    /// `{"type": "command", "command": "…"}` (a missing `type` means command).
    /// Tolerant: malformed JSON or unexpected shapes yield an empty list.
    public static func hookCommands(inSettingsJSON data: Data) -> [String] {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let hooks = root["hooks"] as? [String: Any]
        else { return [] }
        var commands: [String] = []
        for (_, value) in hooks.sorted(by: { $0.key < $1.key }) {
            guard let groups = value as? [[String: Any]] else { continue }
            for group in groups {
                guard let entries = group["hooks"] as? [[String: Any]] else { continue }
                for entry in entries {
                    let type = entry["type"] as? String ?? "command"
                    guard type == "command",
                        let command = entry["command"] as? String,
                        !command.isEmpty
                    else { continue }
                    commands.append(command)
                }
            }
        }
        return commands
    }

    /// The path references a hook command makes, mapped to their guest-side
    /// resolution (see the type-level rules). Tokenizes quote-aware, trims shell
    /// glue (`;`, `&`, `|`, parens) off token edges, and keeps only tokens that
    /// look like host paths: `~/…`, `$HOME/…`, `${HOME}/…`, or absolute. Tokens
    /// under `$CLAUDE_PROJECT_DIR` resolve inside the already-mounted
    /// workspace, so they are dropped here.
    public static func pathRefs(
        inCommand command: String, hostHome: String, guestHome: String
    ) -> [PathRef] {
        var refs: [PathRef] = []
        for raw in tokenize(command) {
            let token = raw.trimmingCharacters(in: CharacterSet(charactersIn: ";&|()"))
            guard !token.isEmpty else { continue }
            let rest: String?
            if token.hasPrefix("~/") {
                rest = String(token.dropFirst(2))
            } else if token.hasPrefix("$HOME/") {
                rest = String(token.dropFirst("$HOME/".count))
            } else if token.hasPrefix("${HOME}/") {
                rest = String(token.dropFirst("${HOME}/".count))
            } else {
                rest = nil
            }
            if let rest {
                refs.append(
                    PathRef(
                        hostPath: hostHome + "/" + rest,
                        guestPath: guestHome + "/" + rest))
                continue
            }
            if token.hasPrefix("/") {
                refs.append(PathRef(hostPath: token, guestPath: token))
            }
        }
        return refs
    }

    /// Split a command on whitespace, honoring single/double quotes so a quoted
    /// path with spaces stays one token (quotes are stripped from the result).
    static func tokenize(_ command: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var quote: Character?
        for ch in command {
            if let q = quote {
                if ch == q { quote = nil } else { current.append(ch) }
            } else if ch == "\"" || ch == "'" {
                quote = ch
            } else if ch == " " || ch == "\t" || ch == "\n" {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    // MARK: - Resolution

    /// Turn extracted refs into read-only mount specs, applying the guardrails.
    /// Filesystem access is injected (`exists`/`isDirectory`), as is the
    /// sensitive-source check (the runner symlink-resolves before asking), so
    /// this stays pure and unit-testable.
    public static func resolve(
        refs: [PathRef],
        hostHome: String,
        guestHome: String,
        mountClaudeConfig: Bool,
        alreadyMounted: [Config.MountSpec] = [],
        exists: (String) -> Bool,
        isDirectory: (String) -> Bool,
        isSensitive: (String) -> Bool
    ) -> Resolution {
        var out = Resolution()

        func under(_ path: String, _ prefix: String) -> Bool {
            path == prefix || path.hasPrefix(prefix + "/")
        }
        /// True when an existing mount (the caller's — e.g. the workspace,
        /// mounted at its own host path — or one already selected here) exposes
        /// `host` at `guest`: same relative suffix below a source/destination pair.
        func covered(host: String, guest: String) -> Bool {
            // The mountClaudeConfig share exposes host ~/.claude at guest
            // ~/.claude, so tilde-referenced paths inside it need no extra mount.
            if mountClaudeConfig,
                under(host, hostHome + "/.claude"), under(guest, guestHome + "/.claude"),
                host.dropFirst(hostHome.count) == guest.dropFirst(guestHome.count)
            {
                return true
            }
            return (alreadyMounted + out.specs).contains { spec in
                under(host, spec.source) && under(guest, spec.destination)
                    && host.dropFirst(spec.source.count) == guest.dropFirst(spec.destination.count)
            }
        }

        var seen = Set<String>()
        for ref in refs {
            guard seen.insert(ref.hostPath + "\u{0}" + ref.guestPath).inserted else { continue }
            // Only mirror files under the host home: anything else (e.g.
            // /usr/bin/python3) is an interpreter or system path whose mount
            // would shadow the guest's own directories. Silent — this is
            // classification, not an error.
            guard under(ref.hostPath, hostHome), ref.hostPath != hostHome else { continue }
            guard exists(ref.hostPath) else {
                out.skipped.append(Skipped(path: ref.hostPath, reason: .missing))
                continue
            }
            // Mount the parent directory of a file; a directory mounts itself.
            let dir = isDirectory(ref.hostPath)
            let hostDir = dir ? ref.hostPath : parent(of: ref.hostPath)
            let guestDir = dir ? ref.guestPath : parent(of: ref.guestPath)
            if hostDir == hostHome || guestDir == guestHome {
                out.skipped.append(Skipped(path: ref.hostPath, reason: .homeRoot))
                continue
            }
            if isSensitive(hostDir) {
                out.skipped.append(Skipped(path: ref.hostPath, reason: .sensitive))
                continue
            }
            if covered(host: hostDir, guest: guestDir) { continue }
            out.specs.append(
                Config.MountSpec(
                    source: hostDir, destination: guestDir,
                    readOnly: true))
        }
        return out
    }

    /// Everything before the last path separator (no trailing slash).
    static func parent(of path: String) -> String {
        (path as NSString).deletingLastPathComponent
    }
}
