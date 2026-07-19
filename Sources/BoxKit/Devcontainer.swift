import CryptoKit
import Foundation

/// Project dependencies via a devcontainer: when a project declares its toolchain
/// in `.devcontainer/devcontainer.json` (a Swift base image, a `build.dockerfile`,
/// etc.), box can — with the user's consent — run the agent in a VM built *on top
/// of* that base, so `swift build` / an LSP / whatever the project needs is
/// present in the box.
///
/// Split-proxy shape: the devcontainer base is kept essentially stock — the
/// composed image adds only Claude Code, the agent user, and the client
/// entrypoint (see `box-layers.dockerfile`). squid and its enforcement stack
/// run in a SEPARATE proxy-sidecar VM booted from box's own image (`Runner`
/// wires the two together; the dev VM's egress is iptables-locked to the
/// sidecar). The client image is cached by a content hash of the devcontainer
/// files plus the box-layers template (`box:dc-<sha8>`).
///
/// v1 scope: the devcontainer **base** (`image` / `build.dockerfile`) and
/// `postCreateCommand`. Devcontainer `features` (ghcr.io/devcontainers/*) are out
/// of scope for now — the base image covers the common "add a toolchain" case.
///
/// Everything here is pure (parsing, hashing, Dockerfile composition) so it's
/// unit-testable without a VM. The box **essential-layer fragment** is *injected*
/// by the caller at build time (extracted from `assets/files/Dockerfile`) rather
/// than hardcoded here, so this file never drifts from the real Dockerfile.
public enum Devcontainer {
    /// The parsed subset of `devcontainer.json` box honors in v1.
    public struct Spec: Sendable, Equatable {
        /// A prebuilt base image (`"image"`), if the devcontainer uses one.
        public var image: String?
        /// A `build.dockerfile` path (relative to the devcontainer dir), if it
        /// builds its base from a Dockerfile instead.
        public var dockerfile: String?
        /// Build context (relative), when `dockerfile` is set.
        public var context: String?
        /// `postCreateCommand`, normalized to shell command lines (each becomes a
        /// build-time `RUN` layer — see the semantic note on `dockerfile(...)`).
        public var postCreateCommands: [String]

        public init(
            image: String? = nil, dockerfile: String? = nil, context: String? = nil,
            postCreateCommands: [String] = []
        ) {
            self.image = image
            self.dockerfile = dockerfile
            self.context = context
            self.postCreateCommands = postCreateCommands
        }
    }

    public enum AutoDecision: Sendable, Equatable {
        case devcontainer(consent: Consent)
        case baseWithHint
        case baseWarnMissing
        case base

        public enum Consent: Sendable, Equatable {
            case flag
            case trusted
        }

        public var usesDevcontainer: Bool {
            if case .devcontainer = self { return true }
            return false
        }
    }

    public static func autoDecision(flagged: Bool, detected: Bool, trusted: Bool) -> AutoDecision {
        if flagged {
            return detected ? .devcontainer(consent: .flag) : .baseWarnMissing
        }
        if detected {
            return trusted ? .devcontainer(consent: .trusted) : .baseWithHint
        }
        return .base
    }

    // MARK: - Detection

    /// Locate a project's devcontainer definition, checking the standard
    /// locations: `.devcontainer/devcontainer.json`, a bare `.devcontainer.json`,
    /// and one level of `.devcontainer/<subfolder>/devcontainer.json`. Returns the
    /// first hit, or nil if the project has no devcontainer.
    public static func detect(projectRoot: URL) -> URL? {
        let fm = FileManager.default
        let direct = [
            projectRoot.appendingPathComponent(".devcontainer/devcontainer.json"),
            projectRoot.appendingPathComponent(".devcontainer.json"),
        ]
        for url in direct where fm.fileExists(atPath: url.path) { return url }

        let dcDir = projectRoot.appendingPathComponent(".devcontainer")
        if let subs = try? fm.contentsOfDirectory(
            at: dcDir, includingPropertiesForKeys: [.isDirectoryKey])
        {
            for sub in subs.sorted(by: { $0.path < $1.path }) {
                let candidate = sub.appendingPathComponent("devcontainer.json")
                if fm.fileExists(atPath: candidate.path) { return candidate }
            }
        }
        return nil
    }

    // MARK: - Parsing (JSONC-tolerant)

    /// Parse a `devcontainer.json` (JSONC: allows `//` and `/* */` comments and
    /// trailing commas). Throws `CBError` if it isn't a JSON object.
    public static func parse(_ jsonc: Data) throws -> Spec {
        let cleaned = stripJSONC(String(decoding: jsonc, as: UTF8.self))
        let obj = try JSONSerialization.jsonObject(with: Data(cleaned.utf8))
        guard let dict = obj as? [String: Any] else {
            throw CBError("devcontainer.json is not a JSON object")
        }
        let image = dict["image"] as? String
        var dockerfile: String?
        var context: String?
        if let build = dict["build"] as? [String: Any] {
            dockerfile = (build["dockerfile"] as? String) ?? (build["dockerFile"] as? String)
            context = build["context"] as? String
        }
        // Legacy top-level keys.
        dockerfile = dockerfile ?? (dict["dockerFile"] as? String) ?? (dict["dockerfile"] as? String)
        return Spec(
            image: image, dockerfile: dockerfile, context: context,
            postCreateCommands: normalizeCommand(dict["postCreateCommand"]))
    }

    /// Normalize a devcontainer lifecycle command into shell command lines.
    /// String → one command; array (argv) → one space-joined command; object
    /// (named parallel commands) → each value normalized and flattened.
    static func normalizeCommand(_ value: Any?) -> [String] {
        switch value {
        case let s as String:
            return [s]
        case let arr as [Any]:
            let parts = arr.compactMap { $0 as? String }
            return parts.isEmpty ? [] : [parts.joined(separator: " ")]
        case let map as [String: Any]:
            return map.keys.sorted().flatMap { normalizeCommand(map[$0]) }
        default:
            return []
        }
    }

    /// Strip JSONC comments and trailing commas so `JSONSerialization` accepts it.
    /// String literals (and their escapes) are respected, so `//` or `,` inside a
    /// string is preserved.
    static func stripJSONC(_ s: String) -> String {
        enum State { case normal, string, lineComment, blockComment }
        var state = State.normal
        var escaped = false
        var out: [Character] = []
        let chars = Array(s)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            let next: Character? = i + 1 < chars.count ? chars[i + 1] : nil
            switch state {
            case .normal:
                if c == "\"" {
                    state = .string
                    out.append(c)
                } else if c == "/" && next == "/" {
                    state = .lineComment
                    i += 1
                } else if c == "/" && next == "*" {
                    state = .blockComment
                    i += 1
                } else {
                    out.append(c)
                }
            case .string:
                out.append(c)
                if escaped {
                    escaped = false
                } else if c == "\\" {
                    escaped = true
                } else if c == "\"" {
                    state = .normal
                }
            case .lineComment:
                if c == "\n" {
                    state = .normal
                    out.append(c)
                }
            case .blockComment:
                if c == "*" && next == "/" {
                    state = .normal
                    i += 1
                }
            }
            i += 1
        }
        return removeTrailingCommas(String(out))
    }

    /// Remove commas that immediately precede a `}` or `]` (ignoring whitespace),
    /// which JSONC allows but strict JSON rejects. String-aware.
    static func removeTrailingCommas(_ s: String) -> String {
        let chars = Array(s)
        var keep = [Bool](repeating: true, count: chars.count)
        var inString = false
        var escaped = false
        for (idx, c) in chars.enumerated() {
            if inString {
                if escaped { escaped = false } else if c == "\\" { escaped = true }
                else if c == "\"" { inString = false }
                continue
            }
            if c == "\"" { inString = true; continue }
            if c == "," {
                var j = idx + 1
                while j < chars.count, chars[j] == " " || chars[j] == "\n"
                    || chars[j] == "\t" || chars[j] == "\r"
                {
                    j += 1
                }
                if j < chars.count, chars[j] == "}" || chars[j] == "]" {
                    keep[idx] = false
                }
            }
        }
        return String(chars.enumerated().filter { keep[$0.offset] }.map { $0.element })
    }

    // MARK: - Variant keying + Dockerfile composition

    /// Content-hash tag for the variant image (`dc-<sha8>`), keyed on the
    /// devcontainer file contents (and any referenced Dockerfile). A change to
    /// any input yields a new tag, so the cache and consent both re-trigger.
    public static func variantTag(_ contents: [Data]) -> String {
        var hasher = SHA256()
        for d in contents { hasher.update(data: d) }
        let hex = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return "dc-" + hex.prefix(8)
    }

    /// Placeholder the box-layers template uses for the devcontainer base image.
    public static let basePlaceholder = "__DC_BASE__"

    /// Compose the generated Dockerfile: substitute the devcontainer `base` into
    /// the box-layers `template` (the multi-stage squid build + box layers, shipped
    /// as `assets/files/box-layers.dockerfile`, with `__DC_BASE__` placeholders),
    /// then append a `RUN` per `postCreate` command.
    ///
    /// Semantic note: devcontainer `postCreateCommand` runs *after* container
    /// creation; box's model is build-then-run-immutable, so these become build
    /// `RUN` layers instead. Commands that expect a running workspace/network at
    /// create time won't behave identically — documented for users.
    public static func dockerfile(
        base: String, template: String, postCreate: [String]
    ) -> String {
        var out = template.replacingOccurrences(of: basePlaceholder, with: base)
        if !out.hasSuffix("\n") { out += "\n" }
        for cmd in postCreate {
            out += "\nRUN \(cmd)\n"
        }
        return out
    }
}
