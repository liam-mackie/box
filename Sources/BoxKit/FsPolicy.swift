import Foundation

/// Pure model for the dynamic filesystem-visibility policy — the live-toggle
/// analog of the egress allowlist, applied to the broad read-only roots.
///
/// ## What this controls (and what it does NOT)
///
/// Each `readOnlyRoots` entry is mounted read-only at a HIDDEN guest path
/// (`/mnt/.roots/<basename>`) at VM-create time. The agent never sees that path;
/// its working view lives at `/mnt/<basename>`, which the entrypoint (running as
/// root, before dropping to the agent) builds out of bind-mounts of ONLY the
/// allowed subpaths of the hidden root. A host edit to `fs-policy.txt` is picked
/// up by a 2s guest poll, which re-runs the carve.
///
/// This is **visibility control, not a hard security boundary**:
///  - An already-open file descriptor survives a `umount` — the reconcile uses a
///    lazy unmount (`umount -l`) and accepts the race for a file open across the
///    moment a deny lands.
///  - There is a ≤2s window between a host `fs-deny` and the carve taking effect.
///  - A brand-new host root cannot appear live (Containerization 0.33.1 cannot
///    hot-plug a mount); adding one needs a box restart. For real secrets,
///    exclude them at create time via a scoped `readOnlyRoots`.
///
/// ## Policy file format (`fs-policy.txt`)
///
/// One rule per line; `#` comments and blanks ignored:
///   - `allow <path>`  — make `<path>` (a subpath of some root) visible
///   - `deny  <path>`  — hide `<path>`
/// A bare path with no verb is treated as `deny` (the common case: "hide this").
/// Paths are guest-absolute (`/mnt/<basename>/…`) — the same paths the agent
/// sees — and are normalized (collapse `//`, strip trailing `/`, drop `.`
/// segments; `..` is rejected so a rule can't escape its root).
///
/// ## Default policy (DECISION: allow-the-whole-root, deny subtracts)
///
/// With NO rule touching a given root, the whole root is visible — identical to
/// today's behavior (least surprise). A `deny` under a root switches that root
/// into "carve" mode: everything stays visible EXCEPT the denied subtrees. An
/// `allow` only matters once something under the same root has been denied (it
/// re-exposes a subpath inside a denied subtree, or names a specific child to
/// keep). The most-specific (longest-prefix) matching rule wins, so
/// `deny /mnt/g/secret` + `allow /mnt/g/secret/public` hides everything under
/// `secret` except `public`.
public enum FsPolicy {
    /// One parsed rule: a verb plus a normalized guest-absolute path.
    public struct Rule: Equatable, Sendable {
        public enum Verb: String, Equatable, Sendable { case allow, deny }
        public let verb: Verb
        public let path: String
        public init(verb: Verb, path: String) {
            self.verb = verb
            self.path = path
        }
    }

    // MARK: - Parse / serialize

    /// Parse `fs-policy.txt` text into rules, dropping blanks, comments, and any
    /// line whose path fails normalization (e.g. contains `..` or isn't absolute).
    /// A bare path (no verb) is treated as `deny`.
    public static func parse(_ text: String) -> [Rule] {
        var rules: [Rule] = []
        for rawLine in text.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(
                separator: " ", maxSplits: 1,
                omittingEmptySubsequences: true
            ).map(String.init)
            let verb: Rule.Verb
            let rawPath: String
            if parts.count == 2, let v = Rule.Verb(rawValue: parts[0].lowercased()) {
                verb = v
                rawPath = parts[1].trimmingCharacters(in: .whitespaces)
            } else {
                // Bare path (or an unrecognized first token treated as part of the
                // path): default to deny — "hide this" is the common ask.
                verb = .deny
                rawPath = line
            }
            guard let norm = normalize(rawPath) else { continue }
            rules.append(Rule(verb: verb, path: norm))
        }
        return rules
    }

    /// Serialize rules back to file text (one `verb path` per line, sorted by
    /// path then verb for a stable diff). Used by `box fs-allow`/`fs-deny`.
    public static func serialize(_ rules: [Rule]) -> String {
        let sorted = canonicalOrder(rules)
        return sorted.map { "\($0.verb.rawValue) \($0.path)" }.joined(separator: "\n")
            + (sorted.isEmpty ? "" : "\n")
    }

    /// Stable order for a clean file diff: by path, then verb.
    static func canonicalOrder(_ rules: [Rule]) -> [Rule] {
        rules.sorted {
            $0.path == $1.path ? $0.verb.rawValue < $1.verb.rawValue : $0.path < $1.path
        }
    }

    // MARK: - Merge (the `box fs-allow`/`fs-deny` edit)

    /// Result of folding a new rule into an existing rule set.
    public struct MergeResult: Equatable, Sendable {
        public let rules: [Rule]
        /// True if `rules` differs from the input (so the caller knows to write).
        public let changed: Bool
        /// Human-readable note about what happened (for the CLI to print).
        public let note: String

        public init(rules: [Rule], changed: Bool, note: String) {
            self.rules = rules
            self.changed = changed
            self.note = note
        }
    }

    /// Fold `verb path` into `existing`, returning the new rule set.
    ///
    /// A path carries at most one verb: setting `allow` on a path that was
    /// `deny` (or vice-versa) REPLACES it (toggling visibility), rather than
    /// stacking a contradictory pair. Re-issuing the same rule is a no-op.
    /// `path` is normalized; an un-normalizable path yields an unchanged result
    /// with an explanatory note.
    public static func merge(existing: [Rule], verb: Rule.Verb, path: String) -> MergeResult {
        guard let norm = normalize(path) else {
            return MergeResult(
                rules: existing, changed: false,
                note: "ignored \(verb.rawValue) \(path): not a normalizable absolute path")
        }
        let priorVerb = existing.first { $0.path == norm }?.verb
        if priorVerb == verb {
            return MergeResult(
                rules: existing, changed: false, note: "already \(verb.rawValue): \(norm)")
        }
        // Keep a single verb per path: drop any prior rule for this exact path.
        var out = existing.filter { $0.path != norm }
        out.append(Rule(verb: verb, path: norm))
        out = canonicalOrder(out)
        let note =
            priorVerb == nil
            ? "\(verb.rawValue): \(norm)"
            : "changed \(priorVerb!.rawValue) → \(verb.rawValue): \(norm)"
        return MergeResult(rules: out, changed: true, note: note)
    }

    // MARK: - Reconciliation (policy + available subpaths → bind-mount sources)

    /// Decision for one root: which guest-source paths (under the hidden
    /// `/mnt/.roots/<basename>` tree) to bind-mount into the agent's view at
    /// `/mnt/<basename>`, expressed RELATIVE to the root (e.g. `""` means "bind
    /// the whole root", `"a/b"` means "bind only `<root>/a/b`").
    public struct RootDecision: Equatable, Sendable {
        /// Relative subpaths to expose. `[""]` means the whole root is visible
        /// (the default when nothing under it is denied). An empty array means
        /// the root is fully hidden.
        public let exposed: [String]
        public init(exposed: [String]) { self.exposed = exposed }
    }

    /// Given the rules and the children that actually exist under a root, decide
    /// which (relative) subpaths to bind-mount so the agent sees exactly the
    /// allowed view.
    ///
    /// `rootMount` is the agent-facing mount point (`/mnt/<basename>`); rules are
    /// matched against it. `listChildren` returns the immediate child names of a
    /// guest path — called only for directories we must descend into, so we carve
    /// at top level and recurse only where a rule reaches deeper.
    ///
    /// Algorithm (allow-default, deny-subtracts, longest-prefix wins):
    ///  - If NO rule's path is at or under `rootMount`, expose the whole root
    ///    (`[""]`) — today's behavior.
    ///  - Otherwise walk the tree implied by the rule paths. For each node, the
    ///    most-specific rule covering it decides allow/deny; unruled nodes inherit
    ///    their parent's decision (root default = allow). We expose the maximal
    ///    subtrees that are allowed and contain no deeper deny, and individually
    ///    expose allowed children of a denied directory.
    public static func reconcile(
        rootMount: String, rules: [Rule],
        listChildren: (String) -> [String]
    ) -> RootDecision {
        let root = normalize(rootMount) ?? rootMount
        // Rules that apply to this root (path == root or a descendant of root).
        let scoped = rules.filter { isAtOrUnder($0.path, root: root) }
        guard !scoped.isEmpty else { return RootDecision(exposed: [""]) }

        var exposed: [String] = []
        carve(
            path: root, root: root, defaultAllow: true, rules: scoped,
            listChildren: listChildren, into: &exposed)
        return RootDecision(exposed: exposed.sorted())
    }

    /// Recursively carve one directory: emit the relative path if the whole
    /// subtree is allowed with no deeper deny; otherwise descend into children.
    private static func carve(
        path: String, root: String, defaultAllow: Bool,
        rules: [Rule], listChildren: (String) -> [String],
        into exposed: inout [String]
    ) {
        let allowedHere = decision(for: path, rules: rules, default: defaultAllow)
        // Does any rule target something strictly BELOW this path? If not, this
        // node is a leaf decision: expose it (relative) iff allowed.
        let hasDeeperRule = rules.contains { isStrictlyUnder($0.path, parent: path) }
        if !hasDeeperRule {
            if allowedHere { exposed.append(relative(path, root: root)) }
            return
        }
        // A deeper rule exists → look at children individually. Each inherits
        // `allowedHere` unless a rule overrides it. Children with no rule at/under
        // them collapse back to a whole-subtree bind via the leaf branch above.
        for child in listChildren(path).sorted() {
            let childPath = path == "/" ? "/\(child)" : "\(path)/\(child)"
            carve(
                path: childPath, root: root, defaultAllow: allowedHere,
                rules: rules, listChildren: listChildren, into: &exposed)
        }
    }

    /// The effective allow/deny for `path`: the verb of the longest rule path
    /// that is a prefix of (or equal to) `path`; else `default`.
    private static func decision(for path: String, rules: [Rule], default def: Bool) -> Bool {
        var best: Rule?
        for r in rules where isAtOrUnder(path, root: r.path) {
            if best == nil || r.path.count > best!.path.count { best = r }
        }
        guard let best else { return def }
        return best.verb == .allow
    }

    // MARK: - Path helpers

    /// Normalize a guest-absolute path: require a leading `/`, collapse repeated
    /// slashes, drop `.` segments and trailing slashes, and REJECT (`nil`) any
    /// `..` segment so a rule can't escape upward out of its root.
    public static func normalize(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("/") else { return nil }
        var out: [String] = []
        for seg in trimmed.split(separator: "/", omittingEmptySubsequences: true) {
            let s = String(seg)
            if s == "." { continue }
            if s == ".." { return nil }
            out.append(s)
        }
        return "/" + out.joined(separator: "/")
    }

    /// Is `path` equal to `root`, or a descendant of it? Both must already be
    /// normalized. `/` is a parent of everything.
    static func isAtOrUnder(_ path: String, root: String) -> Bool {
        if path == root { return true }
        if root == "/" { return path.hasPrefix("/") }
        return path.hasPrefix(root + "/")
    }

    /// Is `path` strictly below `parent` (a descendant, not equal)?
    static func isStrictlyUnder(_ path: String, parent: String) -> Bool {
        path != parent && isAtOrUnder(path, root: parent)
    }

    /// Express `path` relative to `root` (root itself → "").
    static func relative(_ path: String, root: String) -> String {
        if path == root { return "" }
        let prefix = root == "/" ? "/" : root + "/"
        return String(path.dropFirst(prefix.count))
    }
}
