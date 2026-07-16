import Foundation
import Testing

@testable import BoxKit

/// Pure dynamic-filesystem-visibility policy: parse/merge/serialize the
/// fs-policy entries and decide the bind-mount sources for a reconcile. No VM,
/// no real filesystem — children are supplied by a closure.
@Suite("FsPolicy parse/merge/serialize (pure)")
struct FsPolicyModelTests {
    // MARK: - parse

    @Test("parses allow/deny verbs and normalizes paths")
    func parsesVerbs() {
        let rules = FsPolicy.parse(
            """
            allow /mnt/g/a
            deny /mnt/g/b
            """)
        #expect(
            rules == [
                .init(verb: .allow, path: "/mnt/g/a"),
                .init(verb: .deny, path: "/mnt/g/b"),
            ])
    }

    @Test("a bare path (no verb) defaults to deny")
    func bareIsDeny() {
        #expect(FsPolicy.parse("/mnt/g/secret") == [.init(verb: .deny, path: "/mnt/g/secret")])
    }

    @Test("ignores blanks and # comments")
    func ignoresBlanksComments() {
        let rules = FsPolicy.parse(
            """
            # a comment
            deny /mnt/g/x

               # indented comment
            allow /mnt/g/y
            """)
        #expect(
            rules == [
                .init(verb: .deny, path: "/mnt/g/x"),
                .init(verb: .allow, path: "/mnt/g/y"),
            ])
    }

    @Test("normalizes // and trailing slashes and . segments")
    func normalizesPaths() {
        let rules = FsPolicy.parse("deny /mnt//g/./sub/\n")
        #expect(rules == [.init(verb: .deny, path: "/mnt/g/sub")])
    }

    @Test("drops non-absolute paths and any path containing ..")
    func dropsUnsafePaths() {
        let rules = FsPolicy.parse(
            """
            deny relative/path
            deny /mnt/g/../etc
            allow /mnt/g/ok
            """)
        // Only the safe absolute rule survives.
        #expect(rules == [.init(verb: .allow, path: "/mnt/g/ok")])
    }

    @Test("verb tokens are case-insensitive")
    func verbCaseInsensitive() {
        #expect(FsPolicy.parse("DENY /mnt/g/x") == [.init(verb: .deny, path: "/mnt/g/x")])
        #expect(FsPolicy.parse("Allow /mnt/g/y") == [.init(verb: .allow, path: "/mnt/g/y")])
    }

    // MARK: - serialize / round-trip

    @Test("serialize is sorted by path then verb and round-trips")
    func serializeRoundTrips() {
        let rules: [FsPolicy.Rule] = [
            .init(verb: .allow, path: "/mnt/g/secret/public"),
            .init(verb: .deny, path: "/mnt/g/secret"),
        ]
        let text = FsPolicy.serialize(rules)
        #expect(text == "deny /mnt/g/secret\nallow /mnt/g/secret/public\n")
        #expect(FsPolicy.parse(text) == FsPolicy.canonicalOrder(rules))
    }

    @Test("empty rules serialize to empty string")
    func serializeEmpty() {
        #expect(FsPolicy.serialize([]).isEmpty)
    }

    // MARK: - merge

    @Test("merge adds a new deny rule")
    func mergeAddsDeny() {
        let r = FsPolicy.merge(existing: [], verb: .deny, path: "/mnt/g/secret")
        #expect(r.changed)
        #expect(r.rules == [.init(verb: .deny, path: "/mnt/g/secret")])
    }

    @Test("merge dedups an identical rule (no change)")
    func mergeDedups() {
        let existing: [FsPolicy.Rule] = [.init(verb: .deny, path: "/mnt/g/secret")]
        let r = FsPolicy.merge(existing: existing, verb: .deny, path: "/mnt/g/secret")
        #expect(!r.changed)
        #expect(r.rules == existing)
        #expect(r.note.contains("already"))
    }

    @Test("merge toggling a path REPLACES the verb (deny→allow), not stacking")
    func mergeToggles() {
        let existing: [FsPolicy.Rule] = [.init(verb: .deny, path: "/mnt/g/secret")]
        let r = FsPolicy.merge(existing: existing, verb: .allow, path: "/mnt/g/secret")
        #expect(r.changed)
        // Single verb per path: only the allow remains.
        #expect(r.rules == [.init(verb: .allow, path: "/mnt/g/secret")])
        #expect(r.note.contains("changed"))
    }

    @Test("merge normalizes the incoming path before comparing")
    func mergeNormalizes() {
        let existing: [FsPolicy.Rule] = [.init(verb: .deny, path: "/mnt/g/secret")]
        // Same path, written with a trailing slash + double slash → matches.
        let r = FsPolicy.merge(existing: existing, verb: .deny, path: "/mnt//g/secret/")
        #expect(!r.changed)
    }

    @Test("merge rejects an unsafe path without changing the set")
    func mergeRejectsUnsafe() {
        let existing: [FsPolicy.Rule] = [.init(verb: .deny, path: "/mnt/g/x")]
        let r = FsPolicy.merge(existing: existing, verb: .deny, path: "../escape")
        #expect(!r.changed)
        #expect(r.rules == existing)
        #expect(r.note.contains("ignored"))
    }

    @Test("a deny under an allowed root is represented as a single deny rule")
    func denyUnderAllowedRoot() {
        // The root has no allow rule (it's allowed by default); a deny under it
        // is just one deny entry — the subtraction is resolved at reconcile time.
        let r = FsPolicy.merge(existing: [], verb: .deny, path: "/mnt/g/secret/private")
        #expect(r.rules == [.init(verb: .deny, path: "/mnt/g/secret/private")])
    }

    // MARK: - normalize edge cases

    @Test("normalize root path stays /")
    func normalizeRoot() {
        #expect(FsPolicy.normalize("/") == "/")
        #expect(FsPolicy.normalize("///") == "/")
    }

    @Test("normalize rejects relative and .. paths")
    func normalizeRejects() {
        #expect(FsPolicy.normalize("relative") == nil)
        #expect(FsPolicy.normalize("/a/../b") == nil)
        #expect(FsPolicy.normalize("") == nil)
    }
}

/// Pure reconciliation: given a policy and the available children under a root,
/// decide which (relative) subpaths to bind-mount into the agent's view.
@Suite("FsPolicy.reconcile (pure)")
struct FsPolicyReconcileTests {
    // A fixed fake tree under /mnt/g:
    //   repoA/src, repoB, secret/public, secret/private
    let tree: [String: [String]] = [
        "/mnt/g": ["repoA", "repoB", "secret"],
        "/mnt/g/repoA": ["src"],
        "/mnt/g/repoA/src": [],
        "/mnt/g/repoB": [],
        "/mnt/g/secret": ["public", "private"],
        "/mnt/g/secret/public": [],
        "/mnt/g/secret/private": [],
    ]
    func children(_ p: String) -> [String] { tree[p] ?? [] }

    @Test("no rules → expose the whole root (today's behavior)")
    func noRulesWholeRoot() {
        let d = FsPolicy.reconcile(rootMount: "/mnt/g", rules: [], listChildren: children)
        #expect(d.exposed == [""])
    }

    @Test("rules for a DIFFERENT root don't carve this one")
    func otherRootIgnored() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [.init(verb: .deny, path: "/mnt/other/x")],
            listChildren: children)
        #expect(d.exposed == [""])
    }

    @Test("deny a leaf subtree → expose siblings + the allowed parts")
    func denyLeaf() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [.init(verb: .deny, path: "/mnt/g/secret/private")],
            listChildren: children)
        // repoA, repoB stay whole; secret descends, exposing only public.
        #expect(d.exposed == ["repoA", "repoB", "secret/public"])
    }

    @Test("deny then allow inside (longest-prefix) re-exposes the allowed child")
    func denyThenAllow() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [
                .init(verb: .deny, path: "/mnt/g/secret"),
                .init(verb: .allow, path: "/mnt/g/secret/public"),
            ],
            listChildren: children)
        #expect(d.exposed == ["repoA", "repoB", "secret/public"])
    }

    @Test("deny the whole root → nothing exposed")
    func denyWholeRoot() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [.init(verb: .deny, path: "/mnt/g")],
            listChildren: children)
        #expect(d.exposed.isEmpty)
    }

    @Test("deny a directory whose only child is also denied")
    func denyDeepOnlyChild() {
        // repoA's only child is src; denying src leaves repoA empty (nothing under
        // repoA exposed), repoB + secret stay whole.
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [.init(verb: .deny, path: "/mnt/g/repoA/src")],
            listChildren: children)
        #expect(d.exposed == ["repoB", "secret"])
    }

    @Test("deny whole root but allow one subtree back")
    func denyRootAllowSubtree() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g",
            rules: [
                .init(verb: .deny, path: "/mnt/g"),
                .init(verb: .allow, path: "/mnt/g/repoB"),
            ],
            listChildren: children)
        #expect(d.exposed == ["repoB"])
    }

    @Test("rootMount with trailing slash is normalized before matching")
    func rootMountNormalized() {
        let d = FsPolicy.reconcile(
            rootMount: "/mnt/g/",
            rules: [.init(verb: .deny, path: "/mnt/g/secret/private")],
            listChildren: children)
        #expect(d.exposed == ["repoA", "repoB", "secret/public"])
    }
}

/// Filesystem wrapper: `box fs-allow`/`fs-deny` edit the host policy file under
/// `Box.configDir` (which is mounted at /etc/box), and `fs-policy` reads it back.
@Suite("Commands fs-policy (filesystem wrapper)")
struct FsPolicyCommandTests {
    @Test("Box.fsPolicy is under Box.configDir (so it rides the /etc/box mount)")
    func policyUnderConfigDir() throws {
        try withTempBoxDir { _ in
            #expect(Box.fsPolicy.deletingLastPathComponent().path == Box.configDir.path)
            #expect(Box.fsPolicy.lastPathComponent == "fs-policy.txt")
        }
    }

    @Test("fs-deny then fs-allow writes a normalized, toggling policy file")
    func denyThenAllowWritesFile() throws {
        try withTempBoxDir { _ in
            try Commands.editFsPolicy(verb: .deny, path: "/mnt/g/secret/")
            var text = try String(contentsOf: Box.fsPolicy, encoding: .utf8)
            #expect(text == "deny /mnt/g/secret\n")

            // Allowing the same path replaces the verb (single verb per path).
            try Commands.editFsPolicy(verb: .allow, path: "/mnt/g/secret")
            text = try String(contentsOf: Box.fsPolicy, encoding: .utf8)
            #expect(text == "allow /mnt/g/secret\n")
        }
    }

    @Test("an unsafe path is not written")
    func unsafeNotWritten() throws {
        try withTempBoxDir { _ in
            try Commands.editFsPolicy(verb: .deny, path: "../escape")
            #expect(!FileManager.default.fileExists(atPath: Box.fsPolicy.path))
        }
    }
}
