import Foundation
import Testing

@testable import BoxKit

@Suite("Trust.hash / evaluate (pure core)")
struct TrustCoreTests {
    @Test("hash is deterministic and binds both path and contents")
    func hashDeterministicAndBound() {
        let a = Trust.hash(path: "/p/.box/allowlist.txt", contents: ".example.com\n")
        let b = Trust.hash(path: "/p/.box/allowlist.txt", contents: ".example.com\n")
        #expect(a == b)
        // 64 hex chars (sha256).
        #expect(a.count == 64)
        #expect(a.allSatisfy { $0.isHexDigit })
        // Different contents → different hash.
        #expect(Trust.hash(path: "/p/.box/allowlist.txt", contents: ".other.com\n") != a)
        // Same contents, different path → different hash (no cross-repo reuse).
        #expect(Trust.hash(path: "/q/.box/allowlist.txt", contents: ".example.com\n") != a)
    }

    @Test("exact match on both components → both trusted")
    func bothTrustedOnMatch() {
        let aHash = Trust.hash(path: "/p/.box/allowlist.txt", contents: "a")
        let cHash = Trust.hash(path: "/p/.box/config.json", contents: "{}")
        let record = Trust.Record(allowlist: aHash, config: cHash)
        let d = Trust.evaluate(record: record, liveAllowlistHash: aHash, liveConfigHash: cHash)
        #expect(d.allowlistTrusted)
        #expect(d.configTrusted)
    }

    @Test("any hash mismatch fails closed for that component")
    func mismatchFailsClosed() {
        let record = Trust.Record(allowlist: "approved-a", config: "approved-c")
        // allowlist changed, config unchanged.
        let d1 = Trust.evaluate(
            record: record, liveAllowlistHash: "edited-a", liveConfigHash: "approved-c")
        #expect(!d1.allowlistTrusted)
        #expect(d1.configTrusted)
        // config changed (e.g. git pull), allowlist unchanged.
        let d2 = Trust.evaluate(
            record: record, liveAllowlistHash: "approved-a", liveConfigHash: "edited-c")
        #expect(d2.allowlistTrusted)
        #expect(!d2.configTrusted)
    }

    @Test("no record at all → nothing trusted (fail-closed)")
    func missingRecord() {
        let d = Trust.evaluate(record: nil, liveAllowlistHash: "x", liveConfigHash: "y")
        #expect(!d.allowlistTrusted)
        #expect(!d.configTrusted)
    }

    @Test("granular: --allowlist-only records config==nil → config never trusted")
    func allowlistOnlyGranular() {
        let aHash = "approved-a"
        let cHash = "live-c"
        let record = Trust.Record(allowlist: aHash, config: nil)  // allowlist-only approval
        let d = Trust.evaluate(record: record, liveAllowlistHash: aHash, liveConfigHash: cHash)
        #expect(d.allowlistTrusted)
        #expect(!d.configTrusted)  // config was never approved
    }

    @Test("absent live component (nil hash) is never trusted even with a record")
    func absentLiveComponent() {
        let record = Trust.Record(allowlist: "approved-a", config: "approved-c")
        let d = Trust.evaluate(record: record, liveAllowlistHash: nil, liveConfigHash: nil)
        #expect(!d.allowlistTrusted)
        #expect(!d.configTrusted)
    }

    @Test("sensitive-source detection: exact and nested under prefixes")
    func sensitiveSource() {
        let home = "/Users/me"
        #expect(Trust.isSensitiveSource("/Users/me/.ssh", home: home))
        #expect(Trust.isSensitiveSource("/Users/me/.ssh/id_ed25519", home: home))
        #expect(Trust.isSensitiveSource("/Users/me/.aws/credentials", home: home))
        #expect(Trust.isSensitiveSource("/etc/passwd", home: home))
        #expect(Trust.isSensitiveSource("/Users/me/.box/trust/trust.json", home: home))
        // A sibling that merely shares a prefix string but isn't nested is safe.
        #expect(!Trust.isSensitiveSource("/Users/me/.sshconfig", home: home))
        #expect(!Trust.isSensitiveSource("/Users/me/projects/repo", home: home))
        #expect(!Trust.isSensitiveSource("/Users/me/.config/box", home: home))
    }
}

@Suite("Trust store + gating (FS, BOX_DIR temp)", .serialized)
struct TrustStoreTests {
    /// Build a throwaway project tree with a `.box/` containing the given files.
    private func makeProject(allowlist: String?, config: String?) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-trust-\(UUID().uuidString)")
        let boxDir = root.appendingPathComponent("repo/.box")
        try FileManager.default.createDirectory(at: boxDir, withIntermediateDirectories: true)
        if let allowlist {
            try allowlist.write(
                to: boxDir.appendingPathComponent("allowlist.txt"),
                atomically: true, encoding: .utf8)
        }
        if let config {
            try config.write(
                to: boxDir.appendingPathComponent("config.json"),
                atomically: true, encoding: .utf8)
        }
        return root
    }

    @Test("store round-trips a record keyed by project dir")
    func storeRoundTrip() throws {
        try withTempBoxDir { _ in
            let root = try makeProject(allowlist: ".example.com\n", config: "{}")
            defer { try? FileManager.default.removeItem(at: root) }
            let boxDir = root.appendingPathComponent("repo/.box")
            #expect(TrustStore.record(forProjectBoxDir: boxDir) == nil)
            let rec = Trust.Record(allowlist: "a", config: "c")
            try TrustStore.setRecord(rec, forProjectBoxDir: boxDir)
            #expect(TrustStore.record(forProjectBoxDir: boxDir) == rec)
            // Removal.
            try TrustStore.setRecord(nil, forProjectBoxDir: boxDir)
            #expect(TrustStore.record(forProjectBoxDir: boxDir) == nil)
        }
    }

    @Test("discover + evaluate: untrusted by default, trusted after recording live hashes")
    func gatingFlow() throws {
        try withTempBoxDir { _ in
            let root = try makeProject(allowlist: ".example.com\n", config: "{\"cpus\":2}\n")
            defer { try? FileManager.default.removeItem(at: root) }
            let cwd = root.appendingPathComponent("repo")

            // Default: nothing trusted (fail-closed) even though files exist.
            let d0 = ProjectTrust.evaluate(cwd: cwd)
            #expect(!d0.allowlistTrusted)
            #expect(!d0.configTrusted)

            // Record the live hashes (what `box trust` does).
            let discovered = try #require(ProjectTrust.discover(cwd: cwd))
            let rec = Trust.Record(
                allowlist: discovered.allowlistHash, config: discovered.configHash)
            try TrustStore.setRecord(rec, forProjectBoxDir: discovered.boxDir)

            let d1 = ProjectTrust.evaluate(cwd: cwd)
            #expect(d1.allowlistTrusted)
            #expect(d1.configTrusted)
        }
    }

    @Test("editing a component after trust re-blocks it (fail-closed)")
    func editInvalidates() throws {
        try withTempBoxDir { _ in
            let root = try makeProject(allowlist: ".example.com\n", config: "{}\n")
            defer { try? FileManager.default.removeItem(at: root) }
            let cwd = root.appendingPathComponent("repo")
            let boxDir = root.appendingPathComponent("repo/.box")

            let d = try #require(ProjectTrust.discover(cwd: cwd))
            try TrustStore.setRecord(
                Trust.Record(allowlist: d.allowlistHash, config: d.configHash),
                forProjectBoxDir: boxDir)
            #expect(ProjectTrust.evaluate(cwd: cwd).allowlistTrusted)

            // Simulate a `git pull` / edit: change the allowlist content.
            try ".evil.com\n".write(
                to: boxDir.appendingPathComponent("allowlist.txt"),
                atomically: true, encoding: .utf8)
            let after = ProjectTrust.evaluate(cwd: cwd)
            #expect(!after.allowlistTrusted)  // hash changed → re-blocked
            #expect(after.configTrusted)  // config unchanged → still trusted
        }
    }

    @Test("allowlist-only trust: config stays untrusted")
    func allowlistOnlyStoreFlow() throws {
        try withTempBoxDir { _ in
            let root = try makeProject(allowlist: ".example.com\n", config: "{\"cpus\":2}\n")
            defer { try? FileManager.default.removeItem(at: root) }
            let cwd = root.appendingPathComponent("repo")
            let d = try #require(ProjectTrust.discover(cwd: cwd))
            // Record allowlist only (config: nil), mirroring `box trust --allowlist-only`.
            try TrustStore.setRecord(
                Trust.Record(allowlist: d.allowlistHash, config: nil),
                forProjectBoxDir: d.boxDir)
            let decision = ProjectTrust.evaluate(cwd: cwd)
            #expect(decision.allowlistTrusted)
            #expect(!decision.configTrusted)
        }
    }

    @Test("no project .box/ → discover returns nil and nothing is trusted")
    func noProject() throws {
        try withTempBoxDir { _ in
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("box-noproj-\(UUID().uuidString)")
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent("repo/src"), withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let cwd = root.appendingPathComponent("repo/src")
            #expect(ProjectTrust.discover(cwd: cwd) == nil)
            let d = ProjectTrust.evaluate(cwd: cwd)
            #expect(!d.allowlistTrusted)
            #expect(!d.configTrusted)
        }
    }

    @Test("allowlist present, config absent: only allowlist can be trusted")
    func allowlistOnlyFilePresent() throws {
        try withTempBoxDir { _ in
            let root = try makeProject(allowlist: ".example.com\n", config: nil)
            defer { try? FileManager.default.removeItem(at: root) }
            let cwd = root.appendingPathComponent("repo")
            let d = try #require(ProjectTrust.discover(cwd: cwd))
            #expect(d.allowlistHash != nil)
            #expect(d.configHash == nil)
            try TrustStore.setRecord(
                Trust.Record(allowlist: d.allowlistHash, config: d.configHash),
                forProjectBoxDir: d.boxDir)
            let decision = ProjectTrust.evaluate(cwd: cwd)
            #expect(decision.allowlistTrusted)
            #expect(!decision.configTrusted)  // no config file at all
        }
    }
}
