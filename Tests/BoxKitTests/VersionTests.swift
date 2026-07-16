import Foundation
import Testing

@testable import BoxKit

@Suite("buildArg token assembly (pure, no docker)")
struct BuildArgTests {
    @Test("flattens key/value pairs into --build-arg tokens in order")
    func tokens() {
        #expect(buildArgTokens([]) == [])
        #expect(
            buildArgTokens([("CLAUDE_VERSION", "latest")])
                == ["--build-arg", "CLAUDE_VERSION=latest"])
        #expect(
            buildArgTokens([("A", "1"), ("B", "2")])
                == ["--build-arg", "A=1", "--build-arg", "B=2"])
    }

    @Test("claudeBuildArgs defaults to latest")
    func claudeDefault() {
        #expect(claudeBuildArgs(to: nil) == ["--build-arg", "CLAUDE_VERSION=latest"])
    }

    @Test("claudeBuildArgs passes a pinned version through")
    func claudePinned() {
        #expect(claudeBuildArgs(to: "1.2.3") == ["--build-arg", "CLAUDE_VERSION=1.2.3"])
    }
}

@Suite("host claude version parsing + ordering (pure)")
struct ClaudeVersionSyncTests {
    @Test("extracts the semver from `claude --version` output")
    func parsesVersionOutput() {
        #expect(Version.parseClaudeVersionOutput("2.1.211 (Claude Code)") == "2.1.211")
        #expect(Version.parseClaudeVersionOutput("2.1.211\n") == "2.1.211")
        #expect(Version.parseClaudeVersionOutput("1.0.0-beta.1 (Claude Code)") == "1.0.0-beta.1")
    }

    @Test("returns nil for output with no version token")
    func rejectsGarbage() {
        #expect(Version.parseClaudeVersionOutput("") == nil)
        #expect(Version.parseClaudeVersionOutput("command not found") == nil)
        #expect(Version.parseClaudeVersionOutput("(Claude Code)") == nil)
    }

    @Test("orders versions numerically, not lexically")
    func numericOrdering() {
        #expect(Version.isOlder("2.1.159", than: "2.1.211"))
        #expect(!Version.isOlder("2.1.211", than: "2.1.159"))
        #expect(Version.isOlder("2.1.9", than: "2.1.10"))  // lexical would say newer
        #expect(Version.isOlder("1.9.9", than: "2.0.0"))
        #expect(!Version.isOlder("2.1.211", than: "2.1.211"))
    }

    @Test("missing components count as zero; garbage is never 'older'")
    func toleratesShapes() {
        #expect(Version.isOlder("2.1", than: "2.1.1"))
        #expect(!Version.isOlder("2.1.0", than: "2.1"))
        #expect(!Version.isOlder("unknown", than: "unknown"))
    }
}

/// Serialized: these set the process-global BOX_DIR, so they must not run
/// concurrently with each other (mirrors AssetsTests). The shared
/// `withTempBoxDir` (BoxDirLock.swift) also serializes against other BOX_DIR suites.
@Suite("Sidecar round-trip + Version assembly", .serialized)
struct VersionTests {
    @Test("sidecar JSON survives a write/read round-trip")
    func sidecarRoundTrip() throws {
        try withTempBoxDir { _ in
            let original = Sidecar(claudeCode: "1.2.3", claudeRequested: "latest")
            try original.write()
            let read = try #require(Sidecar.read())
            #expect(read == original)
            #expect(read.claudeCode == "1.2.3")
            #expect(read.claudeRequested == "latest")
        }
    }

    @Test("sidecar file lives at Box.dir/image.json")
    func sidecarPath() throws {
        try withTempBoxDir { dir in
            try Sidecar(claudeCode: "9.9.9").write()
            #expect(Sidecar.fileURL.path == dir.appendingPathComponent("image.json").path)
            #expect(FileManager.default.fileExists(atPath: Sidecar.fileURL.path))
        }
    }

    @Test("read returns nil when the sidecar is absent")
    func sidecarAbsent() throws {
        try withTempBoxDir { _ in
            #expect(Sidecar.read() == nil)
        }
    }

    @Test("read tolerates corrupt sidecar JSON (returns nil)")
    func sidecarCorrupt() throws {
        try withTempBoxDir { _ in
            try FileManager.default.createDirectory(
                at: Box.dir, withIntermediateDirectories: true)
            try "not json".write(to: Sidecar.fileURL, atomically: true, encoding: .utf8)
            #expect(Sidecar.read() == nil)
        }
    }

    @Test("version info reports the cached claude-code version")
    func assemblesFromSidecar() throws {
        try withTempBoxDir { _ in
            try Sidecar(claudeCode: "1.2.3").write()
            let info = Version.all(refresh: false)
            #expect(info.claudeCode == "1.2.3")
            // box / containerization / vminit are populated (don't assert exact strings).
            #expect(!info.box.isEmpty)
            #expect(info.containerization == Version.containerization)
            #expect(info.vminit == Box.vminitRef)
        }
    }

    @Test("refresh annotates the cached value without booting a VM")
    func refreshAnnotatesCached() throws {
        try withTempBoxDir { _ in
            try Sidecar(claudeCode: "1.2.3").write()
            let info = Version.all(refresh: true)
            #expect(info.claudeCode.contains("1.2.3"))
            #expect(info.claudeCode.contains("cached"))
        }
    }

    @Test("missing sidecar yields an 'unknown' claude-code marker, not a crash")
    func unknownWhenAbsent() throws {
        try withTempBoxDir { _ in
            let info = Version.all(refresh: false)
            #expect(info.claudeCode.contains("unknown"))
            #expect(!info.box.isEmpty)
        }
    }
}
