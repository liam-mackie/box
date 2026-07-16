import Foundation
import Testing

@testable import BoxKit

@Suite("EnvInjection (pure)")
struct EnvInjectionTests {
    // MARK: - dotenv parsing

    @Test("parses simple KEY=VALUE lines")
    func parsesSimple() {
        let env = EnvInjection.parseDotenv("FOO=bar\nBAZ=qux")
        #expect(env == ["FOO": "bar", "BAZ": "qux"])
    }

    @Test("ignores blank lines and # comments")
    func ignoresBlanksAndComments() {
        let text = """
            # a comment
            FOO=bar

               # indented comment
            BAZ=qux
            """
        #expect(EnvInjection.parseDotenv(text) == ["FOO": "bar", "BAZ": "qux"])
    }

    @Test("splits on the first = so values may contain =")
    func splitsOnFirstEquals() {
        let env = EnvInjection.parseDotenv("URL=https://x/y?a=1&b=2")
        #expect(env["URL"] == "https://x/y?a=1&b=2")
    }

    @Test("trims surrounding whitespace on key and value")
    func trimsWhitespace() {
        let env = EnvInjection.parseDotenv("  FOO  =   bar  ")
        #expect(env == ["FOO": "bar"])
    }

    @Test("strips a leading export and surrounding quotes")
    func stripsExportAndQuotes() {
        let text = """
            export TOKEN="s3cret"
            NAME='Ada Lovelace'
            """
        #expect(EnvInjection.parseDotenv(text) == ["TOKEN": "s3cret", "NAME": "Ada Lovelace"])
    }

    @Test("skips lines without = or with an empty key")
    func skipsMalformed() {
        let text = """
            NOEQUALS
            =novalue
            OK=1
            """
        #expect(EnvInjection.parseDotenv(text) == ["OK": "1"])
    }

    @Test("last duplicate wins")
    func duplicateLastWins() {
        #expect(EnvInjection.parseDotenv("K=1\nK=2") == ["K": "2"])
    }

    @Test("tolerates CRLF line endings")
    func toleratesCRLF() {
        #expect(EnvInjection.parseDotenv("A=1\r\nB=2\r\n") == ["A": "1", "B": "2"])
    }

    // MARK: - merge precedence

    @Test("config env overrides file env on collision")
    func configWinsOnCollision() {
        let merged = EnvInjection.mergedEnv(
            configEnv: ["SHARED": "from-config", "ONLY_CFG": "c"],
            dotenv: ["SHARED": "from-file", "ONLY_FILE": "f"])
        #expect(
            merged == [
                "SHARED": "from-config",  // config precedence
                "ONLY_CFG": "c",
                "ONLY_FILE": "f",
            ])
    }

    @Test("empty inputs merge to empty")
    func emptyMerge() {
        #expect(EnvInjection.mergedEnv(configEnv: [:], dotenv: [:]).isEmpty)
    }

    // MARK: - serialization

    @Test("empty map serializes to empty string")
    func serializeEmpty() {
        #expect(EnvInjection.serialize([:]).isEmpty)
    }

    @Test("serializes sorted KEY='VALUE' lines, single-quote-escaping values")
    func serializeSortedQuoted() {
        let out = EnvInjection.serialize(["B": "two", "A": "o'ne"])
        // Keys sorted; single quotes inside values escaped as '\''.
        #expect(out == "A='o'\\''ne'\nB='two'\n")
    }

    @Test("a serialized value round-trips back through bash source semantics")
    func quotingIsLiteral() {
        // The serialized value is meant to be sourced literally — verify our
        // escaping produces a value bash reads back verbatim (incl. metachars).
        let value = "a b$c'd\"e`f"
        let line = EnvInjection.serialize(["K": value])
        // Use a real shell to source it and echo the value back.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        let script = "set -a; eval \"$1\"; set +a; printf '%s' \"$K\""
        p.arguments = ["-c", script, "bash", String(line.dropLast())]  // drop trailing \n
        let pipe = Pipe()
        p.standardOutput = pipe
        try? p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        #expect(String(data: data, encoding: .utf8) == value)
    }
}

@Suite("Runner.envMounts (filesystem wrapper)")
struct EnvMountsTests {
    @Test("empty env yields no mount")
    func emptyYieldsNoMount() throws {
        try withTempBoxDir { _ in
            let mounts = Runner.envMounts(Config(env: [:], envFile: nil), id: "box-x-1")
            #expect(mounts.isEmpty)
        }
    }

    @Test("non-empty env writes a 0600 file in a dedicated dir and mounts it ro")
    func writesAndMounts() throws {
        try withTempBoxDir { _ in
            let id = "box-test-42"
            let mounts = Runner.envMounts(Config(env: ["TOKEN": "abc"], envFile: nil), id: id)
            #expect(mounts.count == 1)
            let mount = try #require(mounts.first)
            #expect(mount.destination == Runner.secretMountDir)
            #expect(mount.options.contains("ro"))
            // Source is the dedicated per-box dir (not runDir itself).
            #expect(mount.source == Box.secretDir(forBoxID: id).path)
            #expect(mount.source != Box.runDir.path)

            // File exists inside that dir, is 0600, and contains the value.
            let file = Box.envFile(forBoxID: id)
            #expect(FileManager.default.fileExists(atPath: file.path))
            let perms =
                try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions]
                as? NSNumber
            #expect(perms?.int16Value == 0o600)
            let contents = try String(contentsOf: file, encoding: .utf8)
            #expect(contents.contains("TOKEN="))

            // The dedicated dir contains ONLY the env file — no sibling leakage.
            let entries = try FileManager.default.contentsOfDirectory(
                atPath: Box.secretDir(forBoxID: id).path)
            #expect(entries == ["env"])

            // Cleanup (mirrors runBox's defer) leaves nothing behind.
            try FileManager.default.removeItem(at: Box.secretDir(forBoxID: id))
            #expect(!FileManager.default.fileExists(atPath: Box.secretDir(forBoxID: id).path))
        }
    }

    @Test("config env overrides envFile via the filesystem path")
    func fileAndConfigMerge() throws {
        try withTempBoxDir { _ in
            let dotenvPath = FileManager.default.temporaryDirectory
                .appendingPathComponent("box-test-\(UUID().uuidString).env")
            try "SHARED=from-file\nONLY_FILE=f\n".write(
                to: dotenvPath, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: dotenvPath) }

            let id = "box-merge-1"
            let mounts = Runner.envMounts(
                Config(env: ["SHARED": "from-config"], envFile: dotenvPath.path), id: id)
            #expect(mounts.count == 1)
            let contents = try String(contentsOf: Box.envFile(forBoxID: id), encoding: .utf8)
            // Config wins on SHARED; file-only key survives.
            #expect(contents.contains("SHARED='from-config'"))
            #expect(contents.contains("ONLY_FILE='f'"))
            #expect(!contents.contains("from-file"))
            try? FileManager.default.removeItem(at: Box.secretDir(forBoxID: id))
        }
    }
}
