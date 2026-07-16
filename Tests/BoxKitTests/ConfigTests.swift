import Foundation
import Testing

@testable import BoxKit

/// Serialized: these set the process-global XDG_CONFIG_HOME env var.
@Suite("Config", .serialized)
struct ConfigTests {
    private func withConfig(_ json: String?, _ body: () throws -> Void) throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-cfg-\(UUID().uuidString)")
        setenv("XDG_CONFIG_HOME", dir.path, 1)
        defer {
            unsetenv("XDG_CONFIG_HOME")
            try? FileManager.default.removeItem(at: dir)
        }
        if let json {
            try FileManager.default.createDirectory(
                at: dir.appendingPathComponent("box"), withIntermediateDirectories: true)
            try json.write(to: Config.fileURL, atomically: true, encoding: .utf8)
        }
        try body()
    }

    @Test("absent file yields defaults (isolated, nothing mounted)")
    func defaultsWhenAbsent() throws {
        try withConfig(nil) {
            let c = Config.load()
            #expect(c == Config())
            #expect(c.mountClaudeConfig == false)
            #expect(c.resolvedMounts(claudeDir: "/h/.claude", claudeExists: true).isEmpty)
        }
    }

    @Test("full config parses")
    func parsesFull() throws {
        let json = """
            {
              "mountClaudeConfig": true,
              "claudeConfigReadOnly": true,
              "extraMounts": [
                { "source": "~/work", "destination": "/work", "readOnly": true },
                { "source": "/tmp/data", "destination": "/data" }
              ]
            }
            """
        try withConfig(json) {
            let c = Config.load()
            #expect(c.mountClaudeConfig)
            #expect(c.claudeConfigReadOnly)
            #expect(c.extraMounts.count == 2)
            #expect(c.extraMounts[1].readOnly == false)  // defaulted
        }
    }

    @Test("partial config fills the rest with defaults")
    func parsesPartial() throws {
        try withConfig(#"{ "mountClaudeConfig": true }"#) {
            let c = Config.load()
            #expect(c.mountClaudeConfig)
            #expect(c.claudeConfigReadOnly == false)
            #expect(c.extraMounts.isEmpty)
        }
    }

    @Test("invalid JSON falls back to defaults without throwing")
    func invalidFallsBack() throws {
        try withConfig("{ not json") {
            #expect(Config.load() == Config())
        }
    }

    @Test("resolvedMounts maps claude dir + extra mounts, expanding ~")
    func resolvesMounts() throws {
        let c = Config(
            mountClaudeConfig: true,
            claudeConfigReadOnly: true,
            extraMounts: [.init(source: "~/work", destination: "/work", readOnly: true)])
        let specs = c.resolvedMounts(claudeDir: "/Users/x/.claude", claudeExists: true)
        #expect(specs.count == 2)
        #expect(
            specs[0]
                == .init(
                    source: "/Users/x/.claude",
                    destination: "/home/agent/.claude", readOnly: true))
        #expect(specs[1].destination == "/work")
        #expect(specs[1].readOnly)
        #expect(!specs[1].source.hasPrefix("~"), "tilde should be expanded")
    }

    @Test("claude mount skipped when the directory is absent")
    func skipsMissingClaude() {
        let c = Config(mountClaudeConfig: true)
        #expect(c.resolvedMounts(claudeDir: "/nope/.claude", claudeExists: false).isEmpty)
    }

    @Test("tlsInspect/bumpHosts default off + empty when absent")
    func tlsKeysDefault() throws {
        try withConfig(#"{ "mountClaudeConfig": true }"#) {
            let c = Config.load()
            #expect(c.tlsInspect == false)
            #expect(c.bumpHosts.isEmpty)
        }
    }

    @Test("tlsInspect/bumpHosts parse when present (tolerant decode)")
    func tlsKeysParse() throws {
        let json = #"{ "tlsInspect": true, "bumpHosts": ["a.internal", "b.internal"] }"#
        try withConfig(json) {
            let c = Config.load()
            #expect(c.tlsInspect == true)
            #expect(c.bumpHosts == ["a.internal", "b.internal"])
        }
    }

    @Test("syncClaudeVersion/mountHooks default ON when absent")
    func syncAndHooksDefault() throws {
        try withConfig(#"{ "mountClaudeConfig": true }"#) {
            let c = Config.load()
            #expect(c.syncClaudeVersion == true)
            #expect(c.mountHooks == true)
        }
    }

    @Test("syncClaudeVersion/mountHooks can be switched off")
    func syncAndHooksParse() throws {
        try withConfig(#"{ "syncClaudeVersion": false, "mountHooks": false }"#) {
            let c = Config.load()
            #expect(c.syncClaudeVersion == false)
            #expect(c.mountHooks == false)
        }
    }

    @Test("skipPermissions/disableTelemetry/clipboardSync default ON, can be switched off")
    func behaviorKeys() throws {
        try withConfig(nil) {
            let c = Config.load()
            #expect(c.skipPermissions == true)
            #expect(c.disableTelemetry == true)
            #expect(c.clipboardSync == true)
        }
        try withConfig(
            #"{ "skipPermissions": false, "disableTelemetry": false, "clipboardSync": false }"#
        ) {
            let c = Config.load()
            #expect(c.skipPermissions == false)
            #expect(c.disableTelemetry == false)
            #expect(c.clipboardSync == false)
        }
    }
}
