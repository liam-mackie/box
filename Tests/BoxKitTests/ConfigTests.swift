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
            #expect(c.mountClaudeConfig == .off)
            #expect(c.resolvedMounts(claudeDir: "/h/.claude", claudeExists: true).isEmpty)
        }
    }

    @Test("full config parses")
    func parsesFull() throws {
        let json = """
            {
              "mountClaudeConfig": "rw",
              "extraMounts": [
                { "source": "~/work", "destination": "/work", "readOnly": true },
                { "source": "/tmp/data", "destination": "/data" }
              ]
            }
            """
        try withConfig(json) {
            let c = Config.load()
            #expect(c.mountClaudeConfig == .rw)
            #expect(c.extraMounts.count == 2)
            #expect(c.extraMounts[1].readOnly == false)
        }
    }

    @Test("partial config fills the rest with defaults")
    func parsesPartial() throws {
        try withConfig(#"{ "mountClaudeConfig": "ro" }"#) {
            let c = Config.load()
            #expect(c.mountClaudeConfig == .ro)
            #expect(c.extraMounts.isEmpty)
        }
    }

    @Test("mountClaudeConfig decodes off/ro/rw")
    func mountClaudeConfigTriStateDecodes() throws {
        for (raw, expected): (String, ClaudeConfigMount) in
            [("off", .off), ("ro", .ro), ("rw", .rw)]
        {
            try withConfig("{ \"mountClaudeConfig\": \"\(raw)\" }") {
                #expect(Config.load().mountClaudeConfig == expected)
            }
        }
    }

    @Test("a bool mountClaudeConfig fails whole-file decode → pure defaults")
    func boolMountClaudeConfigFallsBack() throws {
        try withConfig(#"{ "mountClaudeConfig": true, "cpus": 12 }"#) {
            #expect(Config.load() == Config())
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
            mountClaudeConfig: .ro,
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

    @Test("resolvedMounts gates on off and sets readOnly per tri-state")
    func resolvedMountsTriState() {
        #expect(
            Config(mountClaudeConfig: .off)
                .resolvedMounts(claudeDir: "/h/.claude", claudeExists: true).isEmpty)

        let ro = Config(mountClaudeConfig: .ro)
            .resolvedMounts(claudeDir: "/h/.claude", claudeExists: true)
        #expect(ro.count == 1)
        #expect(ro[0].readOnly == true)

        let rw = Config(mountClaudeConfig: .rw)
            .resolvedMounts(claudeDir: "/h/.claude", claudeExists: true)
        #expect(rw.count == 1)
        #expect(rw[0].readOnly == false)
    }

    @Test("claude mount skipped when the directory is absent")
    func skipsMissingClaude() {
        let c = Config(mountClaudeConfig: .ro)
        #expect(c.resolvedMounts(claudeDir: "/nope/.claude", claudeExists: false).isEmpty)
    }

    @Test("writeStarter seeds a missing config that decodes to .ro")
    func writeStarterSeeds() throws {
        try withConfig(nil) {
            let wrote = try Config.writeStarter()
            #expect(wrote == true)
            #expect(Config.load().mountClaudeConfig == .ro)
        }
    }

    @Test("writeStarter never overwrites an existing config")
    func writeStarterSkipsExisting() throws {
        let original = #"{ "mountClaudeConfig": "rw" }"#
        try withConfig(original) {
            let wrote = try Config.writeStarter()
            #expect(wrote == false)
            let onDisk = try String(contentsOf: Config.fileURL, encoding: .utf8)
            #expect(onDisk == original)
            #expect(Config.load().mountClaudeConfig == .rw)
        }
    }

    @Test("syncClaudeVersion defaults ON when absent")
    func syncDefault() throws {
        try withConfig(#"{ "mountClaudeConfig": "ro" }"#) {
            let c = Config.load()
            #expect(c.syncClaudeVersion == true)
        }
    }

    @Test("syncClaudeVersion can be switched off")
    func syncParse() throws {
        try withConfig(#"{ "syncClaudeVersion": false }"#) {
            let c = Config.load()
            #expect(c.syncClaudeVersion == false)
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

    @Test("dedicatedProxy default OFF, can be switched on")
    func dedicatedProxyParse() throws {
        try withConfig(nil) {
            let c = Config.load()
            #expect(c.dedicatedProxy == false)
        }
        try withConfig(#"{ "dedicatedProxy": true }"#) {
            let c = Config.load()
            #expect(c.dedicatedProxy == true)
        }
    }

    @Test("configReport names every Config.CodingKeys key")
    func configReportCoversEveryKey() {
        let merged = Config.merged(global: ConfigLayer(), project: nil)
        let report = Commands.configReport(merged, detectedToolchains: []).joined(separator: "\n")
        for key in Config.CodingKeys.allCases {
            #expect(report.contains(key.rawValue), "config report omits key '\(key.rawValue)'")
        }
    }

    @Test("configReport shows detected toolchains when the key is at its default")
    func configReportDetectedToolchains() {
        let merged = Config.merged(global: ConfigLayer(), project: nil)
        let report = Commands.configReport(merged, detectedToolchains: ["go", "rust"])
            .joined(separator: "\n")
        #expect(report.contains("toolchains:           go, rust [detected]"))
    }

    @Test("configReport prefers a configured toolchains value over detection")
    func configReportConfiguredToolchains() {
        let merged = Config.merged(global: ConfigLayer(toolchains: ["dotnet"]), project: nil)
        let report = Commands.configReport(merged, detectedToolchains: ["go"])
            .joined(separator: "\n")
        #expect(report.contains("toolchains:           dotnet [global]"))
        #expect(!report.contains("[detected]"))
    }
}
