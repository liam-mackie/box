import Foundation
import Testing

@testable import BoxKit

@Suite("Config layering (merge / ConfigLayer)")
struct ConfigLayerTests {
    @Test("empty layers yield defaults")
    func emptyDefaults() {
        let m = Config.merge(global: ConfigLayer(), project: nil)
        #expect(m == Config())
        #expect(m.cpus == 4)
        #expect(m.memory == "4g")
        #expect(m.rootfsSize == "8g")
        #expect(m.toolchains.isEmpty)
        #expect(m.readOnlyRoots.isEmpty)
        #expect(m.env.isEmpty)
        #expect(m.envFile == nil)
    }

    @Test("global value used when project absent for that key")
    func globalWhenProjectAbsent() {
        let global = ConfigLayer(cpus: 8, memory: "16g")
        let project = ConfigLayer(cpus: 2)  // sets cpus only
        let m = Config.merge(global: global, project: project)
        #expect(m.cpus == 2)  // project wins
        #expect(m.memory == "16g")  // falls back to global
    }

    @Test("mountClaudeConfig tri-state layers with provenance")
    func mountClaudeConfigLayering() {
        let globalOnly = Config.merged(
            global: ConfigLayer(mountClaudeConfig: .ro),
            project: ConfigLayer())
        #expect(globalOnly.config.mountClaudeConfig == .ro)
        #expect(globalOnly.origins.mountClaudeConfig == .global)

        let projectWins = Config.merged(
            global: ConfigLayer(mountClaudeConfig: .ro),
            project: ConfigLayer(mountClaudeConfig: .rw))
        #expect(projectWins.config.mountClaudeConfig == .rw)
        #expect(projectWins.origins.mountClaudeConfig == .project)

        let defaulted = Config.merged(global: ConfigLayer(), project: nil)
        #expect(defaulted.config.mountClaudeConfig == .off)
        #expect(defaulted.origins.mountClaudeConfig == .default)
    }

    @Test("extraMounts append, dedup by destination, project wins on collision")
    func extraMountsMerge() {
        let global = ConfigLayer(extraMounts: [
            .init(source: "/g/a", destination: "/a"),
            .init(source: "/g/b", destination: "/b"),
        ])
        let project = ConfigLayer(extraMounts: [
            .init(source: "/p/b", destination: "/b", readOnly: true),  // collides on /b
            .init(source: "/p/c", destination: "/c"),
        ])
        let m = Config.merge(global: global, project: project)
        #expect(m.extraMounts.count == 3)
        #expect(m.extraMounts.map(\.destination) == ["/a", "/b", "/c"])
        // project won the /b collision
        let b = m.extraMounts.first { $0.destination == "/b" }
        #expect(b?.source == "/p/b")
        #expect(b?.readOnly == true)
    }

    @Test("merged() reports per-value provenance")
    func provenance() {
        let global = ConfigLayer(cpus: 8)
        let project = ConfigLayer(memory: "2g")
        let m = Config.merged(global: global, project: project)
        #expect(m.origins.cpus == .global)
        #expect(m.origins.memory == .project)
        #expect(m.origins.rootfsSize == .default)
    }

    @Test("syncClaudeVersion layer + merge with provenance")
    func syncLayering() {
        // Default: on.
        let d = Config.merge(global: ConfigLayer(), project: nil)
        #expect(d.syncClaudeVersion == true)

        // global disables sync, project disables skipPermissions.
        let global = ConfigLayer(syncClaudeVersion: false)
        let project = ConfigLayer(skipPermissions: false)
        let m = Config.merged(global: global, project: project)
        #expect(m.config.syncClaudeVersion == false)
        #expect(m.config.skipPermissions == false)
        #expect(m.origins.syncClaudeVersion == .global)
        #expect(m.origins.skipPermissions == .project)
    }

    @Test("skipPermissions/disableTelemetry/clipboardSync layer + merge with provenance")
    func behaviorKeysLayering() {
        let d = Config.merge(global: ConfigLayer(), project: nil)
        #expect(d.skipPermissions == true)
        #expect(d.disableTelemetry == true)
        #expect(d.clipboardSync == true)

        let global = ConfigLayer(skipPermissions: false)
        let project = ConfigLayer(clipboardSync: false)
        let m = Config.merged(global: global, project: project)
        #expect(m.config.skipPermissions == false)
        #expect(m.config.clipboardSync == false)
        #expect(m.origins.skipPermissions == .global)
        #expect(m.origins.disableTelemetry == .default)
        #expect(m.origins.clipboardSync == .project)
    }

    @Test("dedicatedProxy default OFF, project layer overrides with provenance")
    func dedicatedProxyLayering() {
        let d = Config.merge(global: ConfigLayer(), project: nil)
        #expect(d.dedicatedProxy == false)

        let project = ConfigLayer(dedicatedProxy: true)
        let m = Config.merged(global: ConfigLayer(), project: project)
        #expect(m.config.dedicatedProxy == true)
        #expect(m.origins.dedicatedProxy == .project)
    }

    // Regression: `envFile` is the only Optional config field, so the generic
    // `pick` (String? promoted to String??) used to read an unset value as
    // `.some(nil)` and always report `.project`. It must reflect the real source.
    @Test("envFile provenance is correct (Optional field not mis-attributed)")
    func envFileProvenance() {
        // Neither layer sets envFile → default, not project.
        let none = Config.merged(global: ConfigLayer(cpus: 8), project: ConfigLayer(memory: "2g"))
        #expect(none.origins.envFile == .default)
        #expect(none.config.envFile == nil)
        // Global sets it, project doesn't → global.
        let g = Config.merged(global: ConfigLayer(envFile: "/g/.env"), project: ConfigLayer())
        #expect(g.origins.envFile == .global)
        #expect(g.config.envFile == "/g/.env")
        // Project sets it → project wins.
        let p = Config.merged(
            global: ConfigLayer(envFile: "/g/.env"),
            project: ConfigLayer(envFile: "/p/.env"))
        #expect(p.origins.envFile == .project)
        #expect(p.config.envFile == "/p/.env")
    }

    @Test("ConfigLayer decodes tolerantly: absent keys stay nil")
    func layerTolerantDecode() throws {
        let json = #"{ "cpus": 6 }"#
        let layer = try JSONDecoder().decode(ConfigLayer.self, from: Data(json.utf8))
        #expect(layer.cpus == 6)
        #expect(layer.memory == nil)
        #expect(layer.toolchains == nil)
    }

    @Test("Config decodes all new keys tolerantly with defaults")
    func configNewKeys() throws {
        let json = """
            {
              "cpus": 12,
              "memory": "32g",
              "rootfsSize": "20g",
              "env": { "FOO": "bar" },
              "envFile": "/tmp/.env",
              "toolchains": ["go", "rust"],
              "readOnlyRoots": ["~/g"]
            }
            """
        let c = try JSONDecoder().decode(Config.self, from: Data(json.utf8))
        #expect(c.cpus == 12)
        #expect(c.memory == "32g")
        #expect(c.rootfsSize == "20g")
        #expect(c.env == ["FOO": "bar"])
        #expect(c.envFile == "/tmp/.env")
        #expect(c.toolchains == ["go", "rust"])
        #expect(c.readOnlyRoots == ["~/g"])
    }
}

@Suite("Config.projectConfigDir discovery")
struct ProjectDiscoveryTests {
    /// Build a throwaway tree under a unique temp dir; returns its root.
    private func makeTree(_ rels: [String]) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-disco-\(UUID().uuidString)")
        for rel in rels {
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent(rel), withIntermediateDirectories: true)
        }
        return root
    }

    @Test("finds .box in an ancestor of cwd")
    func findsAncestor() throws {
        let root = try makeTree(["repo/.box", "repo/src/deep"])
        defer { try? FileManager.default.removeItem(at: root) }
        let cwd = root.appendingPathComponent("repo/src/deep")
        let found = Config.projectConfigDir(startingFrom: cwd, stopAt: root)
        #expect(
            found?.standardizedFileURL.path
                == root.appendingPathComponent("repo/.box").standardizedFileURL.path)
    }

    @Test("finds .box directly in cwd")
    func findsInCwd() throws {
        let root = try makeTree(["repo/.box"])
        defer { try? FileManager.default.removeItem(at: root) }
        let cwd = root.appendingPathComponent("repo")
        let found = Config.projectConfigDir(startingFrom: cwd, stopAt: root)
        #expect(found != nil)
    }

    @Test("returns nil when no .box exists between cwd and stop")
    func noneCase() throws {
        let root = try makeTree(["repo/src"])
        defer { try? FileManager.default.removeItem(at: root) }
        let cwd = root.appendingPathComponent("repo/src")
        #expect(Config.projectConfigDir(startingFrom: cwd, stopAt: root) == nil)
    }

    @Test("stops at the boundary: a .box at/above stopAt is not a project")
    func stopsAtBoundary() throws {
        // .box lives at the stop boundary itself (mimics ~/.box being the global dir).
        let root = try makeTree([".box", "work/proj"])
        defer { try? FileManager.default.removeItem(at: root) }
        let cwd = root.appendingPathComponent("work/proj")
        // Walking up from work/proj stops AT root before seeing root/.box.
        #expect(Config.projectConfigDir(startingFrom: cwd, stopAt: root) == nil)
    }
}
