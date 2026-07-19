import Foundation
import Testing

@testable import BoxKit

@Suite("ManagedSettings: guest hook/statusline neutralizer")
struct ManagedSettingsTests {
    @Test("payload is valid JSON with disableAllHooks and a no-op statusLine")
    func payload() throws {
        let obj = try JSONSerialization.jsonObject(with: Data(ManagedSettings.json.utf8))
        let dict = try #require(obj as? [String: Any])
        #expect(dict["disableAllHooks"] as? Bool == true)
        let status = try #require(dict["statusLine"] as? [String: Any])
        #expect(status["type"] as? String == "command")
        #expect(status["command"] as? String == "true")
    }

    @Test("mounts is a no-op when mountClaudeConfig is off")
    func gatedOff() {
        #expect(ManagedSettings.mounts(Config(), id: "box-t-1").isEmpty)
    }

    @Test("staged via /run/box-managed; the entrypoint installs it root-owned")
    func destination() {
        // NOT /etc/claude-code directly: a virtiofs share arrives owned by the
        // agent's uid and Claude Code ignores a managed file the constrained
        // user owns. The entrypoint copies it onto the rootfs as root.
        #expect(ManagedSettings.mountDir == "/run/box-managed")
        #expect(ManagedSettings.fileName == "managed-settings.json")
    }
}
