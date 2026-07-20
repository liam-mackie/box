import Foundation
import Testing

@testable import BoxKit

@Suite("ClaudeSettings: strip host hooks/statusLine from the mounted settings.json")
struct ClaudeSettingsTests {
    @Test("sanitized drops hooks and statusLine, keeps other config")
    func stripsHooksAndStatusLine() throws {
        let input = """
            {
              "model": "opus",
              "hooks": { "SessionStart": [{ "hooks": [] }] },
              "statusLine": { "type": "command", "command": "bun x statusline" },
              "permissions": { "allow": ["Bash"] }
            }
            """
        let out = try #require(ClaudeSettings.sanitized(Data(input.utf8)))
        let dict = try #require(
            try JSONSerialization.jsonObject(with: out) as? [String: Any])
        #expect(dict["hooks"] == nil)
        #expect(dict["statusLine"] == nil)
        #expect(dict["model"] as? String == "opus")
        #expect(dict["permissions"] != nil)
    }

    @Test("sanitized rejects non-object and malformed JSON")
    func rejectsMalformed() {
        #expect(ClaudeSettings.sanitized(Data("not json".utf8)) == nil)
        #expect(ClaudeSettings.sanitized(Data("[1, 2, 3]".utf8)) == nil)
    }

    @Test("mounts is a no-op when mountClaudeConfig is off")
    func gatedOff() {
        #expect(ClaudeSettings.mounts(Config(), id: "box-t-1").isEmpty)
    }
}
