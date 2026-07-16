import Foundation
import Testing

@testable import BoxKit

@Suite("Runner.effectiveCommand (skipPermissions insertion, pure)")
struct EffectiveCommandTests {
    @Test("plain `box run` gets --dangerously-skip-permissions after `claude`")
    func insertsFlag() {
        #expect(
            Runner.effectiveCommand(["claude"], claudeRun: true, skipPermissions: true)
                == ["claude", "--dangerously-skip-permissions"])
        #expect(
            Runner.effectiveCommand(["claude", "-c"], claudeRun: true, skipPermissions: true)
                == ["claude", "--dangerously-skip-permissions", "-c"])
    }

    @Test("user-supplied permission flags win (no duplicate, no override)")
    func userFlagsWin() {
        let explicit = ["claude", "--dangerously-skip-permissions"]
        #expect(
            Runner.effectiveCommand(explicit, claudeRun: true, skipPermissions: true)
                == explicit)
        let mode = ["claude", "--permission-mode", "plan"]
        #expect(Runner.effectiveCommand(mode, claudeRun: true, skipPermissions: true) == mode)
        let modeEq = ["claude", "--permission-mode=plan"]
        #expect(Runner.effectiveCommand(modeEq, claudeRun: true, skipPermissions: true) == modeEq)
    }

    @Test("disabled config, non-claude commands, and login are untouched")
    func noInsertionCases() {
        #expect(
            Runner.effectiveCommand(["claude"], claudeRun: true, skipPermissions: false)
                == ["claude"])
        #expect(
            Runner.effectiveCommand(["bash"], claudeRun: false, skipPermissions: true)
                == ["bash"])
        // `box login` runs claude but is not a claudeRun.
        #expect(
            Runner.effectiveCommand(
                ["claude", "/login"], claudeRun: false,
                skipPermissions: true)
                == ["claude", "/login"])
    }
}

@Suite("Runner.guestEnv (telemetry/auto-update flags, pure)")
struct GuestEnvTests {
    @Test("auto-updater/sandbox flags are always on; telemetry follows the config")
    func envFlags() {
        let on = Runner.guestEnv(Config(disableTelemetry: true))
        #expect(on.contains("DISABLE_AUTOUPDATER=1"))
        #expect(on.contains("IS_SANDBOX=1"))
        #expect(on.contains("DISABLE_TELEMETRY=1"))
        #expect(on.contains("DISABLE_ERROR_REPORTING=1"))
        #expect(on.contains("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"))

        let off = Runner.guestEnv(Config(disableTelemetry: false))
        #expect(off.contains("DISABLE_AUTOUPDATER=1"))
        #expect(off.contains("IS_SANDBOX=1"))
        #expect(!off.contains("DISABLE_TELEMETRY=1"))
        #expect(!off.contains("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"))
    }
}
