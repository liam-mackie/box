import Foundation
import Testing

@testable import BoxKit

@Suite("HookMounts: extraction from settings JSON (pure)")
struct HookMountsExtractionTests {
    static let settings = """
        {
          "model": "opus",
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  { "type": "command", "command": "~/.claude/hooks/guard.sh" },
                  { "command": "python3 /Users/u/g/dotfiles/hooks/lint.py --fix" }
                ]
              }
            ],
            "Stop": [
              { "hooks": [ { "type": "prompt", "command": "ignored-not-a-command" } ] }
            ]
          }
        }
        """

    @Test("collects command strings; missing type means command; other types skipped")
    func extractsCommands() {
        let cmds = HookMounts.hookCommands(inSettingsJSON: Data(Self.settings.utf8))
        #expect(
            cmds == [
                "~/.claude/hooks/guard.sh",
                "python3 /Users/u/g/dotfiles/hooks/lint.py --fix",
            ])
    }

    @Test("malformed JSON and missing hooks sections yield nothing")
    func tolerantExtraction() {
        #expect(HookMounts.hookCommands(inSettingsJSON: Data("not json".utf8)).isEmpty)
        #expect(HookMounts.hookCommands(inSettingsJSON: Data("{}".utf8)).isEmpty)
        #expect(
            HookMounts.hookCommands(
                inSettingsJSON: Data(#"{"hooks": {"PreToolUse": "wrong-shape"}}"#.utf8)
            ).isEmpty)
    }
}

@Suite("HookMounts: path refs in a command (pure)")
struct HookMountsPathRefTests {
    let home = "/Users/u"
    let guest = "/home/agent"

    func refs(_ command: String) -> [HookMounts.PathRef] {
        HookMounts.pathRefs(inCommand: command, hostHome: home, guestHome: guest)
    }

    @Test("tilde and $HOME map to the guest home; absolute maps to itself")
    func mapsPrefixes() {
        #expect(
            refs("~/.claude/hooks/x.sh") == [
                HookMounts.PathRef(
                    hostPath: "/Users/u/.claude/hooks/x.sh",
                    guestPath: "/home/agent/.claude/hooks/x.sh")
            ])
        #expect(
            refs("$HOME/hooks/y.sh") == [
                HookMounts.PathRef(
                    hostPath: "/Users/u/hooks/y.sh",
                    guestPath: "/home/agent/hooks/y.sh")
            ])
        #expect(
            refs("bash /Users/u/g/dotfiles/z.sh") == [
                HookMounts.PathRef(
                    hostPath: "/Users/u/g/dotfiles/z.sh",
                    guestPath: "/Users/u/g/dotfiles/z.sh")
            ])
    }

    @Test("$CLAUDE_PROJECT_DIR paths are dropped (already in /workspace)")
    func skipsProjectDir() {
        #expect(refs("\"$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh\" --check").isEmpty)
    }

    @Test("quoted paths with spaces stay one token; shell glue is trimmed")
    func tokenizes() {
        #expect(
            refs(#"sh '/Users/u/my hooks/x.sh';"#) == [
                HookMounts.PathRef(
                    hostPath: "/Users/u/my hooks/x.sh",
                    guestPath: "/Users/u/my hooks/x.sh")
            ])
        #expect(
            refs("(~/hooks/a.sh && echo ok)") == [
                HookMounts.PathRef(
                    hostPath: "/Users/u/hooks/a.sh",
                    guestPath: "/home/agent/hooks/a.sh")
            ])
    }

    @Test("non-path tokens produce nothing")
    func ignoresNonPaths() {
        #expect(refs("echo done | jq .field").isEmpty)
    }
}

@Suite("HookMounts: resolution guardrails (pure)")
struct HookMountsResolveTests {
    let home = "/Users/u"
    let guest = "/home/agent"

    /// Resolve with an injected filesystem: `files` exist (dirs end in "/").
    func resolve(
        _ refs: [HookMounts.PathRef], files: Set<String>, dirs: Set<String> = [],
        mountClaudeConfig: Bool = false, sensitive: Set<String> = []
    ) -> HookMounts.Resolution {
        HookMounts.resolve(
            refs: refs, hostHome: home, guestHome: guest,
            mountClaudeConfig: mountClaudeConfig,
            exists: { files.contains($0) || dirs.contains($0) },
            isDirectory: { dirs.contains($0) },
            isSensitive: { path in sensitive.contains { path == $0 || path.hasPrefix($0 + "/") } })
    }

    @Test("mounts a script's parent directory read-only at the guest path")
    func mountsParentDir() {
        let r = resolve(
            [
                .init(
                    hostPath: "/Users/u/g/dotfiles/hooks/lint.py",
                    guestPath: "/Users/u/g/dotfiles/hooks/lint.py")
            ],
            files: ["/Users/u/g/dotfiles/hooks/lint.py"])
        #expect(
            r.specs == [
                Config.MountSpec(
                    source: "/Users/u/g/dotfiles/hooks",
                    destination: "/Users/u/g/dotfiles/hooks",
                    readOnly: true)
            ])
    }

    @Test("a directory ref mounts the directory itself")
    func mountsDirectory() {
        let r = resolve(
            [.init(hostPath: "/Users/u/hooks", guestPath: "/home/agent/hooks")],
            files: [], dirs: ["/Users/u/hooks"])
        #expect(
            r.specs == [
                Config.MountSpec(
                    source: "/Users/u/hooks",
                    destination: "/home/agent/hooks",
                    readOnly: true)
            ])
    }

    @Test("missing host paths are skipped quietly (guest-only paths)")
    func skipsMissing() {
        let r = resolve(
            [.init(hostPath: "/Users/u/nope.sh", guestPath: "/Users/u/nope.sh")],
            files: [])
        #expect(r.specs.isEmpty)
        #expect(r.skipped == [HookMounts.Skipped(path: "/Users/u/nope.sh", reason: .missing)])
    }

    @Test("paths outside the host home never mount (no shadowing guest dirs)")
    func skipsOutsideHome() {
        let r = resolve(
            [.init(hostPath: "/usr/bin/python3", guestPath: "/usr/bin/python3")],
            files: ["/usr/bin/python3"])
        #expect(r.specs.isEmpty)
        #expect(r.skipped.isEmpty)  // classification, not an error
    }

    @Test("a script at the home root is refused (would mount all of home)")
    func refusesHomeRoot() {
        let r = resolve(
            [.init(hostPath: "/Users/u/hook.sh", guestPath: "/home/agent/hook.sh")],
            files: ["/Users/u/hook.sh"])
        #expect(r.specs.isEmpty)
        #expect(r.skipped == [HookMounts.Skipped(path: "/Users/u/hook.sh", reason: .homeRoot)])
    }

    @Test("sensitive sources are refused")
    func refusesSensitive() {
        let r = resolve(
            [.init(hostPath: "/Users/u/.ssh/exfil.sh", guestPath: "/home/agent/.ssh/exfil.sh")],
            files: ["/Users/u/.ssh/exfil.sh"],
            sensitive: ["/Users/u/.ssh"])
        #expect(r.specs.isEmpty)
        #expect(
            r.skipped == [
                HookMounts.Skipped(
                    path: "/Users/u/.ssh/exfil.sh",
                    reason: .sensitive)
            ])
    }

    @Test("tilde refs inside ~/.claude are covered by mountClaudeConfig")
    func claudeConfigCoverage() {
        let ref = HookMounts.PathRef(
            hostPath: "/Users/u/.claude/hooks/x.sh",
            guestPath: "/home/agent/.claude/hooks/x.sh")
        // Covered when ~/.claude is mounted…
        #expect(resolve([ref], files: [ref.hostPath], mountClaudeConfig: true).specs.isEmpty)
        // …and mounted explicitly when it isn't.
        let r = resolve([ref], files: [ref.hostPath], mountClaudeConfig: false)
        #expect(
            r.specs == [
                Config.MountSpec(
                    source: "/Users/u/.claude/hooks",
                    destination: "/home/agent/.claude/hooks",
                    readOnly: true)
            ])
    }

    @Test("an absolute ref to ~/.claude still mounts (guest path differs)")
    func absoluteClaudePathNotCovered() {
        let ref = HookMounts.PathRef(
            hostPath: "/Users/u/.claude/hooks/x.sh",
            guestPath: "/Users/u/.claude/hooks/x.sh")
        let r = resolve([ref], files: [ref.hostPath], mountClaudeConfig: true)
        #expect(
            r.specs == [
                Config.MountSpec(
                    source: "/Users/u/.claude/hooks",
                    destination: "/Users/u/.claude/hooks",
                    readOnly: true)
            ])
    }

    @Test("duplicate refs and refs under an already-selected mount collapse")
    func dedupes() {
        let a = HookMounts.PathRef(
            hostPath: "/Users/u/hooks/a.sh",
            guestPath: "/home/agent/hooks/a.sh")
        let b = HookMounts.PathRef(
            hostPath: "/Users/u/hooks/b.sh",
            guestPath: "/home/agent/hooks/b.sh")
        let r = resolve([a, a, b], files: [a.hostPath, b.hostPath])
        #expect(
            r.specs == [
                Config.MountSpec(
                    source: "/Users/u/hooks",
                    destination: "/home/agent/hooks",
                    readOnly: true)
            ])
    }
}
