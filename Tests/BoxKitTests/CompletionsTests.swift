import Foundation
import Testing

@testable import BoxKit

@Suite("Completions")
struct CompletionsTests {
    @Test("an explicit shell argument wins over $SHELL")
    func explicitShell() throws {
        #expect(try Commands.completionShell(argument: "zsh", shellEnv: nil) == .zsh)
        #expect(try Commands.completionShell(argument: "bash", shellEnv: "/bin/zsh") == .bash)
        #expect(try Commands.completionShell(argument: "fish", shellEnv: nil) == .fish)
    }

    @Test("an unknown shell argument throws")
    func unknownShell() {
        #expect(throws: CBError.self) {
            try Commands.completionShell(argument: "powershell", shellEnv: nil)
        }
    }

    @Test("the shell defaults from the $SHELL basename")
    func defaultFromShellEnv() throws {
        #expect(try Commands.completionShell(argument: nil, shellEnv: "/bin/zsh") == .zsh)
        #expect(try Commands.completionShell(argument: nil, shellEnv: "/opt/homebrew/bin/fish") == .fish)
        #expect(try Commands.completionShell(argument: nil, shellEnv: "/bin/bash") == .bash)
    }

    @Test("an undetectable or unrecognized $SHELL throws")
    func undetectableShell() {
        #expect(throws: CBError.self) {
            try Commands.completionShell(argument: nil, shellEnv: nil)
        }
        #expect(throws: CBError.self) {
            try Commands.completionShell(argument: nil, shellEnv: "/bin/tcsh")
        }
    }

    @Test("install paths map to each shell's conventional location")
    func installPaths() {
        let home = URL(fileURLWithPath: "/Users/x")
        #expect(Commands.completionInstallURL(.zsh, home: home).path == "/Users/x/.zfunc/_box")
        #expect(
            Commands.completionInstallURL(.bash, home: home).path
                == "/Users/x/.local/share/bash-completion/completions/box")
        #expect(
            Commands.completionInstallURL(.fish, home: home).path
                == "/Users/x/.config/fish/completions/box.fish")
    }

    @Test("the zsh hint appears only when ~/.zshrc lacks a .zfunc reference")
    func zshHint() {
        #expect(Commands.zshHint(zshrc: nil) != nil)
        #expect(Commands.zshHint(zshrc: "export PATH=/usr/bin") != nil)
        #expect(Commands.zshHint(zshrc: "fpath+=~/.zfunc\nautoload -Uz compinit") == nil)
    }
}
