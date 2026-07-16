import Foundation
import Testing

@testable import BoxKit

// MARK: - Which hosts get bumped vs spliced (pure core)

@Suite("Runner.caBumpHosts / isAlwaysSpliced (pure)")
struct CaBumpHostsTests {
    @Test("empty bumpHosts ⇒ nothing bumped (splice-only default)")
    func emptyIsEmpty() {
        #expect(Runner.caBumpHosts([]) == [])
    }

    @Test("a plain internal host is bumped")
    func plainHostBumped() {
        #expect(Runner.caBumpHosts(["registry.internal"]) == ["registry.internal"])
    }

    @Test("blank/whitespace entries are dropped")
    func blanksDropped() {
        #expect(Runner.caBumpHosts(["", "  ", "a.internal"]) == ["a.internal"])
    }

    @Test("entries are lowercased and de-duplicated, order preserved")
    func dedupAndLowercase() {
        #expect(
            Runner.caBumpHosts(["B.Internal", "a.internal", "b.internal"])
                == ["b.internal", "a.internal"])
    }

    @Test("the Anthropic / Claude API is NEVER bumped, even if listed")
    func anthropicNeverBumped() {
        #expect(Runner.caBumpHosts(["api.anthropic.com"]) == [])
        #expect(Runner.caBumpHosts(["anthropic.com"]) == [])
        #expect(Runner.caBumpHosts([".anthropic.com"]) == [])
        #expect(Runner.caBumpHosts(["claude.ai"]) == [])
        #expect(Runner.caBumpHosts(["console.claude.com"]) == [])
    }

    @Test("npm and git/github are never bumped (cert-pinned / auth-sensitive)")
    func packageAndScmNeverBumped() {
        #expect(Runner.caBumpHosts(["registry.npmjs.org"]) == [])
        #expect(Runner.caBumpHosts(["github.com"]) == [])
        #expect(Runner.caBumpHosts(["codeload.github.com"]) == [])
        #expect(Runner.caBumpHosts(["raw.githubusercontent.com"]) == [])
    }

    @Test("the always-spliced set filters pinned hosts out of a mixed list")
    func mixedListFiltered() {
        let got = Runner.caBumpHosts([
            "api.anthropic.com", "internal.corp", "registry.npmjs.org", "vault.internal",
        ])
        #expect(got == ["internal.corp", "vault.internal"])
    }

    @Test("isAlwaysSpliced matches the host and its subdomains but not unrelated hosts")
    func alwaysSplicedMatching() {
        #expect(Runner.isAlwaysSpliced("anthropic.com"))
        #expect(Runner.isAlwaysSpliced("api.anthropic.com"))
        #expect(Runner.isAlwaysSpliced(".anthropic.com"))
        // A look-alike host that merely ends in the same letters is NOT matched.
        #expect(!Runner.isAlwaysSpliced("notanthropic.com"))
        #expect(!Runner.isAlwaysSpliced("anthropic.com.evil.test"))
        #expect(!Runner.isAlwaysSpliced("internal.corp"))
    }
}

// MARK: - caInit writes the expected CA files (temp Box.caDir via BOX_DIR)

@Suite("Commands.caInit", .serialized)
struct CaInitTests {
    @Test("writes ca.key (0600) + ca.crt and refuses to clobber")
    func writesCaFiles() throws {
        // openssl is required to generate the CA; skip cleanly if absent.
        try #require(Sh.exists("openssl"))

        try withTempBoxDir { _ in
            try Commands.caInit()

            let fm = FileManager.default
            let key = Box.caDir.appendingPathComponent("ca.key")
            let cert = Box.caDir.appendingPathComponent("ca.crt")
            #expect(fm.fileExists(atPath: key.path))
            #expect(fm.fileExists(atPath: cert.path))

            // Private key locked to 0600.
            let perms = (try fm.attributesOfItem(atPath: key.path)[.posixPermissions]) as? NSNumber
            #expect(perms?.int16Value == 0o600)

            // It really is a CA cert (self-signed, CA:TRUE) — readable by openssl.
            let cfrom = cert.path
            let text = (try? Sh.output(["openssl", "x509", "-in", cfrom, "-noout", "-text"])) ?? ""
            #expect(text.contains("CA:TRUE"))

            // A second init refuses rather than silently replacing the CA.
            #expect(throws: CBError.self) { try Commands.caInit() }
        }
    }
}
