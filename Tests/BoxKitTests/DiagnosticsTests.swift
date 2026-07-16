import Foundation
import Testing

@testable import BoxKit

/// A fully-passing baseline `Probe` that individual tests tweak to drive one
/// check at a time. Defaults to a healthy arm64 / macOS 26 host with the image
/// present and the binary correctly located and signed.
private func healthyProbe(
    machine: String = "arm64",
    macOS: Int = 26,
    tools: Set<String> = ["container", "docker"],
    kernelResolves: Bool = true,
    executablePath: String = "/usr/local/bin/box",
    homePath: String = "/Users/tester",
    commandOutput: @escaping @Sendable ([String]) -> String = { _ in
        "[Dict]\n  com.apple.security.virtualization = 1\n"
    },
    pathExists: @escaping @Sendable (String) -> Bool = { _ in true },
    imageInStore: Bool = true,
    vminitReachable: Bool = true
) -> Probe {
    Probe(
        machine: { machine },
        macOSMajorVersion: { macOS },
        toolExists: { tools.contains($0) },
        kernelResolves: { kernelResolves },
        executablePath: { executablePath },
        homePath: { homePath },
        commandOutput: commandOutput,
        pathExists: pathExists,
        imageInStore: { imageInStore },
        vminitReachable: { vminitReachable }
    )
}

private func result(_ results: [DiagnosticResult], _ name: String) -> DiagnosticResult {
    results.first { $0.name.contains(name) }!
}

@Suite("Diagnostics individual checks (via seams)")
struct DiagnosticsCheckTests {
    @Test("arch passes only on arm64")
    func arch() {
        #expect(Diagnostics.checkArch(healthyProbe(machine: "arm64")).status == .pass)
        let bad = Diagnostics.checkArch(healthyProbe(machine: "x86_64"))
        #expect(bad.status == .fail)
        #expect(bad.hard)
        #expect(bad.remediation != nil)
    }

    @Test("macOS requires major >= 26")
    func macOS() {
        #expect(Diagnostics.checkMacOS(healthyProbe(macOS: 26)).status == .pass)
        #expect(Diagnostics.checkMacOS(healthyProbe(macOS: 27)).status == .pass)
        let old = Diagnostics.checkMacOS(healthyProbe(macOS: 15))
        #expect(old.status == .fail)
        #expect(old.hard)
    }

    @Test("container CLI presence drives the check")
    func containerCLI() {
        #expect(Diagnostics.checkContainerCLI(healthyProbe(tools: ["container"])).status == .pass)
        let missing = Diagnostics.checkContainerCLI(healthyProbe(tools: []))
        #expect(missing.status == .fail)
        #expect(missing.hard)
    }

    @Test("kernel discoverability drives the check")
    func kernel() {
        #expect(Diagnostics.checkKernel(healthyProbe(kernelResolves: true)).status == .pass)
        let missing = Diagnostics.checkKernel(healthyProbe(kernelResolves: false))
        #expect(missing.status == .fail)
        #expect(missing.hard)
        #expect(missing.remediation?.contains("container system start") == true)
    }

    @Test("docker is an optional fallback: missing ⇒ soft warning, never a failure")
    func docker() {
        #expect(Diagnostics.checkDocker(healthyProbe(tools: ["docker"])).status == .pass)
        let missing = Diagnostics.checkDocker(healthyProbe(tools: ["container"]))
        #expect(missing.status == .warn)
        #expect(!missing.hard)
    }

    @Test("entitlement check parses codesign output for the virtualization key")
    func entitlementPresent() {
        let p = healthyProbe(commandOutput: { args in
            // Echo back the path we were asked to inspect, with the entitlement.
            #expect(args.contains("codesign"))
            #expect(args.contains("/usr/local/bin/box"))
            return "<key>com.apple.security.virtualization</key><true/>"
        })
        #expect(Diagnostics.checkEntitlement(p).status == .pass)
    }

    @Test("entitlement check fails when the key is absent from codesign output")
    func entitlementAbsent() {
        let p = healthyProbe(commandOutput: { _ in "no entitlements\n" })
        let r = Diagnostics.checkEntitlement(p)
        #expect(r.status == .fail)
        #expect(r.hard)
        #expect(r.remediation?.contains("com.apple.security.virtualization") == true)
    }

    @Test("entitlement check fails (hard) when the binary path can't be resolved")
    func entitlementNoPath() {
        let p = healthyProbe(executablePath: "")
        let r = Diagnostics.checkEntitlement(p)
        #expect(r.status == .fail)
        #expect(r.hard)
    }

    @Test("location check passes outside Documents/Desktop")
    func locationOK() {
        let p = healthyProbe(executablePath: "/usr/local/bin/box", homePath: "/Users/tester")
        #expect(Diagnostics.checkLocation(p).status == .pass)
    }

    @Test("location check fails under ~/Documents and names it in remediation")
    func locationDocuments() {
        let p = healthyProbe(
            executablePath: "/Users/tester/Documents/box/.build/box",
            homePath: "/Users/tester")
        let r = Diagnostics.checkLocation(p)
        #expect(r.status == .fail)
        #expect(r.hard)
        #expect(r.remediation?.contains("Documents") == true)
    }

    @Test("location check fails under ~/Desktop")
    func locationDesktop() {
        let p = healthyProbe(
            executablePath: "/Users/tester/Desktop/box",
            homePath: "/Users/tester")
        let r = Diagnostics.checkLocation(p)
        #expect(r.status == .fail)
        #expect(r.remediation?.contains("Desktop") == true)
    }

    @Test("location check does not false-positive on a sibling like DocumentsArchive")
    func locationSiblingNotMatched() {
        let p = healthyProbe(
            executablePath: "/Users/tester/DocumentsArchive/box",
            homePath: "/Users/tester")
        #expect(Diagnostics.checkLocation(p).status == .pass)
    }

    @Test("image absence is a warning (not hard)")
    func imageMissingWarns() {
        let r = Diagnostics.checkImage(healthyProbe(imageInStore: false))
        #expect(r.status == .warn)
        #expect(!r.hard)
    }

    @Test("vminit unreachable is a warning (not hard)")
    func vminitWarns() {
        let r = Diagnostics.checkVminit(healthyProbe(vminitReachable: false))
        #expect(r.status == .warn)
        #expect(!r.hard)
    }

    @Test("missing Claude credentials is a warning (not hard)")
    func loginWarns() {
        let r = Diagnostics.checkLogin(healthyProbe(pathExists: { _ in false }))
        #expect(r.status == .warn)
        #expect(!r.hard)
        #expect(r.remediation?.contains("box login") == true)
    }
}

@Suite("Diagnostics.isUnder path containment")
struct DiagnosticsPathTests {
    @Test("matches the root itself and descendants") func descendants() {
        #expect(Diagnostics.isUnder(path: "/a/b", root: "/a/b"))
        #expect(Diagnostics.isUnder(path: "/a/b/c", root: "/a/b"))
        #expect(Diagnostics.isUnder(path: "/a/b/c/d.bin", root: "/a/b"))
    }

    @Test("does not match siblings or prefixes that aren't path boundaries") func siblings() {
        #expect(!Diagnostics.isUnder(path: "/a/bc", root: "/a/b"))
        #expect(!Diagnostics.isUnder(path: "/x/y", root: "/a/b"))
    }

    @Test("empty inputs are never a match") func empties() {
        #expect(!Diagnostics.isUnder(path: "", root: "/a"))
        #expect(!Diagnostics.isUnder(path: "/a", root: ""))
    }

    @Test("normalizes trailing slashes / dot segments") func normalizes() {
        #expect(Diagnostics.isUnder(path: "/a/b/./c", root: "/a/b/"))
    }
}

@Suite("Diagnostics.claudeCredentialsPresent")
struct DiagnosticsLoginTests {
    @Test("detects .claude/.credentials.json under the agent home") func nested() {
        let p = healthyProbe(pathExists: { $0 == "/home/.claude/.credentials.json" })
        #expect(Diagnostics.claudeCredentialsPresent(in: "/home", probe: p))
    }

    @Test("detects a top-level .credentials.json") func topLevel() {
        let p = healthyProbe(pathExists: { $0 == "/home/.credentials.json" })
        #expect(Diagnostics.claudeCredentialsPresent(in: "/home", probe: p))
    }

    @Test("absent when no candidate exists") func absent() {
        let p = healthyProbe(pathExists: { _ in false })
        #expect(!Diagnostics.claudeCredentialsPresent(in: "/home", probe: p))
    }
}

@Suite("Diagnostics.runAll composition")
struct DiagnosticsRunAllTests {
    @Test("offline run omits the vminit check; online includes it") func onlineToggle() {
        let offline = Diagnostics.runAll(online: false, probe: healthyProbe())
        #expect(!offline.contains { $0.name.contains("vminit") })
        let online = Diagnostics.runAll(online: true, probe: healthyProbe())
        #expect(online.contains { $0.name.contains("vminit") })
    }

    @Test("a fully healthy host passes every check") func allGreen() {
        let results = Diagnostics.runAll(online: true, probe: healthyProbe())
        #expect(results.allSatisfy { $0.status == .pass })
        #expect(!Commands.Doctor.hasHardFailure(results))
    }

    @Test("the six hard checks are all marked hard; soft checks are not") func hardness() {
        let results = Diagnostics.runAll(online: true, probe: healthyProbe())
        let hard = Set(results.filter { $0.hard }.map(\.name))
        // arch, macOS, container, kernel, entitlement, location.
        // (docker is a soft, optional build fallback since the container-build switch.)
        #expect(hard.count == 6)
        for soft in [
            "image present", "vminit", "Claude login",
            "docker present (optional build fallback)",
        ] {
            #expect(result(results, soft).hard == false)
        }
    }
}

@Suite("Diagnostics kernel/image checks via BOX_* / store seams", .serialized)
struct DiagnosticsLiveSeamTests {
    /// Point BOX_DIR at a fresh temp dir and (optionally) BOX_KERNEL, for the
    /// duration of `body`. These set process-global env, so the suite is serial.
    private func withEnv(
        kernel: String?, _ body: (URL) throws -> Void
    ) rethrows {
        try BoxDirEnvLock.withLock {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("box-doctor-\(UUID().uuidString)")
            setenv("BOX_DIR", dir.path, 1)
            let hadKernel = getenv("BOX_KERNEL") != nil
            if let kernel { setenv("BOX_KERNEL", kernel, 1) } else { unsetenv("BOX_KERNEL") }
            defer {
                unsetenv("BOX_DIR")
                if !hadKernel { unsetenv("BOX_KERNEL") }
                try? FileManager.default.removeItem(at: dir)
            }
            try body(dir)
        }
    }

    @Test("BOX_KERNEL set ⇒ kernel check passes via the live probe") func kernelViaEnv() {
        withEnv(kernel: "/tmp/some-vmlinux") { _ in
            #expect(Probe.live.kernelResolves())
            #expect(Diagnostics.checkKernel(.live).status == .pass)
        }
    }

    @Test("empty BOX_DIR ⇒ image check warns (nothing in the store)") func imageAbsent() {
        withEnv(kernel: "/tmp/some-vmlinux") { _ in
            // Fresh, empty BOX_DIR: no image has ever been built/loaded.
            #expect(Probe.live.imageInStore() == false)
            #expect(Diagnostics.checkImage(.live).status == .warn)
        }
    }

    @Test("empty BOX_DIR ⇒ Claude login warns (no credentials persisted)") func loginAbsent() {
        withEnv(kernel: nil) { _ in
            #expect(Diagnostics.checkLogin(.live).status == .warn)
        }
    }
}

@Suite("Commands.Doctor summary & exit policy")
struct DoctorRenderTests {
    private func r(_ name: String, _ status: DiagnosticStatus, hard: Bool) -> DiagnosticResult {
        DiagnosticResult(
            name: name, status: status,
            remediation: status == .pass ? nil : "fix \(name)", hard: hard)
    }

    @Test("summary counts failed / warnings / passed") func summary() {
        let results = [
            r("a", .pass, hard: true),
            r("b", .fail, hard: true),
            r("c", .warn, hard: false),
            r("d", .pass, hard: false),
            r("e", .warn, hard: false),
        ]
        #expect(Commands.Doctor.summaryLine(results) == "1 failed, 2 warnings, 2 passed")
    }

    @Test("a hard failure trips the exit policy") func hardFails() {
        #expect(Commands.Doctor.hasHardFailure([r("x", .fail, hard: true)]))
    }

    @Test("a soft failure (warning) does not trip the exit policy") func softDoesNotFail() {
        #expect(
            !Commands.Doctor.hasHardFailure([
                r("img", .warn, hard: false),
                r("login", .warn, hard: false),
            ]))
    }

    @Test("a non-hard fail does not trip the exit policy") func nonHardFailIgnored() {
        // Defensive: only `hard && .fail` fails the command.
        #expect(!Commands.Doctor.hasHardFailure([r("soft", .fail, hard: false)]))
    }

    @Test("render shows glyphs, indents remediation under failures, and a summary") func render() {
        let results = [
            r("arch", .pass, hard: true),
            r("docker", .fail, hard: true),
            r("image", .warn, hard: false),
        ]
        let out = Commands.Doctor.render(results, verbose: false)
        #expect(out.contains("✔ arch"))
        #expect(out.contains("✖ docker"))
        #expect(out.contains("⚠ image"))
        #expect(out.contains("    → fix docker"))  // remediation indented
        #expect(!out.contains("→ fix arch"))  // passing check has no remediation
        #expect(out.contains("1 failed, 1 warnings, 1 passed"))
    }

    @Test("verbose render adds the detail line under each check") func verbose() {
        let withDetail = DiagnosticResult(
            name: "arch", status: .pass, detail: "uname -m → arm64", hard: true)
        let out = Commands.Doctor.render([withDetail], verbose: true)
        #expect(out.contains("    uname -m → arm64"))
        let terse = Commands.Doctor.render([withDetail], verbose: false)
        #expect(!terse.contains("uname -m"))
    }
}
