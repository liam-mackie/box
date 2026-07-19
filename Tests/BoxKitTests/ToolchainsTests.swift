import Testing

@testable import BoxKit

@Suite("Toolchains.domains")
struct ToolchainDomainsTests {
    @Test("empty set yields no domains")
    func emptyIsEmpty() throws {
        #expect(try Toolchains.domains(for: []) == [])
    }

    @Test(".NET domains (corrected: dot.net script, no retired azureedge)")
    func dotnetDomains() throws {
        let d = try Toolchains.domains(for: ["dotnet"])
        #expect(
            d == [
                "dot.net", "builds.dotnet.microsoft.com",
                ".dotnet.microsoft.com", "aka.ms", ".nuget.org",
            ])
        #expect(!d.contains("dotnetcli.azureedge.net"))
    }

    @Test("Go domains")
    func goDomains() throws {
        let d = try Toolchains.domains(for: ["go"])
        #expect(d == ["go.dev", "dl.google.com", ".golang.org", "pkg.go.dev"])
    }

    @Test("Rust domains use .crates.io only (no bare crates.io)")
    func rustDomains() throws {
        let d = try Toolchains.domains(for: ["rust"])
        #expect(d == [".rust-lang.org", ".crates.io"])
        #expect(!d.contains("crates.io"))
        // The Rust set must not internally carry a dotted+bare conflict.
        #expect(Allowlist.conflicts(in: d).isEmpty)
    }

    @Test("multiple toolchains union in canonical order, deduped")
    func unionDedup() throws {
        let d = try Toolchains.domains(for: ["rust", "go", "dotnet"])
        // dotnet, go, rust order (sorted ids); each block's domains in registry order.
        #expect(
            d == [
                "dot.net", "builds.dotnet.microsoft.com", ".dotnet.microsoft.com",
                "aka.ms", ".nuget.org",
                "go.dev", "dl.google.com", ".golang.org", "pkg.go.dev",
                ".rust-lang.org", ".crates.io",
            ])
        // No duplicates and no dotted/bare conflicts across the combined set.
        #expect(Set(d).count == d.count)
        #expect(Allowlist.conflicts(in: d).isEmpty)
    }

    @Test("case-insensitive + duplicate requests collapse")
    func caseAndDupeCollapse() throws {
        #expect(
            try Toolchains.domains(for: ["GO", "go", "Go"])
                == ["go.dev", "dl.google.com", ".golang.org", "pkg.go.dev"])
    }

    @Test("unknown toolchain is rejected with a clear error")
    func rejectsUnknown() {
        #expect(throws: CBError.self) {
            _ = try Toolchains.domains(for: ["node"])
        }
        do {
            _ = try Toolchains.domains(for: ["go", "cobol"])
            Issue.record("expected a throw for an unknown toolchain")
        } catch let e as CBError {
            #expect(e.description.contains("cobol"))
            #expect(e.description.contains("supported:"))
        } catch {
            Issue.record("expected CBError, got \(error)")
        }
    }
}

@Suite("Toolchains.dockerfile")
struct ToolchainDockerfileTests {
    @Test("empty set is a bare FROM box:latest passthrough")
    func emptyPassthrough() throws {
        let df = try Toolchains.dockerfile(for: [])
        #expect(df == "FROM box:latest\n")
    }

    @Test("starts FROM the base image ref")
    func fromsBase() throws {
        let df = try Toolchains.dockerfile(for: ["go"])
        #expect(df.hasPrefix("FROM \(Box.imageRef())\n"))
        #expect(df.hasPrefix("FROM box:latest\n"))
    }

    @Test("fragments appear in sorted-id order, deduped")
    func sortedDedupedFragments() throws {
        // Request out of order + duplicated; expect dotnet → go → rust ordering.
        let df = try Toolchains.dockerfile(for: ["rust", "go", "dotnet", "go"])
        guard let dotnetAt = df.range(of: ".NET SDK"),
            let goAt = df.range(of: "Go toolchain"),
            let rustAt = df.range(of: "Rust toolchain")
        else {
            Issue.record("expected all three fragments present")
            return
        }
        #expect(dotnetAt.lowerBound < goAt.lowerBound)
        #expect(goAt.lowerBound < rustAt.lowerBound)
        // Deduped: the Go fragment appears exactly once.
        #expect(df.components(separatedBy: "Go toolchain").count - 1 == 1)
    }

    @Test("uses the dot.net install script, not apt or the retired azureedge host")
    func dotnetScriptNotApt() throws {
        let df = try Toolchains.dockerfile(for: ["dotnet"])
        #expect(df.contains("dot.net/v1/dotnet-install.sh"))
        #expect(!df.contains("dotnetcli.azureedge.net"))
        #expect(!df.contains("apt-get install dotnet"))
    }

    @Test("unknown toolchain is rejected")
    func rejectsUnknown() {
        #expect(throws: CBError.self) {
            _ = try Toolchains.dockerfile(for: ["ruby"])
        }
    }
}

@Suite("Toolchains.detected (project markers)")
struct ToolchainDetectTests {
    @Test("go.mod detects go")
    func goMod() {
        #expect(Toolchains.detected(fromFilenames: ["go.mod", "main.go"]) == ["go"])
    }

    @Test("Cargo.toml detects rust")
    func cargoToml() {
        #expect(Toolchains.detected(fromFilenames: ["Cargo.toml", "src"]) == ["rust"])
    }

    @Test("csproj / fsproj / global.json detect dotnet")
    func dotnetMarkers() {
        #expect(Toolchains.detected(fromFilenames: ["App.csproj"]) == ["dotnet"])
        #expect(Toolchains.detected(fromFilenames: ["App.fsproj"]) == ["dotnet"])
        #expect(Toolchains.detected(fromFilenames: ["global.json"]) == ["dotnet"])
    }

    @Test("marker matching is case-insensitive")
    func caseInsensitive() {
        #expect(Toolchains.detected(fromFilenames: ["GO.MOD"]) == ["go"])
        #expect(Toolchains.detected(fromFilenames: ["cargo.TOML"]) == ["rust"])
        #expect(Toolchains.detected(fromFilenames: ["App.CsProj"]) == ["dotnet"])
        #expect(Toolchains.detected(fromFilenames: ["Global.JSON"]) == ["dotnet"])
    }

    @Test("multiple markers yield a sorted, deduped union")
    func multipleMarkers() {
        let ids = Toolchains.detected(fromFilenames: [
            "Cargo.toml", "go.mod", "App.csproj", "Other.fsproj",
        ])
        #expect(ids == ["dotnet", "go", "rust"])
    }

    @Test("no markers yield an empty set")
    func noMarkers() {
        #expect(Toolchains.detected(fromFilenames: ["README.md", "src", "package.json"]) == [])
        #expect(Toolchains.detected(fromFilenames: []) == [])
    }

    @Test("only exact filenames match, not substrings")
    func exactNames() {
        #expect(Toolchains.detected(fromFilenames: ["not-go.mod.bak", "cargo.toml.orig"]) == [])
    }
}

@Suite("Toolchains.effective (config vs detection)")
struct ToolchainEffectiveTests {
    @Test("default origin uses detection")
    func defaultUsesDetection() {
        #expect(
            Toolchains.effective(configured: [], origin: .default, detected: ["go"]) == ["go"])
    }

    @Test("an explicit configured list wins over detection")
    func explicitWins() {
        #expect(
            Toolchains.effective(configured: ["rust"], origin: .global, detected: ["go"])
                == ["rust"])
        #expect(
            Toolchains.effective(configured: ["rust"], origin: .project, detected: ["go"])
                == ["rust"])
    }

    @Test("an explicit empty list opts out of detection")
    func explicitEmptyOptsOut() {
        #expect(Toolchains.effective(configured: [], origin: .global, detected: ["go"]) == [])
        #expect(Toolchains.effective(configured: [], origin: .project, detected: ["go"]) == [])
    }

    @Test("project-set [] over a global list disables detection (via merge)")
    func projectEmptyOverGlobalList() {
        let m = Config.merged(
            global: ConfigLayer(toolchains: ["go"]), project: ConfigLayer(toolchains: []))
        #expect(m.config.toolchains == [])
        #expect(m.origins.toolchains == .project)
        #expect(
            Toolchains.effective(
                configured: m.config.toolchains, origin: m.origins.toolchains,
                detected: ["rust"]) == [])
    }

    @Test("absent in both layers is default origin, so detection applies (via merge)")
    func absentIsDefault() {
        let m = Config.merged(global: ConfigLayer(), project: ConfigLayer())
        #expect(m.origins.toolchains == .default)
        #expect(
            Toolchains.effective(
                configured: m.config.toolchains, origin: m.origins.toolchains,
                detected: ["dotnet"]) == ["dotnet"])
    }
}

@Suite("Toolchains.cacheDirs")
struct ToolchainCacheDirTests {
    @Test("per-toolchain persistent cache dirs under the agent home")
    func cacheDirs() throws {
        #expect(try Toolchains.cacheDirs(for: ["dotnet"]) == ["~/.nuget/packages"])
        #expect(try Toolchains.cacheDirs(for: ["go"]) == ["~/go/pkg/mod", "~/.cache/go-build"])
        #expect(try Toolchains.cacheDirs(for: ["rust"]) == ["~/.cargo/registry", "~/.cargo/git"])
    }

    @Test("empty set has no cache dirs; combined set unions deduped")
    func emptyAndCombined() throws {
        #expect(try Toolchains.cacheDirs(for: []) == [])
        let c = try Toolchains.cacheDirs(for: ["go", "rust"])
        #expect(c == ["~/go/pkg/mod", "~/.cache/go-build", "~/.cargo/registry", "~/.cargo/git"])
    }
}
