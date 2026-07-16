import Foundation

/// Single source of truth for the per-project language toolchains box can layer
/// on top of the base image: the Dockerfile fragment that installs each SDK, the
/// egress domains it needs, and the persistent cache dirs it uses.
///
/// Selection produces a layered variant image `FROM box:latest` adding only the
/// requested SDKs (tagged by the sorted/deduped set — see `Box.imageRef`). The
/// pure functions here (`domains(for:)`, `dockerfile(for:)`) are filesystem-free
/// so they can be unit-tested without a VM or docker.
public enum Toolchains {
    /// A supported language toolchain.
    public struct Toolchain: Sendable {
        /// Canonical lowercase id (as it appears in `config.toolchains`).
        public let id: String
        /// Dockerfile lines installing the SDK on top of `FROM box:latest`.
        /// Does NOT include the `FROM` line — that's emitted once by `dockerfile`.
        public let fragment: String
        /// Egress allowlist domains this SDK fetches from (squid `dstdomain`
        /// form: a leading dot matches the host and all subdomains).
        public let domains: [String]
        /// Persistent cache dirs under the agent's home (`/home/agent`), where
        /// downloaded packages/build artifacts should live across sessions.
        public let cacheDirs: [String]
    }

    /// The registry of supported toolchains, keyed by canonical id.
    ///
    /// Two egress-domain choices are deliberate:
    ///  - .NET installs via the `dot.net/v1/dotnet-install.sh` script (NOT apt),
    ///    so the retired `dotnetcli.azureedge.net` is intentionally absent.
    ///  - Rust uses `.crates.io` only (the bare `crates.io` is dropped to avoid a
    ///    squid leading-dot vs bare conflict).
    public static let registry: [String: Toolchain] = [
        "dotnet": Toolchain(
            id: "dotnet",
            // Channel pinned to LTS; the install script lands the SDK under
            // /usr/share/dotnet and we expose it on PATH for all users. NuGet
            // packages persist under the agent's home (~/.nuget/packages).
            fragment: """
                # --- .NET SDK (via dot.net/v1/dotnet-install.sh, not apt) ---
                USER root
                RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \\
                    && chmod +x /tmp/dotnet-install.sh \\
                    && /tmp/dotnet-install.sh --channel LTS --install-dir /usr/share/dotnet \\
                    && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \\
                    && rm -f /tmp/dotnet-install.sh
                ENV DOTNET_ROOT=/usr/share/dotnet \\
                    DOTNET_CLI_TELEMETRY_OPTOUT=1 \\
                    DOTNET_NOLOGO=1
                """,
            domains: [
                "dot.net",
                "builds.dotnet.microsoft.com",
                ".dotnet.microsoft.com",
                "aka.ms",
                ".nuget.org",
            ],
            cacheDirs: ["~/.nuget/packages"]
        ),
        "go": Toolchain(
            id: "go",
            // Official tarball from go.dev (redirects to dl.google.com); module
            // cache + build cache persist under the agent's home.
            fragment: """
                # --- Go toolchain (official go.dev tarball) ---
                USER root
                ARG GO_VERSION=1.22.5
                RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" -o /tmp/go.tgz \\
                    && tar -C /usr/local -xzf /tmp/go.tgz \\
                    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \\
                    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \\
                    && rm -f /tmp/go.tgz
                ENV PATH=/usr/local/go/bin:$PATH
                """,
            domains: [
                "go.dev",
                "dl.google.com",
                ".golang.org",
                "pkg.go.dev",
            ],
            cacheDirs: ["~/go/pkg/mod", "~/.cache/go-build"]
        ),
        "rust": Toolchain(
            id: "rust",
            // rustup from rust-lang.org installs into the agent's home; cargo's
            // registry + git caches persist under ~/.cargo.
            fragment: """
                # --- Rust toolchain (rustup from rust-lang.org) ---
                USER agent
                ENV RUSTUP_HOME=/home/agent/.rustup \\
                    CARGO_HOME=/home/agent/.cargo \\
                    PATH=/home/agent/.cargo/bin:$PATH
                RUN curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \\
                    && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \\
                    && rm -f /tmp/rustup-init.sh
                USER root
                """,
            domains: [
                ".rust-lang.org",
                ".crates.io",
            ],
            cacheDirs: ["~/.cargo/registry", "~/.cargo/git"]
        ),
    ]

    /// Canonical sorted list of supported ids (for error messages).
    public static var supported: [String] { registry.keys.sorted() }

    /// Validate + normalize a requested toolchain set: lowercase, dedupe, sort.
    /// Throws `CBError` on any unknown id (listing what's supported).
    public static func validated(_ requested: [String]) throws -> [String] {
        let normalized = Set(requested.map { $0.lowercased() }).sorted()
        let unknown = normalized.filter { registry[$0] == nil }
        guard unknown.isEmpty else {
            throw CBError(
                "unknown toolchain(s): \(unknown.joined(separator: ", ")). "
                    + "supported: \(supported.joined(separator: ", "))")
        }
        return normalized
    }

    /// The egress domains required by a toolchain set: the deduped union of each
    /// toolchain's domains, in canonical (sorted-toolchain) order. Empty set ⇒
    /// no domains. Pure; validates ids (throws on unknown).
    public static func domains(for requested: [String]) throws -> [String] {
        let ids = try validated(requested)
        var out: [String] = []
        var seen = Set<String>()
        for id in ids {
            for d in registry[id]!.domains where seen.insert(d).inserted {
                out.append(d)
            }
        }
        return out
    }

    /// The persistent cache dirs (under `/home/agent`) for a toolchain set,
    /// deduped in canonical order. Pure; validates ids (throws on unknown).
    public static func cacheDirs(for requested: [String]) throws -> [String] {
        let ids = try validated(requested)
        var out: [String] = []
        var seen = Set<String>()
        for id in ids {
            for c in registry[id]!.cacheDirs where seen.insert(c).inserted {
                out.append(c)
            }
        }
        return out
    }

    /// The derived Dockerfile for a toolchain set: `FROM box:latest` followed by
    /// each requested toolchain's install fragment, in canonical (sorted) order.
    /// Empty set ⇒ a bare `FROM box:latest` passthrough. Pure; validates ids
    /// (throws on unknown).
    public static func dockerfile(for requested: [String]) throws -> String {
        let ids = try validated(requested)
        var lines = ["FROM \(Box.imageRef())"]
        for id in ids {
            lines.append("")
            lines.append(registry[id]!.fragment)
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
