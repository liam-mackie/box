import Containerization
import Foundation

/// Bridges the built image into the framework's ImageStore.
///
/// Images build with `container build` (no docker daemon required), then
/// `container image save` emits the OCI layout the framework store loads.
/// Docker survives only as a fallback: if `container build` fails (its builder
/// VM historically had DNS trouble in some setups) and docker is installed, we
/// build there and bridge the docker-archive into the `container` store so the
/// same save→load tail applies.
enum ImageBridge {
    /// Return the image from the store, building + loading it if absent.
    ///
    /// `toolchains` selects a layered variant image (e.g. `box:dotnet-go-rust`).
    /// The empty set resolves to the base `box:latest`: look up the base ref and,
    /// on a miss, run the base build.
    ///
    /// A non-empty set resolves to a layered variant image. Store-existence is the
    /// cache: if the variant ref is already loaded we short-circuit (no rebuild).
    /// On a miss we (1) ensure the base `box:latest` exists (build it if absent,
    /// exactly as the empty path does), (2) merge the toolchains' egress domains
    /// into the global allowlist so the guest picks them up, then (3) build a
    /// derived image (`FROM box:latest` + the toolchain fragments) and load it
    /// under the variant store ref.
    static func ensure(store: ImageStore, toolchains: [String] = []) async throws -> Image {
        guard !toolchains.isEmpty else {
            let ref = Box.storeRef()
            do {
                return try await store.get(reference: ref, pull: false)
            } catch {
                FileHandle.standardError.write(Data("box: image not found, building…\n".utf8))
                try await build(store: store, noCache: false)
                return try await store.get(reference: ref, pull: false)
            }
        }

        // Non-empty set: validate + normalize, then check the variant cache.
        let ids = try Toolchains.validated(toolchains)
        let variantRef = Box.storeRef(toolchains: ids)
        if let cached = try? await store.get(reference: variantRef, pull: false) {
            return cached
        }

        FileHandle.standardError.write(
            Data(
                "box: toolchain image \(Box.imageRef(toolchains: ids)) not found, building…\n".utf8)
        )

        // 1. Ensure the base box:latest exists (build it if missing, as the empty
        //    path does). The derived image `FROM`s it.
        if (try? await store.get(reference: Box.storeRef(), pull: false)) == nil {
            try await build(store: store, noCache: false)
        }

        // 2. Layer the toolchains' egress domains into the global allowlist so the
        //    guest's normal mount+reload picks them up. Persisted + idempotent.
        try mergeToolchainDomains(ids)

        // 3. Build the derived image and load it under the variant store ref.
        try await buildVariant(store: store, toolchains: ids)
        return try await store.get(reference: variantRef, pull: false)
    }

    /// Merge a toolchain set's egress domains into the GLOBAL allowlist file
    /// (`Box.allowlist`), idempotently, logging which domains were added. This is
    /// the simple persisted approach: we only touch the existing allowlist file
    /// (not squid.conf / entrypoint.sh / Runner mounts), so the guest picks the
    /// domains up via the normal mount+reload owned by the allowlist/trust team.
    ///
    /// Uses `Allowlist.conflicts` to drop any domain that would create a squid
    /// leading-dot-vs-bare collision with the existing list (the base allowlist
    /// ships a bare `crates.io`, so the Rust `.crates.io` would otherwise wedge
    /// the proxy — we skip it and warn rather than write an unparseable list).
    static func mergeToolchainDomains(_ toolchains: [String]) throws {
        let domains = try Toolchains.domains(for: toolchains)
        guard !domains.isEmpty else { return }
        try Assets.materialize()

        let existing =
            (try? String(contentsOf: Box.allowlist, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []

        // Filter out any domain that would conflict (dotted vs bare) with the
        // resulting list, accumulating safe additions one at a time.
        var safe: [String] = []
        for d in domains {
            if Allowlist.conflicts(in: existing + safe + [d]).isEmpty {
                safe.append(d)
            } else {
                FileHandle.standardError.write(
                    Data(
                        ("box: skipped toolchain domain \(d): conflicts with an existing allowlist "
                            + "entry for the same host\n").utf8))
            }
        }

        let result = Allowlist.merge(existing: existing, adding: safe)
        guard !result.added.isEmpty else { return }  // already present; no rewrite.
        try result.lines.joined(separator: "\n")
            .write(to: Box.allowlist, atomically: true, encoding: .utf8)
        FileHandle.standardError.write(
            Data(
                "box: added toolchain egress domains: \(result.added.joined(separator: ", "))\n"
                    .utf8))
    }

    /// Build a layered variant image (`FROM box:latest` + the toolchain install
    /// fragments) and load it into the store under the variant ref, reusing the
    /// same `container build` → `container image save` → `store.load` pipeline
    /// as the base build. The derived Dockerfile is written to a fresh temp
    /// build context that `FROM`s the local `box:latest`.
    static func buildVariant(store: ImageStore, toolchains: [String]) async throws {
        guard Sh.exists("container") else {
            throw CBError(
                "the `container` CLI is required to build the image "
                    + "(install it and run `container system start` once)")
        }

        let ctx = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-variant-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: ctx, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: ctx) }

        let dockerfile = try Toolchains.dockerfile(for: toolchains)
        try dockerfile.write(
            to: ctx.appendingPathComponent("Dockerfile"),
            atomically: true, encoding: .utf8)

        let variantRef = Box.imageRef(toolchains: toolchains)
        try buildImage(ref: variantRef, context: ctx.path, noCache: false, buildArgs: [])
        try await loadIntoStore(store: store, imageRef: variantRef)
    }

    /// Keep the image's baked claude-code at least as new as the host's `claude`
    /// (`syncClaudeVersion`, on by default). The guest cannot self-update — the
    /// global npm dir is root-owned and egress is allowlisted — so without this
    /// the box runs whatever version the last `box build`/`update` happened to
    /// bake, forever.
    ///
    /// Best-effort by design: no host `claude`, no existing image (ensure() is
    /// about to build a fresh one at "latest" anyway), or an undeterminable
    /// image version all mean "do nothing"; a failed rebuild warns and runs the
    /// existing image rather than blocking the launch. When the image IS older,
    /// we rebuild pinned to the HOST version — only the CLAUDE_VERSION layer is
    /// invalidated, so the rebuild is fast, and pinning (vs "latest") keeps
    /// guest and host in lockstep. Toolchain variants are re-derived from the
    /// fresh base, else they'd stay stale.
    static func syncClaudeWithHost(store: ImageStore, toolchains: [String]) async {
        func warn(_ s: String) {
            FileHandle.standardError.write(Data((s + "\n").utf8))
        }
        guard let host = Version.hostClaudeVersion() else { return }
        guard (try? await store.get(reference: Box.storeRef(), pull: false)) != nil else { return }

        // The image's version: the sidecar cache when present, else a live
        // query of the image (whose answer repairs the sidecar for next time).
        let image: String
        if let cached = Sidecar.read()?.claudeCode, !cached.isEmpty {
            image = cached
        } else if let queried = try? resolveClaudeVersion() {
            image = queried
            try? Sidecar(
                claudeCode: queried,
                claudeRequested: Sidecar.read()?.claudeRequested
            ).write()
        } else {
            return  // no sidecar and no way to query: can't compare — run what we have
        }

        guard Version.isOlder(image, than: host) else { return }
        warn(
            "box: image claude-code \(image) is older than host \(host) — updating "
                + "(set \"syncClaudeVersion\": false to disable)…")
        do {
            try await build(store: store, noCache: false, buildArgs: claudeBuildArgs(to: host))
            if !toolchains.isEmpty {
                try await buildVariant(store: store, toolchains: Toolchains.validated(toolchains))
            }
            let resolved = (try? resolveClaudeVersion()) ?? host
            try Sidecar(claudeCode: resolved, claudeRequested: host).write()
            warn("box: image now has claude-code \(resolved)")
        } catch {
            warn(
                "box: claude-code sync failed (\(error)); "
                    + "running the existing image (claude-code \(image)).")
        }
    }

    /// Read the claude-code version baked into the built image by running
    /// `claude --version` inside it via `container run` (a throwaway helper
    /// container, not a full box). Works for both the native install and npm.
    static func resolveClaudeVersion() throws -> String {
        let out = try Sh.output([
            "container", "run", "--rm", "--entrypoint", "claude", Box.imageRef(), "--version",
        ])
        guard let v = Version.parseClaudeVersionOutput(out) else {
            throw CBError("could not determine claude-code version from image")
        }
        return v
    }

    static func build(store: ImageStore, noCache: Bool, buildArgs: [String] = []) async throws {
        guard Sh.exists("container") else {
            throw CBError(
                "the `container` CLI is required to build the image "
                    + "(install it and run `container system start` once)")
        }
        try Assets.materialize()
        let imageRef = Box.imageRef()
        try buildImage(
            ref: imageRef, context: Box.dir.path, noCache: noCache,
            buildArgs: buildArgs)
        try await loadIntoStore(store: store, imageRef: imageRef)
    }

    /// Build `ref` from `context` into the `container` CLI's image store,
    /// docker-free. If `container build` fails AND docker is installed, fall
    /// back to the old docker pipeline (docker build, then bridge the
    /// docker-archive into the container store) with a warning — both paths
    /// must land the image in the container store so `loadIntoStore`'s
    /// save→extract→load tail is shared. NOTE the fallback resolves `FROM`
    /// against docker's own cache, so a variant built there needs its base in
    /// docker too — acceptable for a degraded path that announces itself.
    static func buildImage(
        ref: String, context: String, noCache: Bool, buildArgs: [String]
    ) throws {
        var cmd = ["container", "build"]
        if noCache { cmd.append("--no-cache") }
        cmd += buildArgs  // additive `--build-arg KEY=VALUE` tokens (e.g. CLAUDE_VERSION)
        cmd += ["-t", ref, context]
        FileHandle.standardError.write(Data("box: container build → framework store…\n".utf8))
        do {
            try Sh.checked(cmd)
            return
        } catch {
            guard Sh.exists("docker") else { throw error }
            FileHandle.standardError.write(
                Data(
                    "box: `container build` failed (\(error)); falling back to docker…\n".utf8))
        }

        var dcmd = ["docker", "build"]
        if noCache { dcmd.append("--no-cache") }
        dcmd += buildArgs
        dcmd += ["-t", ref, context]
        try Sh.checked(dcmd)

        // Bridge docker-archive → container store so the shared tail applies.
        let dockerTar = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-docker-\(UUID().uuidString).tar").path
        defer { try? FileManager.default.removeItem(atPath: dockerTar) }
        try Sh.checked(["docker", "save", ref, "-o", dockerTar])
        try Sh.checked(["container", "image", "load", "-i", dockerTar])
    }

    /// Load a built image from the `container` CLI's store into the framework
    /// store: `container image save` → OCI layout tar → extract → `store.load`.
    private static func loadIntoStore(store: ImageStore, imageRef: String) async throws {
        let tmp = FileManager.default.temporaryDirectory
        let ociTar = tmp.appendingPathComponent("box-oci-\(UUID().uuidString).tar").path
        let ociDir = tmp.appendingPathComponent("box-oci-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(atPath: ociTar)
            try? FileManager.default.removeItem(at: ociDir)
        }

        try Sh.checked(["container", "image", "save", imageRef, "-o", ociTar])
        try FileManager.default.createDirectory(at: ociDir, withIntermediateDirectories: true)
        try Sh.checked(["tar", "-xf", ociTar, "-C", ociDir.path])
        let imported = try await store.load(from: ociDir)
        for image in imported {
            FileHandle.standardError.write(Data("loaded \(image.reference)\n".utf8))
        }
    }
}
