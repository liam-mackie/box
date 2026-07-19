import Foundation
import Testing

@testable import BoxKit

/// Serialized: these tests set the process-global BOX_DIR env var, so
/// they must not run concurrently with each other. The shared `withTempBoxDir`
/// (BoxDirLock.swift) also serializes against other BOX_DIR suites.
@Suite("Assets.materialize", .serialized)
struct AssetsTests {

    @Test("writes the build context and runtime dirs, with an executable entrypoint")
    func materializesLayout() throws {
        try withTempBoxDir { dir in
            try Assets.materialize()
            let fm = FileManager.default

            for rel in [
                "Dockerfile", "entrypoint.sh", "xclip-shim.sh", "config/allowlist.txt",
                "proxy/Cargo.toml", "proxy/Cargo.lock", "proxy/src/main.rs",
                "proxy/src/proxy.rs",
            ] {
                #expect(
                    fm.fileExists(atPath: dir.appendingPathComponent(rel).path),
                    "missing \(rel)")
            }
            for sub in ["store", "agent-home", "logs", "run", "config"] {
                var isDir: ObjCBool = false
                #expect(
                    fm.fileExists(
                        atPath: dir.appendingPathComponent(sub).path,
                        isDirectory: &isDir) && isDir.boolValue,
                    "missing dir \(sub)")
            }

            let attrs = try fm.attributesOfItem(
                atPath: dir.appendingPathComponent("entrypoint.sh").path)
            let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
            #expect(perms & 0o111 != 0, "entrypoint.sh should be executable")
        }
    }

    @Test("embeds the box-proxy crate source for the image build stage")
    func materializesProxyCrate() throws {
        try withTempBoxDir { dir in
            try Assets.materialize()
            let cargo = try String(
                contentsOf: dir.appendingPathComponent("proxy/Cargo.toml"), encoding: .utf8)
            #expect(cargo.contains("box-proxy"))
            let main = try String(
                contentsOf: dir.appendingPathComponent("proxy/src/main.rs"), encoding: .utf8)
            #expect(!main.isEmpty)
        }
    }

    @Test("preserves a user-edited allowlist on re-materialize")
    func preservesAllowlist() throws {
        try withTempBoxDir { dir in
            try Assets.materialize()
            let allow = dir.appendingPathComponent("config/allowlist.txt")
            let edited = "# my edits\n.example.com\n"
            try edited.write(to: allow, atomically: true, encoding: .utf8)

            try Assets.materialize()  // should NOT clobber the edited allowlist

            #expect(try String(contentsOf: allow, encoding: .utf8) == edited)
        }
    }

    @Test("refreshes code assets (entrypoint) on re-materialize")
    func refreshesCodeAssets() throws {
        try withTempBoxDir { dir in
            try Assets.materialize()
            let entry = dir.appendingPathComponent("entrypoint.sh")
            try "tampered".write(to: entry, atomically: true, encoding: .utf8)

            try Assets.materialize()  // entrypoint is not preserved; should be restored

            let restored = try String(contentsOf: entry, encoding: .utf8)
            #expect(restored != "tampered")
            #expect(restored.contains("BOX_ROLE"))
        }
    }
}
