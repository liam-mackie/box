import Foundation

/// Materializes the embedded build context + default allowlist into the box
/// directory, and ensures the runtime subdirectories exist. The allowlist is
/// preserved if already present (user edits win); everything else is refreshed.
public enum Assets {
    public static func materialize() throws {
        let fm = FileManager.default
        for d in [Box.dir, Box.configDir, Box.agentHome, Box.logsDir, Box.runDir, Box.storeDir] {
            try fm.createDirectory(at: d, withIntermediateDirectories: true)
        }

        for (rel, b64) in EmbeddedAssets.base64 {
            let dst = Box.dir.appendingPathComponent(rel)
            // Preserve the user's live allowlist.
            if rel == "config/allowlist.txt", fm.fileExists(atPath: dst.path) { continue }
            guard let data = Data(base64Encoded: b64) else {
                throw CBError("corrupt embedded asset: \(rel)")
            }
            try fm.createDirectory(
                at: dst.deletingLastPathComponent(),
                withIntermediateDirectories: true)
            try data.write(to: dst)
            if rel == "entrypoint.sh" {
                try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dst.path)
            }
        }
    }
}
