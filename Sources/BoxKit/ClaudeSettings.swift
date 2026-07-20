import Containerization
import Foundation

enum ClaudeSettings {
    static let stagingMountDir = "/run/box-claude-settings"
    static let fileName = "settings.json"
    static let strippedKeys = ["hooks", "statusLine"]

    static func hostDir(forBoxID id: String) -> URL {
        Box.runDir.appendingPathComponent("claude-settings-\(id)", isDirectory: true)
    }

    static func sanitized(_ data: Data) -> Data? {
        guard let obj = try? JSONSerialization.jsonObject(with: data),
            var dict = obj as? [String: Any]
        else { return nil }
        for key in strippedKeys { dict.removeValue(forKey: key) }
        return try? JSONSerialization.data(
            withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
    }

    static func mounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        guard cfg.mountClaudeConfig != .off else { return [] }
        let hostSettings = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude").appendingPathComponent(fileName)
        guard let raw = try? Data(contentsOf: hostSettings),
            let clean = sanitized(raw)
        else { return [] }
        let dir = hostDir(forBoxID: id)
        let fm = FileManager.default
        do {
            try? fm.removeItem(at: dir)
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755])
            try clean.write(to: dir.appendingPathComponent(fileName), options: [.atomic])
        } catch {
            FileHandle.standardError.write(
                Data(
                    ("box: failed to stage sanitized claude settings: \(error); "
                        + "host hooks/statusline may run in the guest\n").utf8))
            return []
        }
        return [.share(source: dir.path, destination: stagingMountDir, options: ["ro"])]
    }
}
