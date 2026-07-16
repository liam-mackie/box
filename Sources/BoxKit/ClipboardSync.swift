import AppKit
import Containerization
import Foundation

/// Host→guest clipboard IMAGE bridge (`clipboardSync`, on by default).
///
/// Terminal paste only transmits text, so an image copied on the Mac can never
/// reach Claude Code inside the VM on its own: when the TUI sees a paste it
/// asks the SYSTEM clipboard for image data, and the guest's "system clipboard"
/// is an empty Linux VM with no display server. The bridge closes that gap:
///
///  * host side (this file): while a box runs, poll `NSPasteboard.changeCount`
///    (cheap — no data read until the count moves) and, whenever the clipboard
///    holds an image, write it as PNG into a per-run staging dir that is
///    mounted READ-ONLY at `/run/box-clipboard`. A clipboard change to
///    non-image content deletes the file, so a stale image can't be pasted.
///  * guest side: the image ships a clipboard-tool shim that serves
///    `/run/box-clipboard/clipboard.png` to Claude Code's Linux paste path.
///
/// IMAGES ONLY, by design: text clipboards are where passwords and tokens
/// live, so text is never synced. The staging dir is per-run (0700) and
/// removed in the runner's teardown `defer`.
enum ClipboardSync {
    /// Guest path the staging dir is mounted at (read-only).
    static let mountDir = "/run/box-clipboard"
    /// File name the guest shim serves.
    static let fileName = "clipboard.png"

    /// Host-side per-run staging dir.
    static func hostDir(forBoxID id: String) -> URL {
        Box.runDir.appendingPathComponent("clip-\(id)", isDirectory: true)
    }

    /// Stage the per-run dir and return its mount; empty when disabled or the
    /// dir can't be created (best-effort — paste just stays unavailable).
    static func mounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        guard cfg.clipboardSync else { return [] }
        let dir = hostDir(forBoxID: id)
        let fm = FileManager.default
        do {
            try? fm.removeItem(at: dir)  // clear any stale dir from a crashed run
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            FileHandle.standardError.write(
                Data(
                    "box: failed to stage clipboard dir: \(error); image paste disabled\n".utf8))
            return []
        }
        return [.share(source: dir.path, destination: mountDir, options: ["ro"])]
    }

    /// Start the poll loop; the caller cancels the returned task at teardown.
    /// 1s cadence matches the guest's own file polls; data is only read from
    /// the pasteboard when `changeCount` moves.
    static func startPolling(_ cfg: Config, id: String) -> Task<Void, Never>? {
        guard cfg.clipboardSync,
            FileManager.default.fileExists(atPath: hostDir(forBoxID: id).path)
        else { return nil }
        let file = hostDir(forBoxID: id).appendingPathComponent(fileName)
        return Task.detached {
            var lastChange = -1
            while !Task.isCancelled {
                let pasteboard = NSPasteboard.general
                let change = pasteboard.changeCount
                if change != lastChange {
                    lastChange = change
                    if let png = imagePNG(from: pasteboard) {
                        try? png.write(to: file, options: [.atomic])
                    } else {
                        // Non-image clipboard: drop any previous image so the
                        // guest can't paste something stale.
                        try? FileManager.default.removeItem(at: file)
                    }
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    /// The pasteboard's image content as PNG, or nil when it holds none.
    /// Prefers native PNG data; falls back to converting a TIFF flavor (what
    /// most macOS apps put on the pasteboard for images).
    static func imagePNG(from pasteboard: NSPasteboard) -> Data? {
        if let png = pasteboard.data(forType: .png) { return png }
        if let tiff = pasteboard.data(forType: .tiff),
            let rep = NSBitmapImageRep(data: tiff),
            let png = rep.representation(using: .png, properties: [:])
        {
            return png
        }
        return nil
    }
}
