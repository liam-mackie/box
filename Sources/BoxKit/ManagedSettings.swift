import Containerization
import Foundation

/// Guest-only Claude Code *managed settings*, mounted read-only at
/// `/etc/claude-code/managed-settings.json` whenever the host `~/.claude` is
/// shared into the box (`mountClaudeConfig`).
///
/// Why this exists: with `~/.claude` mounted, the host `settings.json` comes
/// along — including a `statusLine` and `hooks` that are *host-shaped* (a `bun`
/// binary at a macOS path, Homebrew CLIs, Mac-only tooling). Inside the Linux
/// microVM those commands don't exist, so they fail silently (blank statusline)
/// or noisily (hook errors). Claude Code MERGES hooks across settings sources,
/// so a higher-precedence file can't *remove* the host hooks — but the
/// enterprise *managed settings* layer (highest precedence, Linux path
/// `/etc/claude-code/managed-settings.json`) supports `disableAllHooks`, which
/// switches off every non-managed hook and, with it, the statusline. We also
/// override `statusLine` with a no-op command as belt-and-suspenders, since the
/// statusline/`disableAllHooks` coupling is not contractually guaranteed.
///
/// This is a *guest* policy file: the host `~/.claude/settings.json` is never
/// touched. box can't hand the guest a sanitized copy of that file directly
/// (the framework shares whole directories, not single files — see the
/// `/run/box-*` staging pattern), so a highest-precedence managed-settings
/// overlay is the mechanism that keeps host-shaped executable config from
/// running in the box.
///
/// The staging dir is mounted at `/run/box-managed` and the ENTRYPOINT (root)
/// installs the file onto the guest rootfs at
/// `/etc/claude-code/managed-settings.json`, root-owned. Mounting the share at
/// `/etc/claude-code` directly does NOT work reliably: virtiofs presents the
/// file as owned by the agent's uid (the host user maps to uid 501), and
/// Claude Code ignores a "managed" policy file owned by the user it
/// constrains (verified empirically — the same file root-owned on the rootfs
/// is honored).
enum ManagedSettings {
    /// Guest path the staging dir is mounted at (read-only). The entrypoint
    /// copies `fileName` from here to `/etc/claude-code` (root-owned) and
    /// unmounts this share.
    static let mountDir = "/run/box-managed"
    /// File name Claude Code reads managed policy from on Linux.
    static let fileName = "managed-settings.json"

    /// The managed-settings payload: disable all non-managed hooks (which also
    /// suppresses the statusline) and, redundantly, pin the statusline to a
    /// no-op command so a host `bun` statusline can never run in the guest.
    static let json = """
        {
          "disableAllHooks": true,
          "statusLine": { "type": "command", "command": "true" }
        }
        """

    /// Host-side per-run staging dir (mirrors `ClipboardSync.hostDir`).
    static func hostDir(forBoxID id: String) -> URL {
        Box.runDir.appendingPathComponent("managed-settings-\(id)", isDirectory: true)
    }

    /// Stage the per-run dir with `managed-settings.json` and return its mount.
    /// Gated on `mountClaudeConfig` — when `~/.claude` isn't shared there's no
    /// host config to neutralize, so project/plugin hooks are left alone. Empty
    /// on failure (best-effort; the box still runs, just without the overlay).
    static func mounts(_ cfg: Config, id: String) -> [Containerization.Mount] {
        guard cfg.mountClaudeConfig != .off else { return [] }
        let dir = hostDir(forBoxID: id)
        let fm = FileManager.default
        do {
            try? fm.removeItem(at: dir)  // clear any stale dir from a crashed run
            try fm.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755])
            try Data(json.utf8).write(
                to: dir.appendingPathComponent(fileName), options: [.atomic])
        } catch {
            FileHandle.standardError.write(
                Data(
                    ("box: failed to stage managed settings: \(error); "
                        + "host hooks/statusline may run in the guest\n").utf8))
            return []
        }
        return [.share(source: dir.path, destination: mountDir, options: ["ro"])]
    }
}
