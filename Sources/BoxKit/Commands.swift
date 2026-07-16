import Containerization
import Foundation

/// Public command facade the executable target drives. Keeps argument parsing
/// (in the `box` target) separate from behavior (here, in the kit).
public enum Commands {
    public static func run(extraArgs: [String]) async throws -> Int32 {
        try await Runner.runBox(
            command: ["claude"] + extraArgs, interactive: true,
            claudeRun: true)
    }

    /// Open a shell. If a box is already running for this directory, attach a
    /// NEW shell inside that same microVM (via its exec socket) so you can run
    /// background commands/servers next to the live Claude session; `--new`
    /// forces a separate VM.
    public static func shell(extraArgs: [String], new: Bool = false) async throws -> Int32 {
        if !new {
            let cwd = FileManager.default.currentDirectoryPath
            if let match = RunState.list().first(where: { $0.cwd == cwd }),
                ExecClient.available(forBoxID: match.id)
            {
                FileHandle.standardError.write(
                    Data(
                        ("box: attaching to running box \(match.id) "
                            + "(use --new for a separate VM)\n").utf8))
                return try ExecClient.run(boxID: match.id, command: ["bash"] + extraArgs)
            }
        }
        return try await Runner.runBox(command: ["bash"] + extraArgs, interactive: true)
    }

    /// Run a command (default: an interactive shell) inside a RUNNING box.
    /// Target: `--box <id>`, else the box running in this directory, else the
    /// only running box.
    public static func exec(box: String?, command: [String]) throws -> Int32 {
        let id: String
        if let box {
            id = box
        } else {
            let cwd = FileManager.default.currentDirectoryPath
            let running = RunState.list()
            if let match = running.first(where: { $0.cwd == cwd }) {
                id = match.id
            } else if running.count == 1 {
                id = running[0].id
            } else if running.isEmpty {
                throw CBError("no running boxes — start one with `box` first (`box ls` to check).")
            } else {
                throw CBError(
                    "multiple boxes running; pick one with --box <id>:\n"
                        + running.map { "  \($0.id)\t\($0.cwd)" }.joined(separator: "\n"))
            }
        }
        guard ExecClient.available(forBoxID: id) else {
            throw CBError(
                "box \"\(id)\" has no exec socket — it isn't running, or was "
                    + "launched by a box version without `box exec`.")
        }
        return try ExecClient.run(boxID: id, command: command)
    }

    public static func login() async throws -> Int32 {
        try await Runner.runBox(command: ["claude", "/login"], interactive: true)
    }

    public static func build(noCache: Bool) async throws {
        let store = try ImageStore(path: Box.storeDir)
        try await ImageBridge.build(store: store, noCache: noCache)
        print("image ready: \(Box.imageRef())")
        // Record the baked claude-code version so `box version` and the
        // launch-time sync compare against reality, not a stale sidecar.
        if let resolved = try? ImageBridge.resolveClaudeVersion() {
            try Sidecar(claudeCode: resolved, claudeRequested: "latest").write()
            print("claude-code: \(resolved)")
        }
    }

    /// Add domains to the allowlist; running boxes pick the change up live.
    ///
    /// With no `domains`, drops into the interactive `denied → allow` promotion
    /// flow (a numbered menu of recently-blocked hosts). `all`/`yes` are the
    /// headless escape: promote every denied host as a wildcard non-interactively.
    ///
    /// `project: true` writes to the discovered project `.box/allowlist.txt`
    /// (creating `.box/` if needed) instead of the global file. Note this changes
    /// the project allowlist's content hash, so it must be re-approved with
    /// `box trust` before a box honors it (fail-closed).
    public static func allow(
        _ domains: [String] = [], all: Bool = false, yes: Bool = false, project: Bool = false
    ) throws {
        if project {
            guard !domains.isEmpty else {
                throw CBError(
                    "box allow --project requires one or more domains "
                        + "(the denied→allow promotion flow only edits the global allowlist).")
            }
            try writeProjectAllowlist(adding: domains)
            return
        }
        if domains.isEmpty {
            try promoteDenied(all: all, yes: yes)
            return
        }
        try Assets.materialize()
        try writeAllowlistAndReload(adding: domains)
    }

    /// Merge `adding` into the discovered project's `.box/allowlist.txt`, creating
    /// `.box/` in the cwd if no project dir is found above it. Project allowlists
    /// are NOT live-reloaded (they're snapshotted at launch under the trust model),
    /// and editing one invalidates its trust, so we point the user at `box trust`.
    static func writeProjectAllowlist(adding domains: [String]) throws {
        let fm = FileManager.default
        let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)
        let home = fm.homeDirectoryForCurrentUser

        // Use an existing project `.box/` if discoverable; otherwise create one in cwd.
        let boxDir: URL
        if let found = Config.projectConfigDir(startingFrom: cwd, stopAt: home) {
            boxDir = found
        } else {
            boxDir = cwd.appendingPathComponent(".box", isDirectory: true)
            try fm.createDirectory(at: boxDir, withIntermediateDirectories: true)
            print("created \(boxDir.path)")
        }

        let allowlistURL = boxDir.appendingPathComponent("allowlist.txt")
        let existing =
            (try? String(contentsOf: allowlistURL, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []
        let result = Allowlist.merge(existing: existing, adding: domains)
        for d in result.added { print("added: \(d)") }
        for d in result.skipped { print("already allowed: \(d)") }
        guard !result.added.isEmpty else { return }
        try result.lines.joined(separator: "\n")
            .write(to: allowlistURL, atomically: true, encoding: .utf8)
        print("wrote \(allowlistURL.path)")
        print("note: this project allowlist must be approved before a box honors it —")
        print("      run `box trust` (or `box trust --allowlist-only`).")
    }

    /// Merge `adding` into the live allowlist, print per-domain results, write it
    /// atomically, and report the live-reload status. Shared by `box allow
    /// <domains>` and the interactive promotion flow so the write/reload tail
    /// lives in one place. Assumes assets are already materialized.
    static func writeAllowlistAndReload(adding domains: [String]) throws {
        let existing =
            (try? String(contentsOf: Box.allowlist, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []
        let result = Allowlist.merge(existing: existing, adding: domains)
        for d in result.added { print("added: \(d)") }
        for d in result.skipped { print("already allowed: \(d)") }
        guard !result.added.isEmpty else {
            // Nothing changed — don't rewrite the file or claim a reload.
            return
        }
        try result.lines.joined(separator: "\n")
            .write(to: Box.allowlist, atomically: true, encoding: .utf8)
        let running = RunState.list().count
        print(
            running > 0
                ? "reloaded live in \(running) running box(es)."
                : "(no running box; applies on next launch)")
    }

    /// Interactive (and headless) promotion of recently-denied hosts into the
    /// allowlist. Reuses `denied()` for host extraction, `DeniedHost.normalize`
    /// to map raw log tokens to candidate entries, and `Allowlist.conflicts` to
    /// skip a dotted+bare collision that would wedge squid.
    public static func promoteDenied(all: Bool = false, yes: Bool = false) throws {
        // Deduplicate + normalize the raw denied hosts, preserving sorted order
        // (denied() already returns them sorted and uniqued by raw token).
        var seen = Set<String>()
        let candidates: [(exact: String, wildcard: String)] = denied().compactMap { raw in
            guard let n = DeniedHost.normalize(raw) else { return nil }
            guard seen.insert(n.exact).inserted else { return nil }
            return n
        }

        guard !candidates.isEmpty else {
            print("(no denied hosts to promote)")
            return
        }

        try Assets.materialize()
        let existing =
            (try? String(contentsOf: Box.allowlist, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []

        // Headless escape: --all (+ optional --yes) promotes everything as a
        // wildcard, no prompts.
        if all || yes {
            try addPromoted(candidates.map(\.wildcard), existing: existing)
            return
        }

        // No flags + non-TTY: we can't prompt. Print guidance and bail.
        guard isatty(STDIN_FILENO) == 1 else {
            print("denied hosts available to promote:")
            for c in candidates { print("  \(c.exact)") }
            print("")
            print("stdin is not a TTY — re-run with `--all --yes` to promote all as wildcards,")
            print("or pass explicit domains: `box allow .\(candidates[0].exact)`")
            return
        }

        // Interactive numbered menu.
        print("Recently denied hosts:")
        for (i, c) in candidates.enumerated() { print("  \(i + 1). \(c.exact)") }
        print("")
        print("Select hosts to allow (e.g. 1,3  or  1-3  or  all  or  q to quit):")
        FileHandle.standardOutput.write(Data("> ".utf8))

        guard let line = readLine(strippingNewline: true) else { return }
        guard let selection = DeniedHost.parseSelection(line, count: candidates.count) else {
            print("invalid selection.")
            return
        }
        guard !selection.isEmpty else {
            print("nothing selected.")
            return
        }

        var toAdd: [String] = []
        for idx in selection.sorted() {
            let c = candidates[idx - 1]
            // Offer exact vs subdomain (default: subdomain/wildcard).
            FileHandle.standardOutput.write(
                Data("Allow \(c.exact) — [s]ubdomains (.\(c.exact)) / [e]xact / s[k]ip? [s]: ".utf8)
            )
            let answer = (readLine(strippingNewline: true) ?? "")
                .trimmingCharacters(in: .whitespaces).lowercased()
            switch answer {
            case "", "s", "subdomains": toAdd.append(c.wildcard)
            case "e", "exact": toAdd.append(c.exact)
            case "k", "skip": continue
            default: print("  (unrecognized — skipping \(c.exact))")
            }
        }

        guard !toAdd.isEmpty else {
            print("nothing to add.")
            return
        }
        try addPromoted(toAdd, existing: existing)
    }

    /// Filter out any entry that would create a dotted+bare squid conflict with
    /// the resulting list, then write + reload via the shared tail.
    private static func addPromoted(_ toAdd: [String], existing: [String]) throws {
        var safe: [String] = []
        for entry in toAdd {
            if Allowlist.conflicts(in: existing + safe + [entry]).isEmpty {
                safe.append(entry)
            } else {
                print("skipped \(entry): would conflict with an existing entry for the same host.")
            }
        }
        guard !safe.isEmpty else {
            print("nothing to add.")
            return
        }
        try writeAllowlistAndReload(adding: safe)
    }

    /// Hosts squid recently blocked, sorted — the plain list the promotion flow
    /// (`box allow`, `box denied -i`) builds its menu from.
    public static func denied() -> [String] {
        deniedReport().map(\.host).sorted()
    }

    /// Rich `box denied` data: every per-box log under `Box.logsDir` plus the
    /// legacy shared `access.log`, aggregated per host with session attribution
    /// (see `EgressLog.deniedReport` for the dedupe rules).
    public static func deniedReport() -> [EgressLog.DeniedHostReport] {
        let fm = FileManager.default
        var perBox: [(id: String, lines: [String])] = []
        let dirs =
            (try? fm.contentsOfDirectory(
                at: Box.logsDir, includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles])) ?? []
        for dir in dirs
        where (try? dir.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true {
            let log = dir.appendingPathComponent("access.log")
            guard let content = try? String(contentsOf: log, encoding: .utf8) else { continue }
            perBox.append((dir.lastPathComponent, content.components(separatedBy: "\n")))
        }
        let shared =
            (try? String(
                contentsOf: Box.logsDir.appendingPathComponent("access.log"),
                encoding: .utf8))?
            .components(separatedBy: "\n") ?? []
        return EgressLog.deniedReport(perBox: perBox, shared: shared)
    }

    /// Print the `box denied` table: host, denial count, last denial, and the
    /// session(s) — box id(s) — it was denied in.
    public static func showDenied() {
        let report = deniedReport()
        guard !report.isEmpty else {
            print("(no denials logged yet)")
            return
        }
        // Host column sized to the longest host so a long name can't run into
        // the next column.
        let hostWidth = max(34, (report.map(\.host.count).max() ?? 0) + 2)
        print(pad("HOST", hostWidth) + pad("COUNT", 7) + pad("LAST DENIED", 17) + "SESSION")
        var unattributed = false
        for r in report {
            let sessions = r.sessions.isEmpty ? "-" : r.sessions.joined(separator: ", ")
            if r.sessions.isEmpty { unattributed = true }
            print(
                pad(r.host, hostWidth) + pad(String(r.count), 7)
                    + pad(logTimeFormatter.string(from: r.lastSeen), 17) + sessions)
        }
        if unattributed {
            print("")
            print("(\"-\" = denied by a box running an older image with no per-session log)")
        }
    }

    public static func listBoxes() -> [(id: String, cwd: String)] {
        RunState.list()
    }

    // MARK: - Egress log

    /// Show the egress audit log. Resolves which box(es) to read, parses their
    /// per-box `access.log` via the pure `EgressLog` core, then renders a table
    /// (or JSON), with `--denied`/`--since` filters and an optional `--follow`
    /// tail.
    public static func log(
        follow: Bool, denied: Bool, since: String?, box: String?, all: Bool, json: Bool
    ) throws {
        let cutoff = try since.map { try EgressLog.resolveSince($0) }
        let logFiles = try resolveLogFiles(box: box, all: all)

        func snapshot() -> [EgressEntry] {
            var entries: [EgressEntry] = []
            for url in logFiles {
                guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }
                entries.append(contentsOf: EgressLog.parse(content.components(separatedBy: "\n")))
            }
            entries.sort { $0.timestamp < $1.timestamp }
            if denied { entries = EgressLog.denied(entries) }
            if let cutoff { entries = EgressLog.since(entries, cutoff) }
            return entries
        }

        let initial = snapshot()
        if json {
            printJSON(initial)
        } else {
            printTableHeader()
            for e in initial { print(renderRow(e)) }
            if initial.isEmpty { print("(no egress recorded yet)") }
        }

        guard follow else { return }
        // Poll for new entries (matches the host-side simplicity of the guest's
        // 2s file poll). We track how many lines we've emitted per file to avoid
        // reprinting; filters still apply to each new entry.
        var seen = initial.count
        while true {
            Thread.sleep(forTimeInterval: 1)
            let current = snapshot()
            if current.count > seen {
                let fresh = current[seen...]
                if json {
                    for e in fresh { print(jsonObject(e)) }
                } else {
                    for e in fresh { print(renderRow(e)) }
                }
                seen = current.count
            }
        }
    }

    /// Resolve the set of per-box `access.log` files to read.
    /// `--box <id>` → that box; `--all` → every box log dir; default → the box
    /// whose cwd matches this directory, else the most-recently-modified log.
    private static func resolveLogFiles(box: String?, all: Bool) throws -> [URL] {
        let fm = FileManager.default
        func logFile(_ id: String) -> URL {
            Box.logDir(forBoxID: id).appendingPathComponent("access.log")
        }

        if let box {
            let f = logFile(box)
            guard fm.fileExists(atPath: f.path) else {
                throw CBError("no log for box \"\(box)\" (looked in \(f.path))")
            }
            return [f]
        }

        // All per-box log directories under logsDir (each holds an access.log).
        let dirs =
            (try? fm.contentsOfDirectory(
                at: Box.logsDir,
                includingPropertiesForKeys: [.contentModificationDateKey],
                options: [.skipsHiddenFiles])) ?? []
        let boxLogs =
            dirs
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true }
            .map { $0.appendingPathComponent("access.log") }
            .filter { fm.fileExists(atPath: $0.path) }

        if all {
            guard !boxLogs.isEmpty else {
                throw CBError("no box logs found under \(Box.logsDir.path)")
            }
            return boxLogs
        }

        // Default: the box matching the current directory, if one is running.
        let cwd = fm.currentDirectoryPath
        if let match = RunState.list().first(where: { $0.cwd == cwd }) {
            let f = logFile(match.id)
            if fm.fileExists(atPath: f.path) { return [f] }
        }

        // Else the most-recently-modified per-box log.
        let newest = boxLogs.max {
            let a =
                (try? $0.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            let b =
                (try? $1.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            return a < b
        }
        guard let newest else {
            throw CBError("no box logs found under \(Box.logsDir.path); run a box first")
        }
        return [newest]
    }

    // MARK: - `box log` rendering

    private static let logTimeFormatter: DateFormatter = {
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.dateFormat = "MM-dd HH:mm:ss"
        return df
    }()

    /// Left-pad-to-width helper (NSString width specifiers don't pad reliably).
    private static func pad(_ s: String, _ width: Int) -> String {
        s.count >= width ? s : s + String(repeating: " ", count: width - s.count)
    }

    private static func printTableHeader() {
        print(
            pad("TIME", 16) + pad("HOST", 34) + pad("METHOD", 9)
                + pad("STATUS", 18) + "BYTES")
    }

    private static func renderRow(_ e: EgressEntry) -> String {
        let time = logTimeFormatter.string(from: e.timestamp)
        let status = "\(e.resultCode)/\(e.httpStatus)"
        return pad(time, 16) + pad(e.host, 34) + pad(e.method, 9)
            + pad(status, 18) + EgressLog.formatBytes(e.bytes)
    }

    private static func jsonObject(_ e: EgressEntry) -> String {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func esc(_ s: String) -> String {
            s.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
        }
        let sniField = e.sni.map { "\"\(esc($0))\"" } ?? "null"
        return "{\"time\":\"\(iso.string(from: e.timestamp))\","
            + "\"client\":\"\(esc(e.client))\","
            + "\"host\":\"\(esc(e.host))\","
            + "\"method\":\"\(esc(e.method))\","
            + "\"url\":\"\(esc(e.url))\","
            + "\"resultCode\":\"\(esc(e.resultCode))\","
            + "\"httpStatus\":\(e.httpStatus),"
            + "\"bytes\":\(e.bytes),"
            + "\"denied\":\(e.isDenied),"
            + "\"sni\":\(sniField)}"
    }

    private static func printJSON(_ entries: [EgressEntry]) {
        print("[" + entries.map(jsonObject).joined(separator: ",\n ") + "]")
    }

    // MARK: - Lifecycle

    public static func doctor(online: Bool, verbose: Bool) throws {
        let results = Diagnostics.runAll(online: online)
        print(Doctor.render(results, verbose: verbose))
        // Exit nonzero only when a HARD check fails; warnings never fail.
        if Doctor.hasHardFailure(results) {
            throw CBError(Doctor.summaryLine(results))
        }
    }

    /// Pure rendering/exit-policy for `box doctor`, kept here (not in
    /// `Diagnostics`) so the checks stay free of presentation concerns.
    enum Doctor {
        /// Render the checklist: a glyph + name per result, the remediation
        /// indented under any non-passing check, the detail line under each
        /// check in verbose mode, then a trailing summary line.
        static func render(_ results: [DiagnosticResult], verbose: Bool) -> String {
            var lines: [String] = []
            for r in results {
                lines.append("\(r.status.glyph) \(r.name)")
                if verbose, let d = r.detail {
                    lines.append("    \(d)")
                }
                if r.status != .pass, let rem = r.remediation {
                    lines.append("    → \(rem)")
                }
            }
            lines.append("")
            lines.append(summaryLine(results))
            return lines.joined(separator: "\n")
        }

        /// `N failed, M warnings, K passed`.
        static func summaryLine(_ results: [DiagnosticResult]) -> String {
            let failed = results.filter { $0.status == .fail }.count
            let warnings = results.filter { $0.status == .warn }.count
            let passed = results.filter { $0.status == .pass }.count
            return "\(failed) failed, \(warnings) warnings, \(passed) passed"
        }

        /// A hard failure is a `.fail` on a check marked `hard` — only these
        /// fail the command.
        static func hasHardFailure(_ results: [DiagnosticResult]) -> Bool {
            results.contains { $0.hard && $0.status == .fail }
        }
    }

    public static func update(to version: String?) async throws {
        let store = try ImageStore(path: Box.storeDir)
        let requested = version ?? "latest"
        // Rebuild WITHOUT --no-cache so only the Claude layer (gated by the
        // CLAUDE_VERSION build arg) is invalidated; apt layers are reused.
        try await ImageBridge.build(
            store: store, noCache: false, buildArgs: claudeBuildArgs(to: version))
        print("image ready: \(Box.imageRef())")

        // Capture the resolved claude-code version into the sidecar. The real
        // version lives inside the freshly built image; query it via docker
        // (no VM boot). If the query fails, still record what was requested.
        let resolved = (try? ImageBridge.resolveClaudeVersion()) ?? requested
        try Sidecar(claudeCode: resolved, claudeRequested: requested).write()
        print("claude-code: \(resolved)")
    }

    public static func version(refresh: Bool) throws {
        let info = Version.all(refresh: refresh)
        print("box:               \(info.box)")
        print("claude-code:       \(info.claudeCode)")
        print("containerization:  \(info.containerization)")
        print("vminit:            \(info.vminit)")
    }

    /// Stop a running box. Daemonless: the VM is a child of the launching `box`
    /// process, so we signal the pid embedded in the id. A plain SIGTERM is
    /// caught by `runBox`'s handler, which runs graceful teardown (RunState.remove
    /// + manager.delete); `--kill` escalates to SIGKILL (no teardown — the marker
    /// goes stale and is reaped by `box prune`/`box rm`).
    public static func stop(id: String, kill killHard: Bool) throws {
        // Honest about the daemonless model: if the launching process is already
        // gone, there's nothing to stop. Just reap any stale marker so `box ls`
        // is accurate, and tell the user.
        guard let pid = RunState.pid(fromID: id) else {
            throw CBError("box stop: \"\(id)\" is not a valid box id (expected box-<dir>-<pid>).")
        }
        guard kill(pid, 0) == 0 else {
            RunState.remove(id: id)
            print("box \"\(id)\" is not running (removed stale marker).")
            return
        }
        guard RunState.stop(id: id, kill: killHard) else {
            throw CBError("box stop: failed to signal box \"\(id)\" (pid \(pid)).")
        }
        if killHard {
            print(
                "sent SIGKILL to box \"\(id)\" (pid \(pid)) — no graceful teardown; "
                    + "run `box prune` to reap its marker.")
        } else {
            print("sent SIGTERM to box \"\(id)\" (pid \(pid)); it will tear down gracefully.")
        }
    }

    /// Stop the box if it's running, then remove its marker and any leftover
    /// per-run state. Idempotent: for a dead pid we just delete the stale marker
    /// (and staging dirs). A graceful stop already removes these via `runBox`'s
    /// `defer`, so the explicit cleanup here is a backstop (and the only cleanup
    /// after a `--force`/SIGKILL stop).
    public static func rm(id: String, force: Bool) throws {
        guard RunState.pid(fromID: id) != nil else {
            throw CBError("box rm: \"\(id)\" is not a valid box id (expected box-<dir>-<pid>).")
        }
        let running = RunState.list().contains { $0.id == id }
        if running {
            // Reuse the stop path. `--force` escalates to SIGKILL.
            try stop(id: id, kill: force)
        }
        removePerRunState(id: id)
        print(running ? "removed box \"\(id)\"." : "removed stale box \"\(id)\".")
    }

    /// Remove a box's marker plus the per-run staging dirs the runner creates
    /// (secrets dir, trusted-project-allowlist snapshot). All no-ops if absent.
    private static func removePerRunState(id: String) {
        let fm = FileManager.default
        RunState.remove(id: id)
        try? fm.removeItem(at: Box.secretDir(forBoxID: id))
        try? fm.removeItem(at: Box.runDir.appendingPathComponent("proj-allow-\(id)"))
        try? fm.removeItem(at: ClipboardSync.hostDir(forBoxID: id))
    }

    /// What `box prune` should do for a given set of flags + running-box count.
    /// Kept pure (no FS, no IO) so the option/confirmation logic is unit-testable;
    /// the command body below turns this into real deletions + prompts.
    struct PruneDecision: Equatable {
        /// Persistent directories selected for deletion (a subset of `Target`).
        var targets: [Target]
        /// True when destructive targets are selected and boxes are still running
        /// without `--force` — the command must refuse.
        var refuseRunning: Bool

        /// Persistent state a destructive flag can wipe. `label`/recovery wording
        /// lives with the command body (presentation), not here.
        enum Target: String, CaseIterable, Equatable {
            case agentHome, store, logs
        }

        /// True when there's a destructive deletion to perform.
        var isDestructive: Bool { !targets.isEmpty }
    }

    /// Pure decision: map the flags + running count to a `PruneDecision`. `--all`
    /// selects every destructive target. Refusal triggers only when something
    /// destructive is selected, a box is running, and `--force` was not passed —
    /// stale-marker pruning (the default, no flags) always proceeds.
    static func pruneDecision(
        agentHome: Bool, store: Bool, logs: Bool, all: Bool,
        force: Bool, runningCount: Int
    ) -> PruneDecision {
        var targets: [PruneDecision.Target] = []
        if all || agentHome { targets.append(.agentHome) }
        if all || store { targets.append(.store) }
        if all || logs { targets.append(.logs) }
        let refuse = !targets.isEmpty && runningCount > 0 && !force
        return PruneDecision(targets: targets, refuseRunning: refuse)
    }

    public static func prune(
        agentHome: Bool, store: Bool, logs: Bool, all: Bool, yes: Bool, force: Bool
    ) throws {
        // Always reap stale markers first (dead pids). This is the safe default
        // and runs even alongside destructive flags.
        let reaped = RunState.pruneStale()
        if reaped.isEmpty {
            print("no stale box markers to remove.")
        } else {
            print("removed \(reaped.count) stale box marker(s): \(reaped.joined(separator: ", "))")
        }

        let running = RunState.list()
        let decision = pruneDecision(
            agentHome: agentHome, store: store, logs: logs, all: all,
            force: force, runningCount: running.count)

        guard decision.isDestructive else { return }

        if decision.refuseRunning {
            let ids = running.map(\.id).joined(separator: ", ")
            throw CBError(
                "box prune: refusing to delete persistent state while "
                    + "\(running.count) box(es) are running (\(ids)). Stop them first, "
                    + "or re-run with --force.")
        }

        // Describe exactly what will be deleted, with the recovery command.
        print("")
        print("This will permanently delete:")
        for t in decision.targets {
            let d = pruneTargetDescription(t)
            print("  \(d.warning) \(d.path)\(d.note.map { " — \($0)" } ?? "")")
        }
        print("Recover with: \(recoveryHint(for: decision.targets))")

        // Confirm unless --yes.
        if !yes {
            FileHandle.standardOutput.write(Data("Proceed? [y/N]: ".utf8))
            let answer = (readLine(strippingNewline: true) ?? "")
                .trimmingCharacters(in: .whitespaces).lowercased()
            guard answer == "y" || answer == "yes" else {
                print("aborted; nothing deleted.")
                return
            }
        }

        let fm = FileManager.default
        for t in decision.targets {
            let url = pruneTargetURL(t)
            do {
                try fm.removeItem(at: url)
                print("deleted \(url.path)")
            } catch {
                // Missing dir isn't an error (idempotent); report anything else.
                if fm.fileExists(atPath: url.path) {
                    FileHandle.standardError.write(
                        Data("box prune: failed to delete \(url.path): \(error)\n".utf8))
                } else {
                    print("\(url.path) (already absent)")
                }
            }
        }
    }

    /// Host directory each destructive prune target maps to.
    private static func pruneTargetURL(_ t: PruneDecision.Target) -> URL {
        switch t {
        case .agentHome: return Box.agentHome
        case .store: return Box.storeDir
        case .logs: return Box.logsDir
        }
    }

    /// Presentation for a destructive prune target: a warning glyph, its path,
    /// and an optional caveat.
    private static func pruneTargetDescription(
        _ t: PruneDecision.Target
    ) -> (warning: String, path: String, note: String?) {
        switch t {
        case .agentHome:
            return (
                "⚠", Box.agentHome.path, "Claude login/credentials — you'll need `box login` again"
            )
        case .store:
            return ("⚠", Box.storeDir.path, "image cache — rebuild with `box build`")
        case .logs:
            return ("⚠", Box.logsDir.path, "egress logs")
        }
    }

    /// Recovery command(s) for the selected destructive targets.
    private static func recoveryHint(for targets: [PruneDecision.Target]) -> String {
        var cmds: [String] = []
        if targets.contains(.agentHome) { cmds.append("box login") }
        if targets.contains(.store) { cmds.append("box build") }
        return cmds.isEmpty ? "(nothing to restore)" : cmds.joined(separator: ", then ")
    }

    // MARK: - Project trust

    /// Approve the current content of this project's `.box/` so its components are
    /// honored. `box trust` records the live hash of both `allowlist.txt` and
    /// `config.json`; `--allowlist-only` records only the allowlist (so the
    /// dangerous `extraMounts`/`env`/`readOnlyRoots` stay disabled). `--show`
    /// prints status without changing anything. Fail-closed: any later edit or
    /// `git pull` changes a hash and re-blocks the affected component.
    public static func trust(allowlistOnly: Bool, show: Bool) throws {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        guard let d = ProjectTrust.discover(cwd: cwd) else {
            print("no project .box/ found above \(cwd.path) — nothing to trust (global-only).")
            return
        }

        if show {
            printTrustStatus(d)
            return
        }

        // Record the live hashes. A nil hash means the file is absent, so there's
        // nothing to approve on that side.
        var record = Trust.Record(allowlist: d.allowlistHash, config: nil)
        if !allowlistOnly {
            record.config = d.configHash
        }

        guard record.allowlist != nil || record.config != nil else {
            print(
                "project .box/ at \(d.boxDir.path) has neither allowlist.txt nor config.json — nothing to trust."
            )
            return
        }

        try TrustStore.setRecord(record, forProjectBoxDir: d.boxDir)

        print("trusted project .box/ at \(d.boxDir.path):")
        if record.allowlist != nil {
            print("  allowlist.txt  approved")
        } else {
            print("  allowlist.txt  (absent)")
        }
        if allowlistOnly {
            print(
                "  config.json    NOT trusted (--allowlist-only: extraMounts/env/readOnlyRoots stay off)"
            )
        } else if record.config != nil {
            print("  config.json    approved (extraMounts/env/readOnlyRoots now honored)")
        } else {
            print("  config.json    (absent)")
        }
        print("Any edit to these files re-blocks them until you run `box trust` again.")
    }

    /// Revoke trust for this project's `.box/` (removes its approval record so it
    /// falls back to global-only).
    public static func untrust() throws {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        guard let d = ProjectTrust.discover(cwd: cwd) else {
            print("no project .box/ found above \(cwd.path) — nothing to untrust.")
            return
        }
        if TrustStore.record(forProjectBoxDir: d.boxDir) == nil {
            print("project .box/ at \(d.boxDir.path) was not trusted — nothing to do.")
            return
        }
        try TrustStore.setRecord(nil, forProjectBoxDir: d.boxDir)
        print("revoked trust for project .box/ at \(d.boxDir.path) (now global-only).")
    }

    /// Print the trust status of a discovered project `.box/`, shared by
    /// `box trust --show` and `box config`.
    private static func printTrustStatus(_ d: ProjectTrust.Discovered) {
        let decision = ProjectTrust.evaluate(d)
        let record = TrustStore.record(forProjectBoxDir: d.boxDir)
        print("project .box/: \(d.boxDir.path)")
        func line(_ name: String, present: Bool, approved: String?, trusted: Bool) {
            if !present {
                print("  \(name): (absent)")
            } else if approved == nil {
                print("  \(name): present, NOT trusted — run `box trust`")
            } else if trusted {
                print("  \(name): present, trusted")
            } else {
                print("  \(name): present, CHANGED since trust — re-run `box trust`")
            }
        }
        line(
            "allowlist.txt", present: d.allowlistHash != nil,
            approved: record?.allowlist, trusted: decision.allowlistTrusted)
        line(
            "config.json", present: d.configHash != nil,
            approved: record?.config, trusted: decision.configTrusted)
    }

    // MARK: - Dynamic filesystem visibility
    //
    // `box fs-allow`/`fs-deny` toggle the VISIBILITY of subpaths under the broad
    // read-only roots by editing the host policy file `Box.fsPolicy`
    // (`~/.box/config/fs-policy.txt`). That file lives inside `Box.configDir`,
    // which the runner mounts read-only at `/etc/box`, so a host edit is visible
    // to every running guest, whose entrypoint re-carves `/mnt/<basename>` within
    // ~2s (the same host-file + 2s-poll pattern as the egress allowlist).
    //
    // Paths are GUEST paths (`/mnt/<basename>/…` — what the agent sees), NOT host
    // paths: the carve runs in the guest against the mounted tree. Visibility
    // control is NOT a hard boundary (open fds survive, ≤2s lag, a new root needs
    // a restart) — for real secrets, scope `readOnlyRoots` at create time.

    /// Make a subpath visible again under its broad read-only root (subtracts a
    /// prior `deny`, or re-exposes a child inside a denied subtree).
    public static func fsAllow(path: String) throws {
        try editFsPolicy(verb: .allow, path: path)
    }

    /// Hide a subpath under its broad read-only root from the agent.
    public static func fsDeny(path: String) throws {
        try editFsPolicy(verb: .deny, path: path)
    }

    /// Merge one rule into the host policy file, write it (so mounted guests see
    /// it via `/etc/box`), and report the live-reload status.
    static func editFsPolicy(verb: FsPolicy.Rule.Verb, path: String) throws {
        try Assets.materialize()
        let existing = readFsPolicyRules()
        let result = FsPolicy.merge(existing: existing, verb: verb, path: path)
        print(result.note)
        guard result.changed else { return }
        try FsPolicy.serialize(result.rules)
            .write(to: Box.fsPolicy, atomically: true, encoding: .utf8)
        let running = RunState.list().count
        print(
            running > 0
                ? "reconciling live in \(running) running box(es) (within ~2s)."
                : "(no running box; applies on next launch)")
    }

    /// Print the current dynamic filesystem-visibility policy.
    public static func fsPolicy() throws {
        let rules = readFsPolicyRules()
        guard !rules.isEmpty else {
            print("(no fs-policy rules — broad read-only roots are fully visible)")
            print("policy file: \(Box.fsPolicy.path)")
            return
        }
        print("dynamic filesystem visibility (default: allow whole root, deny subtracts):")
        for r in FsPolicy.canonicalOrder(rules) {
            print("  \(r.verb.rawValue)  \(r.path)")
        }
        print("")
        print("policy file: \(Box.fsPolicy.path)")
    }

    /// Read + parse the host policy file (empty list if absent/invalid).
    private static func readFsPolicyRules() -> [FsPolicy.Rule] {
        guard let text = try? String(contentsOf: Box.fsPolicy, encoding: .utf8) else { return [] }
        return FsPolicy.parse(text)
    }

    // MARK: - Opt-in MITM CA

    /// Generate a self-signed CA in `Box.caDir` (host side) that squid can use to
    /// forge leaf certs for `bumpHosts` when `tlsInspect` is enabled. Writes
    /// `ca.key` (0600) and `ca.crt`. Refuses to clobber an existing CA so a stale
    /// one isn't silently replaced (which would invalidate already-trusted
    /// guests). The key never leaves the host except as a read-only mount into a
    /// box the user explicitly opted into; inside the guest it's re-staged
    /// root:proxy 0640 so the agent (uid 501) can't read it.
    public static func caInit() throws {
        let fm = FileManager.default
        let caDir = Box.caDir
        let keyURL = caDir.appendingPathComponent("ca.key")
        let certURL = caDir.appendingPathComponent("ca.crt")

        if fm.fileExists(atPath: keyURL.path) || fm.fileExists(atPath: certURL.path) {
            throw CBError(
                "a CA already exists in \(caDir.path) "
                    + "(ca.key/ca.crt). Remove it to regenerate (this invalidates any "
                    + "guest that already trusts the old CA).")
        }

        guard Sh.exists("openssl") else {
            throw CBError("openssl not found on PATH; required to generate the CA.")
        }

        try fm.createDirectory(
            at: caDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])

        // Self-signed CA: 4096-bit RSA key + a 10-year CA cert. `-addext` writes
        // the CA basic-constraint so the guest accepts it as an issuer.
        try Sh.checked([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
            "-keyout", keyURL.path, "-out", certURL.path,
            "-days", "3650", "-sha256",
            "-subj", "/CN=box MITM CA/O=box",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])

        // The CA key is sensitive: lock it to the owner.
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: certURL.path)

        print("generated MITM CA:")
        print("  \(keyURL.path)  (private key, 0600)")
        print("  \(certURL.path)  (certificate)")
        print("")
        print("Enable inspection by setting in your box config:")
        print("  \"tlsInspect\": true,")
        print("  \"bumpHosts\": [\"example.internal\"]   // hosts to decrypt; everything")
        print(
            "                                          // else (Anthropic API, npm, git) stays spliced"
        )
    }

    /// Print the effective (layered) configuration with per-value provenance
    /// (`[global]`/`[project]`/`[default]`), both source file paths, and this
    /// project's trust status. The project layer is folded in only when its
    /// config component is trusted (otherwise it's global-only, fail-closed).
    public static func showConfig() {
        let fm = FileManager.default
        let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)

        // Discover the project + evaluate trust so config provenance reflects
        // exactly what a run would honor.
        let discovered = ProjectTrust.discover(cwd: cwd)
        let decision = ProjectTrust.evaluate(discovered)
        let merged = Config.loadLayered(cwd: cwd, trustProjectConfig: decision.configTrusted)
        let c = merged.config
        let o = merged.origins

        let globalPresent = fm.fileExists(atPath: Config.fileURL.path)
        print(
            "global config: \(Config.fileURL.path) (\(globalPresent ? "present" : "absent — using defaults"))"
        )
        if let d = discovered {
            let cfgPresent = d.configHash != nil
            print("project config: \(d.configURL.path) (\(cfgPresent ? "present" : "absent"))")
        } else {
            print("project config: (none discovered above \(cwd.path))")
        }
        print("")

        func tag(_ origin: Origin) -> String { "[\(origin.rawValue)]" }
        print("mountClaudeConfig:    \(c.mountClaudeConfig) \(tag(o.mountClaudeConfig))")
        print("claudeConfigReadOnly: \(c.claudeConfigReadOnly) \(tag(o.claudeConfigReadOnly))")
        print("mountHooks:           \(c.mountHooks) \(tag(o.mountHooks))")
        print("syncClaudeVersion:    \(c.syncClaudeVersion) \(tag(o.syncClaudeVersion))")
        print("skipPermissions:      \(c.skipPermissions) \(tag(o.skipPermissions))")
        print("disableTelemetry:     \(c.disableTelemetry) \(tag(o.disableTelemetry))")
        print("clipboardSync:        \(c.clipboardSync) \(tag(o.clipboardSync))")
        print("cpus:                 \(c.cpus) \(tag(o.cpus))")
        print("memory:               \(c.memory) \(tag(o.memory))")
        print("rootfsSize:           \(c.rootfsSize) \(tag(o.rootfsSize))")
        print(
            "toolchains:           \(c.toolchains.isEmpty ? "(none)" : c.toolchains.joined(separator: ", ")) \(tag(o.toolchains))"
        )
        print(
            "readOnlyRoots:        \(c.readOnlyRoots.isEmpty ? "(none)" : c.readOnlyRoots.joined(separator: ", ")) \(tag(o.readOnlyRoots))"
        )
        print(
            "env:                  \(c.env.isEmpty ? "(none)" : c.env.keys.sorted().joined(separator: ", ")) \(tag(o.env))"
        )
        print("envFile:              \(c.envFile ?? "(none)") \(tag(o.envFile))")
        if c.extraMounts.isEmpty {
            print("extraMounts:          (none) \(tag(o.extraMounts))")
        } else {
            print("extraMounts: \(tag(o.extraMounts))")
            for m in c.extraMounts {
                print("  - \(m.source) -> \(m.destination)\(m.readOnly ? " (ro)" : "")")
            }
        }

        // Project trust status, so it's clear why a project layer is or isn't in
        // effect.
        print("")
        if let d = discovered {
            printTrustStatus(d)
        } else {
            print("project .box/: (none) — global-only")
        }
    }
}
