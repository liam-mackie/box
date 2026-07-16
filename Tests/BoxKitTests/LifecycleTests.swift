import Foundation
import Testing

@testable import BoxKit

/// Lifecycle commands (`box stop` / `box rm` / `box prune`) are daemonless: a box
/// is tracked by a marker file under `Box.runDir/<id>` whose id embeds the
/// launching process's pid (`box-<dir>-<pid>`). These tests cover the testable
/// host-side logic — `RunState.pruneStale` / `RunState.stop`, `rm` of a dead
/// marker, and the pure `pruneDecision` option/confirmation policy. The
/// SIGTERM/SIGINT handler in `runBox` needs a live VM, so it's left to live
/// verification (its logic is intentionally thin, delegating to `RunState`).
///
/// `getpid()` is a guaranteed-live pid (this test process). For a guaranteed-DEAD
/// pid we spawn `/usr/bin/true` and wait for it to exit + be reaped, so its pid
/// no longer resolves under `kill(pid, 0)`.
@Suite("RunState lifecycle helpers", .serialized)
struct RunStateLifecycleTests {
    /// A pid that has definitely exited and been reaped (so `kill(pid,0)` fails).
    private func deadPid() throws -> pid_t {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try p.run()
        p.waitUntilExit()
        return p.processIdentifier
    }

    /// Write a raw marker (id → cwd) under runDir without going through the live
    /// `getpid()` path, so we can fabricate dead-pid ids.
    private func writeMarker(id: String, cwd: String = "/tmp/proj") throws {
        try FileManager.default.createDirectory(
            at: Box.runDir, withIntermediateDirectories: true)
        try Data(cwd.utf8).write(to: Box.runDir.appendingPathComponent(id))
    }

    private func markerExists(_ id: String) -> Bool {
        FileManager.default.fileExists(atPath: Box.runDir.appendingPathComponent(id).path)
    }

    @Test("pruneStale keeps a live-pid marker and removes a dead-pid one")
    func pruneStaleSurvivesLiveRemovesDead() throws {
        try withTempBoxDir { _ in
            let live = "box-live-\(getpid())"
            let dead = "box-dead-\(try deadPid())"
            try writeMarker(id: live)
            try writeMarker(id: dead)

            let removed = RunState.pruneStale()
            #expect(removed == [dead])
            #expect(markerExists(live), "live-pid marker must survive")
            #expect(!markerExists(dead), "dead-pid marker must be removed")
        }
    }

    @Test("pruneStale is idempotent and reports nothing on a clean run dir")
    func pruneStaleIdempotent() throws {
        try withTempBoxDir { _ in
            let live = "box-live-\(getpid())"
            try writeMarker(id: live)
            #expect(RunState.pruneStale().isEmpty)
            // Re-running with only the live marker still removes nothing.
            #expect(RunState.pruneStale().isEmpty)
            #expect(markerExists(live))
        }
    }

    @Test("pruneStale ignores per-run staging directories (secret-* / proj-allow-*)")
    func pruneStaleIgnoresStagingDirs() throws {
        try withTempBoxDir { _ in
            // A staging dir whose trailing field is a dead pid must NOT be reaped
            // here — it's cleaned up by rm/runBox teardown, not pruneStale.
            let dead = try deadPid()
            let secret = Box.secretDir(forBoxID: "box-x-\(dead)")
            try FileManager.default.createDirectory(at: secret, withIntermediateDirectories: true)
            let removed = RunState.pruneStale()
            #expect(removed.isEmpty)
            #expect(FileManager.default.fileExists(atPath: secret.path))
        }
    }

    @Test("list/pruneStale ignore non-marker files in the run dir (exec sockets)")
    func ignoresExecSockets() throws {
        try withTempBoxDir { _ in
            // A live marker plus an exec control socket file (not `box-` prefixed).
            try writeMarker(id: "box-proj-\(getpid())")
            try writeMarker(id: "exec-\(getpid()).sock")
            let listed = RunState.list().map(\.id)
            #expect(listed == ["box-proj-\(getpid())"])
            #expect(RunState.pruneStale().isEmpty)
            #expect(markerExists("exec-\(getpid()).sock"))  // untouched
        }
    }

    @Test("stop returns false for a dead pid and for a bad id")
    func stopNoOpForDeadOrInvalid() throws {
        let dead = try deadPid()
        try withTempBoxDir { _ in
            #expect(RunState.stop(id: "box-dead-\(dead)", kill: false) == false)
            #expect(RunState.stop(id: "not-a-box-id", kill: false) == false)
        }
    }

    @Test("pid(fromID:) takes the trailing numeric field even when the dir has dashes")
    func pidExtraction() {
        #expect(RunState.pid(fromID: "box-my-proj-12345") == 12345)
        #expect(RunState.pid(fromID: "box-x-1") == 1)
        #expect(RunState.pid(fromID: "box-no-pid") == nil)
        #expect(RunState.pid(fromID: "") == nil)
    }
}

@Suite("Commands.rm (dead marker)", .serialized)
struct RmTests {
    private func deadPid() throws -> pid_t {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try p.run()
        p.waitUntilExit()
        return p.processIdentifier
    }

    @Test("rm of a dead-pid box removes the stale marker (idempotent)")
    func rmDeadMarker() throws {
        try withTempBoxDir { _ in
            let id = "box-dead-\(try deadPid())"
            try FileManager.default.createDirectory(
                at: Box.runDir, withIntermediateDirectories: true)
            try Data("/tmp/proj".utf8).write(to: Box.runDir.appendingPathComponent(id))

            try Commands.rm(id: id, force: false)
            #expect(
                !FileManager.default.fileExists(
                    atPath: Box.runDir.appendingPathComponent(id).path))

            // Idempotent: a second rm on the now-absent box still succeeds.
            try Commands.rm(id: id, force: false)
        }
    }

    @Test("rm rejects an id with no parseable pid")
    func rmRejectsBadID() throws {
        try withTempBoxDir { _ in
            #expect(throws: CBError.self) {
                try Commands.rm(id: "garbage", force: false)
            }
        }
    }
}

/// Pure option/confirmation policy for `box prune` — no filesystem, no IO.
@Suite("Commands.pruneDecision (pure)")
struct PruneDecisionTests {
    private func decide(
        agentHome: Bool = false, store: Bool = false, logs: Bool = false,
        all: Bool = false, force: Bool = false, running: Int = 0
    ) -> Commands.PruneDecision {
        Commands.pruneDecision(
            agentHome: agentHome, store: store, logs: logs, all: all,
            force: force, runningCount: running)
    }

    @Test("no destructive flags ⇒ no targets, never destructive, never refused")
    func defaultIsNonDestructive() {
        let d = decide()
        #expect(d.targets.isEmpty)
        #expect(!d.isDestructive)
        #expect(!d.refuseRunning)
        // Even with boxes running, the default (stale-marker) prune isn't refused.
        #expect(!decide(running: 3).refuseRunning)
    }

    @Test("individual flags select exactly their target")
    func individualFlags() {
        #expect(decide(agentHome: true).targets == [.agentHome])
        #expect(decide(store: true).targets == [.store])
        #expect(decide(logs: true).targets == [.logs])
    }

    @Test("--all selects every destructive target")
    func allSelectsEverything() {
        #expect(decide(all: true).targets == [.agentHome, .store, .logs])
        // --all is a superset of any explicit flag combo.
        #expect(decide(agentHome: true, all: true).targets == [.agentHome, .store, .logs])
    }

    @Test("combining flags unions the targets (in fixed order)")
    func combinedFlags() {
        #expect(decide(agentHome: true, logs: true).targets == [.agentHome, .logs])
        #expect(decide(store: true, logs: true).targets == [.store, .logs])
    }

    @Test("destructive prune is refused while boxes run, unless --force")
    func refusesWhileRunning() {
        #expect(decide(all: true, running: 1).refuseRunning)
        #expect(decide(agentHome: true, running: 2).refuseRunning)
        // --force overrides the refusal.
        #expect(!decide(all: true, force: true, running: 1).refuseRunning)
        // No running boxes ⇒ no refusal regardless of force.
        #expect(!decide(all: true, running: 0).refuseRunning)
    }
}
