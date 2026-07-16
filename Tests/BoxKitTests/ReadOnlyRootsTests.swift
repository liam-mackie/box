import Foundation
import Testing

@testable import BoxKit

/// Pure mapping of `readOnlyRoots` → read-only `/mnt/<basename>` mounts. No VM,
/// no real filesystem: the existence predicate is supplied by the test.
@Suite("readOnlyRoots → mounts (pure)")
struct ReadOnlyRootsTests {
    @Test("empty list yields no mounts and nothing skipped")
    func emptyYieldsNothing() {
        let c = Config(readOnlyRoots: [])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(r.specs.isEmpty)
        #expect(r.skipped.isEmpty)
    }

    @Test("basename derives the /mnt destination; mount is read-only")
    func basenameToMnt() {
        let c = Config(readOnlyRoots: ["/Users/x/g"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(
            r.specs == [
                .init(source: "/Users/x/g", destination: "/mnt/g", readOnly: true)
            ])
        #expect(r.skipped.isEmpty)
    }

    @Test("leading ~ is expanded before deriving the basename")
    func expandsTilde() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let c = Config(readOnlyRoots: ["~/g"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(r.specs.count == 1)
        #expect(r.specs[0].source == home + "/g")
        #expect(!r.specs[0].source.hasPrefix("~"), "tilde should be expanded")
        #expect(r.specs[0].destination == "/mnt/g")
        #expect(r.specs[0].readOnly)
    }

    @Test("bare ~ expands to the home dir and mounts at its basename")
    func bareTilde() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let base = (home as NSString).lastPathComponent
        let c = Config(readOnlyRoots: ["~"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(r.specs.count == 1)
        #expect(r.specs[0].source == home)
        #expect(r.specs[0].destination == "/mnt/\(base)")
    }

    @Test("colliding basenames are disambiguated deterministically (-2, -3, …)")
    func disambiguatesCollisions() {
        let c = Config(readOnlyRoots: ["/a/work", "/b/work", "/c/work"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(r.specs.map(\.destination) == ["/mnt/work", "/mnt/work-2", "/mnt/work-3"])
        #expect(r.specs.map(\.source) == ["/a/work", "/b/work", "/c/work"])
        #expect(r.specs.map(\.readOnly) == [true, true, true])
    }

    @Test("disambiguation follows input order, not the alphabet")
    func disambiguationIsInputOrder() {
        let c = Config(readOnlyRoots: ["/z/repo", "/a/repo"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        // First-seen (/z/repo) keeps the bare /mnt/repo; the later one is suffixed.
        #expect(r.specs[0] == .init(source: "/z/repo", destination: "/mnt/repo", readOnly: true))
        #expect(r.specs[1] == .init(source: "/a/repo", destination: "/mnt/repo-2", readOnly: true))
    }

    @Test("non-existent sources are skipped and reported, not mounted")
    func skipsMissing() {
        let c = Config(readOnlyRoots: ["/exists", "/missing", "/also-here"])
        let present: Set<String> = ["/exists", "/also-here"]
        let r = c.readOnlyRootMounts(exists: { present.contains($0) })
        #expect(r.specs.map(\.destination) == ["/mnt/exists", "/mnt/also-here"])
        #expect(r.skipped == ["/missing"])
    }

    @Test("skipped sources are reported post-tilde-expansion")
    func skippedReportsExpandedPath() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let c = Config(readOnlyRoots: ["~/nope"])
        let r = c.readOnlyRootMounts(exists: { _ in false })
        #expect(r.specs.isEmpty)
        #expect(r.skipped == [home + "/nope"])
    }

    @Test("trailing slashes don't change the basename or destination")
    func trailingSlash() {
        let c = Config(readOnlyRoots: ["/Users/x/g/"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(
            r.specs == [
                .init(source: "/Users/x/g/", destination: "/mnt/g", readOnly: true)
            ])
    }

    @Test("blank / whitespace-only entries are ignored")
    func ignoresBlankEntries() {
        let c = Config(readOnlyRoots: ["", "   ", "/Users/x/g"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(
            r.specs == [
                .init(source: "/Users/x/g", destination: "/mnt/g", readOnly: true)
            ])
        #expect(r.skipped.isEmpty)
    }

    @Test("filesystem root degenerates to /mnt/root")
    func filesystemRoot() {
        let c = Config(readOnlyRoots: ["/"])
        let r = c.readOnlyRootMounts(exists: { _ in true })
        #expect(r.specs == [.init(source: "/", destination: "/mnt/root", readOnly: true)])
    }
}

/// The Runner wrapper relocates each visible `/mnt/<basename>` destination under
/// the HIDDEN `/mnt/.roots/<basename>` prefix, so the agent's working view at
/// `/mnt/<basename>` can be carved live by the entrypoint's bind-mounts. The
/// agent never sees the hidden mount source directly.
@Suite("Runner.readOnlyRootMounts hidden relocation (pure)")
struct ReadOnlyRootsHiddenTests {
    @Test("visible /mnt/<basename> maps to /mnt/.roots/<basename>")
    func relocatesUnderHiddenPrefix() {
        #expect(Runner.hiddenRootDestination(forVisible: "/mnt/g") == "/mnt/.roots/g")
        #expect(Runner.hiddenRootDestination(forVisible: "/mnt/work-2") == "/mnt/.roots/work-2")
        #expect(Runner.hiddenRootDestination(forVisible: "/mnt/root") == "/mnt/.roots/root")
    }

    @Test("a destination not under /mnt/ is left untouched (defensive)")
    func leavesNonMntAlone() {
        #expect(Runner.hiddenRootDestination(forVisible: "/elsewhere") == "/elsewhere")
    }

    @Test("the wrapper mounts existing roots ro at the hidden prefix")
    func wrapperMountsHiddenRo() throws {
        // Use real, guaranteed-existing host dirs so the existence check passes.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-ro-\(UUID().uuidString)")
        let a = tmp.appendingPathComponent("g")
        let b = tmp.appendingPathComponent("work")
        try FileManager.default.createDirectory(at: a, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mounts = Runner.readOnlyRootMounts(Config(readOnlyRoots: [a.path, b.path]))
        #expect(mounts.count == 2)
        #expect(mounts.allSatisfy { $0.options.contains("ro") })
        #expect(mounts.map(\.destination).sorted() == ["/mnt/.roots/g", "/mnt/.roots/work"])
        // Sources are the real host paths (unchanged); only destinations relocate.
        #expect(Set(mounts.map(\.source)) == Set([a.path, b.path]))
    }

    @Test("missing roots are skipped (not mounted)")
    func skipsMissing() {
        let mounts = Runner.readOnlyRootMounts(
            Config(readOnlyRoots: ["/definitely/not/here/\(UUID().uuidString)"]))
        #expect(mounts.isEmpty)
    }
}
