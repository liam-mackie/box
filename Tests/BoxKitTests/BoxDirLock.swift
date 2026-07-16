import Foundation

/// Swift Testing runs suites in parallel by default. Several suites mutate the
/// process-global `BOX_DIR` env var (which `Box.dir` reads), so they must not
/// overlap across suites. `.serialized` only orders tests *within* a suite, so
/// this process-wide lock serializes the BOX_DIR-mutation window across suites.
let boxDirLock = NSLock()

/// Run `body` with `BOX_DIR` pointed at a fresh temp directory, holding the
/// shared lock for the whole window so no other BOX_DIR suite races on the env.
func withTempBoxDir(_ body: (URL) throws -> Void) throws {
    boxDirLock.lock()
    defer { boxDirLock.unlock() }
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("box-test-\(UUID().uuidString)")
    setenv("BOX_DIR", dir.path, 1)
    defer {
        unsetenv("BOX_DIR")
        try? FileManager.default.removeItem(at: dir)
    }
    try body(dir)
}
