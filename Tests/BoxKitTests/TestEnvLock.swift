import Foundation

/// Process-wide lock for tests that mutate the global `BOX_DIR` env var.
///
/// Swift Testing runs suites in parallel, and `.serialized` only orders tests
/// *within* a single suite. Several suites (`AssetsTests`, `VersionTests`,
/// `DiagnosticsLiveSeamTests`) `setenv("BOX_DIR", …)`, so without a shared lock
/// one suite can clobber another's value mid-test.
///
/// This delegates to the SAME `boxDirLock` instance used by the shared
/// `withTempBoxDir` helper (BoxDirLock.swift) — so the global helper and
/// `BoxDirEnvLock.withLock { … }` serialize against each other. They must share
/// one lock; two separate locks would not exclude each other and the race
/// would return.
enum BoxDirEnvLock {
    static func withLock<T>(_ body: () throws -> T) rethrows -> T {
        boxDirLock.lock()
        defer { boxDirLock.unlock() }
        return try body()
    }
}
