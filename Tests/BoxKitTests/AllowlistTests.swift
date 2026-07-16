import Testing

@testable import BoxKit

@Suite("Allowlist.merge")
struct AllowlistTests {
    @Test("appends new domains, preserving existing order")
    func appendsNew() {
        let r = Allowlist.merge(
            existing: [".anthropic.com", ".npmjs.org"],
            adding: [".terraform.io"])
        #expect(r.lines == [".anthropic.com", ".npmjs.org", ".terraform.io"])
        #expect(r.added == [".terraform.io"])
        #expect(r.skipped.isEmpty)
    }

    @Test("skips domains already present")
    func skipsExisting() {
        let r = Allowlist.merge(existing: [".anthropic.com"], adding: [".anthropic.com"])
        #expect(r.lines == [".anthropic.com"])
        #expect(r.added.isEmpty)
        #expect(r.skipped == [".anthropic.com"])
    }

    @Test("dedups repeats within the same input")
    func dedupsWithinInput() {
        let r = Allowlist.merge(existing: [], adding: ["a.com", "a.com", "b.com"])
        #expect(r.lines == ["a.com", "b.com"])
        #expect(r.added == ["a.com", "b.com"])
        #expect(r.skipped == ["a.com"])
    }

    @Test("trims whitespace and ignores blank entries")
    func trimsAndIgnoresBlanks() {
        let r = Allowlist.merge(existing: ["x.com"], adding: ["  y.com  ", "   ", "", "x.com"])
        #expect(r.lines == ["x.com", "y.com"])
        #expect(r.added == ["y.com"])
        #expect(r.skipped == ["x.com"])
    }

    @Test("matches existing entries that carried surrounding whitespace")
    func matchesAgainstTrimmedExisting() {
        let r = Allowlist.merge(existing: ["  z.com  "], adding: ["z.com"])
        #expect(r.added.isEmpty)
        #expect(r.skipped == ["z.com"])
    }
}

@Suite("Allowlist.conflicts")
struct AllowlistConflictTests {
    @Test("detects a leading-dot vs bare conflict")
    func detectsConflict() {
        let c = Allowlist.conflicts(in: [".example.com", "example.com"])
        #expect(c.count == 1)
        #expect(c[0] == (".example.com", "example.com"))
    }

    @Test("no conflict when only one form is present")
    func noConflictSingleForm() {
        #expect(Allowlist.conflicts(in: [".a.com", ".b.com", "c.com"]).isEmpty)
        #expect(Allowlist.conflicts(in: ["a.com", "b.com"]).isEmpty)
    }

    @Test("ignores blanks and comments, trims whitespace")
    func ignoresNoise() {
        let c = Allowlist.conflicts(in: ["# a comment", "", "  .x.com  ", "x.com", "   "])
        #expect(c.count == 1)
        #expect(c[0] == (".x.com", "x.com"))
    }

    @Test("reports multiple conflicts in bare first-seen order")
    func multipleConflicts() {
        let c = Allowlist.conflicts(in: ["b.com", "a.com", ".a.com", ".b.com", "c.com"])
        #expect(c.map(\.1) == ["b.com", "a.com"])
    }
}
