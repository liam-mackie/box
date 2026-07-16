import Testing

@testable import BoxKit

@Suite("Box.parseSize")
struct SizeParseTests {
    @Test("bare number is bytes")
    func bareBytes() throws {
        #expect(try Box.parseSize("0") == 0)
        #expect(try Box.parseSize("1024") == 1024)
    }

    @Test("binary unit suffixes are 1024-based")
    func binaryUnits() throws {
        #expect(try Box.parseSize("1k") == 1024)
        #expect(try Box.parseSize("1m") == 1024 * 1024)
        #expect(try Box.parseSize("4g") == 4 * 1024 * 1024 * 1024)
        #expect(try Box.parseSize("1t") == 1024 * 1024 * 1024 * 1024)
    }

    @Test("case-insensitive and tolerant of i/b/ib suffixes")
    func caseAndSuffixes() throws {
        #expect(try Box.parseSize("4G") == 4 * 1024 * 1024 * 1024)
        #expect(try Box.parseSize("4gb") == 4 * 1024 * 1024 * 1024)
        #expect(try Box.parseSize("4GiB") == 4 * 1024 * 1024 * 1024)
        #expect(try Box.parseSize("512M") == 512 * 1024 * 1024)
    }

    @Test("tolerates whitespace between number and unit")
    func whitespace() throws {
        #expect(try Box.parseSize(" 8 g ") == 8 * 1024 * 1024 * 1024)
    }

    @Test("invalid strings throw")
    func invalidThrows() {
        #expect(throws: CBError.self) { try Box.parseSize("") }
        #expect(throws: CBError.self) { try Box.parseSize("abc") }
        #expect(throws: CBError.self) { try Box.parseSize("4x") }
        #expect(throws: CBError.self) { try Box.parseSize("g4") }
        #expect(throws: CBError.self) { try Box.parseSize("4.5g") }
    }
}
