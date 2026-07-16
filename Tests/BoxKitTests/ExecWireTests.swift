import Foundation
import Testing

@testable import BoxKit

@Suite("ExecWire framing (pure)")
struct ExecWireTests {
    @Test("encode/decode round-trips a frame")
    func roundTrip() {
        let payload = Data("hello box".utf8)
        let encoded = ExecWire.encode(.stdin, payload)
        let decoded = ExecWire.decode(encoded)
        #expect(decoded?.type == ExecWire.FrameType.stdin.rawValue)
        #expect(decoded?.payload == payload)
        #expect(decoded?.consumed == encoded.count)
    }

    @Test("decode waits for a complete frame")
    func incremental() {
        let encoded = ExecWire.encode(.output, Data(repeating: 0x41, count: 100))
        // Any strict prefix is incomplete.
        #expect(ExecWire.decode(Data()) == nil)
        #expect(ExecWire.decode(encoded.prefix(4)) == nil)
        #expect(ExecWire.decode(encoded.prefix(encoded.count - 1)) == nil)
        #expect(ExecWire.decode(encoded) != nil)
    }

    @Test("decode consumes exactly one frame from a coalesced buffer")
    func coalesced() {
        var buffer = ExecWire.encode(.stdin, Data("a".utf8))
        buffer.append(ExecWire.encode(.stdinEOF, Data()))
        let first = ExecWire.decode(buffer)
        #expect(first?.payload == Data("a".utf8))
        buffer.removeFirst(first!.consumed)
        let second = ExecWire.decode(buffer)
        #expect(second?.type == ExecWire.FrameType.stdinEOF.rawValue)
        #expect(second?.payload.isEmpty == true)
        buffer.removeFirst(second!.consumed)
        #expect(buffer.isEmpty)
    }

    @Test("decode survives a non-zero-based Data slice")
    func sliceSafety() {
        // Data subranges keep their parent's indices; decode must not assume
        // startIndex == 0 (a classic Data bug).
        var buffer = Data([0xFF, 0xFF, 0xFF])  // junk prefix to slice off
        buffer.append(ExecWire.encode(.exit, ExecWire.encodeExitCode(42)))
        let slice = buffer.dropFirst(3)
        let decoded = ExecWire.decode(slice)
        #expect(decoded?.type == ExecWire.FrameType.exit.rawValue)
        #expect(ExecWire.decodeExitCode(decoded!.payload) == 42)
    }

    @Test("exit codes round-trip, including large and negative values")
    func exitCodes() {
        for code: Int32 in [0, 1, 42, 137, 255, -1] {
            #expect(ExecWire.decodeExitCode(ExecWire.encodeExitCode(code)) == code)
        }
        // Malformed payload degrades to failure code 1, not a crash.
        #expect(ExecWire.decodeExitCode(Data([0x01])) == 1)
    }

    @Test("header JSON round-trips")
    func headerRoundTrip() throws {
        let header = ExecWire.Header(
            args: ["bash", "-lc", "echo hi"],
            cols: 142, rows: 39, term: "xterm-256color")
        let data = try JSONEncoder().encode(header)
        let back = try JSONDecoder().decode(ExecWire.Header.self, from: data)
        #expect(back == header)
    }
}
