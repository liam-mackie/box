import Foundation
import Testing

@testable import BoxKit

@Suite("BoxNet: net sidecar (pure, temp dir)")
struct BoxNetSidecarTests {
    /// A fresh temp dir per test; caller removes it.
    private func tmp() throws -> URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("boxnet-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    @Test("write → all round-trips id and state")
    func writeAllRoundTrip() throws {
        let dir = try tmp()
        defer { try? FileManager.default.removeItem(at: dir) }
        let state = BoxNet.NetState(
            guestIP: "192.168.64.5", gateway: "192.168.64.1", publishedPorts: [3000])
        try BoxNet.write(state, forBoxID: "box-proj-42", in: dir)

        let all = BoxNet.all(in: dir)
        #expect(all.count == 1)
        #expect(all.first?.id == "box-proj-42")
        #expect(all.first?.state == state)
    }

    @Test("all() ignores non-net- files and corrupt sidecars")
    func allIgnoresNoise() throws {
        let dir = try tmp()
        defer { try? FileManager.default.removeItem(at: dir) }
        try BoxNet.write(BoxNet.NetState(guestIP: "10.0.0.2"), forBoxID: "box-a-1", in: dir)
        // A run marker (box- prefix) and a corrupt sidecar must be skipped.
        try Data("some/cwd".utf8).write(to: dir.appendingPathComponent("box-a-1"))
        try Data("not json".utf8).write(to: dir.appendingPathComponent("net-broken"))

        let all = BoxNet.all(in: dir)
        #expect(all.map(\.id) == ["box-a-1"])
    }

    @Test("lookup tolerates .box suffix, trailing dot, and case")
    func lookupForms() throws {
        let dir = try tmp()
        defer { try? FileManager.default.removeItem(at: dir) }
        try BoxNet.write(BoxNet.NetState(guestIP: "192.168.64.9"), forBoxID: "box-Proj-7", in: dir)

        #expect(BoxNet.lookup("box-proj-7.box", in: dir) == "192.168.64.9")
        #expect(BoxNet.lookup("box-proj-7.box.", in: dir) == "192.168.64.9")
        #expect(BoxNet.lookup("BOX-PROJ-7", in: dir) == "192.168.64.9")
        #expect(BoxNet.lookup("nope.box", in: dir) == nil)
    }

    @Test("remove deletes the sidecar")
    func removeDeletes() throws {
        let dir = try tmp()
        defer { try? FileManager.default.removeItem(at: dir) }
        try BoxNet.write(BoxNet.NetState(guestIP: "10.0.0.3"), forBoxID: "box-x-2", in: dir)
        BoxNet.remove(forBoxID: "box-x-2", in: dir)
        #expect(BoxNet.all(in: dir).isEmpty)
    }
}

@Suite("BoxNet: DNS message codec (pure)")
struct BoxNetDNSTests {
    /// Build a minimal DNS A query for `name` with the given id and RD bit.
    private func query(id: UInt16, name: String, rd: Bool = true) -> [UInt8] {
        var b: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), rd ? 0x01 : 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8)
            b.append(UInt8(bytes.count))
            b.append(contentsOf: bytes)
        }
        b.append(0)  // root
        b.append(contentsOf: [0x00, 0x01, 0x00, 0x01])  // QTYPE=A, QCLASS=IN
        return b
    }

    @Test("parseQuery extracts id, RD, name, and A type")
    func parses() {
        let parsed = BoxNet.parseQuery(query(id: 0x1234, name: "box-foo-1.box"))
        #expect(parsed?.id == 0x1234)
        #expect(parsed?.rd == true)
        #expect(parsed?.question.name == "box-foo-1.box")
        #expect(parsed?.question.type == 1)
    }

    @Test("parseQuery rejects a too-short packet")
    func rejectsShort() {
        #expect(BoxNet.parseQuery([0x00, 0x01]) == nil)
    }

    @Test("buildResponse with an IP yields one A answer with the right RDATA")
    func answerRoundTrip() throws {
        let q = query(id: 0xABCD, name: "box-bar-9.box")
        let parsed = try #require(BoxNet.parseQuery(q))
        let resp = BoxNet.buildResponse(
            id: parsed.id, rd: parsed.rd, question: parsed.question, ipv4: "10.1.2.3")
        // id echoed
        #expect(UInt16(resp[0]) << 8 | UInt16(resp[1]) == 0xABCD)
        // QR + AA set, RCODE 0
        #expect(resp[2] & 0x80 != 0)
        #expect(resp[2] & 0x04 != 0)
        #expect(resp[3] & 0x0F == 0)
        // ANCOUNT == 1
        #expect(UInt16(resp[6]) << 8 | UInt16(resp[7]) == 1)
        // RDATA is the last 4 bytes = the IP
        #expect(Array(resp.suffix(4)) == [10, 1, 2, 3])
    }

    @Test("buildResponse without an IP is NXDOMAIN, no answer")
    func nxdomain() throws {
        let q = query(id: 0x0001, name: "gone.box")
        let parsed = try #require(BoxNet.parseQuery(q))
        let resp = BoxNet.buildResponse(
            id: parsed.id, rd: parsed.rd, question: parsed.question, ipv4: nil)
        #expect(resp[3] & 0x0F == 3)  // RCODE = NXDOMAIN
        #expect(UInt16(resp[6]) << 8 | UInt16(resp[7]) == 0)  // ANCOUNT = 0
    }

    @Test("ipv4ToBytes parses and rejects")
    func ipParse() {
        #expect(BoxNet.ipv4ToBytes("192.168.64.1") == [192, 168, 64, 1])
        #expect(BoxNet.ipv4ToBytes("1.2.3") == nil)
        #expect(BoxNet.ipv4ToBytes("1.2.3.999") == nil)
    }
}

@Suite("BoxNet: /etc/resolver/box predicate (pure)")
struct BoxNetResolverFileTests {
    @Test("nil contents are not a current resolver file")
    func nilContents() {
        #expect(BoxNet.resolverFileCurrent(nil) == false)
    }

    @Test("empty contents are not a current resolver file")
    func emptyContents() {
        #expect(BoxNet.resolverFileCurrent("") == false)
    }

    @Test("a wrong port is not current")
    func wrongPort() {
        #expect(BoxNet.resolverFileCurrent("nameserver 127.0.0.1\nport 9999\n") == false)
    }

    @Test("a missing nameserver line is not current")
    func missingNameserver() {
        #expect(BoxNet.resolverFileCurrent("port 5354\n") == false)
    }

    @Test("nameserver 127.0.0.1 with port 5354 is current")
    func correctContent() {
        #expect(BoxNet.resolverFileCurrent("nameserver 127.0.0.1\nport 5354\n"))
    }

    @Test("the writer's rendered content passes the predicate")
    func renderedContentPasses() {
        #expect(BoxNet.resolverFileCurrent(BoxNet.resolverFileContents()))
    }

    @Test("the predicate honours a custom port on both sides")
    func customPort() {
        #expect(BoxNet.resolverFileCurrent(BoxNet.resolverFileContents(port: 6000), port: 6000))
        #expect(
            BoxNet.resolverFileCurrent(BoxNet.resolverFileContents(port: 6000), port: 5354) == false)
    }
}
