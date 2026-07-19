import ContainerizationExtras
import Foundation
import Testing

@testable import BoxKit

@Suite("Daemon: lease allocation + request handling")
struct DaemonTests {
    private func subnet() throws -> CIDRv4 { try CIDRv4("192.168.66.0/24") }

    /// A throwaway policy dir so handle()'s hello/release file I/O never touches
    /// the real daemon dir. Vary by index to keep concurrent tests independent.
    private func tempPolicyDir(_ tag: String) -> URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("box-daemon-test-\(tag)-\(getpid())", isDirectory: true)
        try? FileManager.default.removeItem(at: d)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    @Test("leases start at the first offset and increment")
    func leaseSequence() throws {
        let state = Daemon.State(subnet: try subnet())
        #expect("\(state.lease("a"))" == "192.168.66.10")
        #expect("\(state.lease("b"))" == "192.168.66.11")
        #expect(state.count == 2)
    }

    @Test("re-leasing the same box is idempotent (no leak)")
    func leaseIdempotent() throws {
        let state = Daemon.State(subnet: try subnet())
        let first = "\(state.lease("a"))"
        #expect("\(state.lease("a"))" == first)
        #expect(state.count == 1)
    }

    @Test("released addresses are reused before fresh ones")
    func leaseReuse() throws {
        let state = Daemon.State(subnet: try subnet())
        _ = state.lease("a")  // .10
        let b = "\(state.lease("b"))"  // .11
        state.release("b")
        #expect("\(state.lease("c"))" == b)  // reuse .11, not .12
        #expect(state.count == 2)
    }

    @Test("hello leases and returns the token + sidecar address")
    func helloOK() throws {
        let pdir = tempPolicyDir("helloOK")
        defer { try? FileManager.default.removeItem(at: pdir) }
        let state = Daemon.State(subnet: try subnet())
        let resp = Daemon.handle(
            Daemon.Request(op: "hello", boxID: "box-x", version: Version.box),
            state: state, token: Data("tok".utf8), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: {}, policyDir: pdir)
        #expect(resp.ok)
        #expect(resp.sidecarIP == "192.168.66.2")
        #expect(resp.leaseIP == "192.168.66.10")
        #expect(resp.token == Data("tok".utf8).base64EncodedString())
    }

    @Test("hello refuses a version-skewed client")
    func helloSkew() throws {
        let pdir = tempPolicyDir("skew")
        defer { try? FileManager.default.removeItem(at: pdir) }
        let state = Daemon.State(subnet: try subnet())
        let resp = Daemon.handle(
            Daemon.Request(op: "hello", boxID: "box-x", version: "ancient"),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: {}, policyDir: pdir)
        #expect(!resp.ok)
        #expect(state.count == 0)  // no lease burned on a refused hello
    }

    @Test("stop is refused while boxes are attached unless forced")
    func stopGuarded() throws {
        let state = Daemon.State(subnet: try subnet())
        _ = state.lease("a")
        var stopped = false
        let refused = Daemon.handle(
            Daemon.Request(op: "stop"),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: { stopped = true })
        #expect(!refused.ok)
        #expect(!stopped)

        let forced = Daemon.handle(
            Daemon.Request(op: "stop", force: true),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: { stopped = true })
        #expect(forced.ok)
        #expect(stopped)
    }

    @Test("hello writes a box's project allowlist; release removes it")
    func perBoxPolicyLifecycle() throws {
        let pdir = tempPolicyDir("policy")
        defer { try? FileManager.default.removeItem(at: pdir) }
        let state = Daemon.State(subnet: try subnet())
        _ = Daemon.handle(
            Daemon.Request(
                op: "hello", boxID: "a", version: Version.box,
                projectAllowlist: "example.org\n"),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: {}, policyDir: pdir)
        // Leased .10 → its allowlist is staged for the sidecar to render.
        let staged = pdir.appendingPathComponent("192.168.66.10/allowlist.txt")
        #expect(FileManager.default.fileExists(atPath: staged.path))
        #expect(try String(contentsOf: staged, encoding: .utf8) == "example.org\n")

        _ = Daemon.handle(
            Daemon.Request(op: "release", boxID: "a"),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: {}, policyDir: pdir)
        #expect(state.count == 0)
        #expect(
            !FileManager.default.fileExists(
                atPath: pdir.appendingPathComponent("192.168.66.10").path))
    }

    @Test("a box with no project allowlist gets an empty policy file (global only)")
    func perBoxPolicyEmpty() throws {
        let pdir = tempPolicyDir("empty")
        defer { try? FileManager.default.removeItem(at: pdir) }
        let state = Daemon.State(subnet: try subnet())
        _ = Daemon.handle(
            Daemon.Request(op: "hello", boxID: "a", version: Version.box),
            state: state, token: Data(), subnet: try subnet(),
            sidecarIP: "192.168.66.2", requestStop: {}, policyDir: pdir)
        let staged = pdir.appendingPathComponent("192.168.66.10/allowlist.txt")
        #expect(FileManager.default.fileExists(atPath: staged.path))
        #expect(try String(contentsOf: staged, encoding: .utf8) == "")
    }

    @Test("hello request carries projectAllowlist through Codable")
    func requestCodable() throws {
        let req = Daemon.Request(
            op: "hello", boxID: "a", version: "v", projectAllowlist: "x.com\n")
        let round = try JSONDecoder().decode(
            Daemon.Request.self, from: try JSONEncoder().encode(req))
        #expect(round.projectAllowlist == "x.com\n")
        #expect(round.op == "hello")
    }
}
