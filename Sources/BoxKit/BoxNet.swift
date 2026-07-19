import Darwin
import Foundation

/// box networking: give each running box a stable name (`<box-id>.box`) that
/// resolves on the Mac to the box's current guest IP, so a dev server bound
/// inside a box (e.g. a worktree under test) is reachable at
/// `http://<box-id>.box:<port>` from the host browser.
///
/// Design (daemonless-friendly, container-style):
///  * Each box writes a small **net sidecar** (`~/.box/run/net-<id>`, JSON) with
///    its guest IP + gateway when it starts, and removes it at teardown. The
///    `net-` prefix keeps these files out of `RunState.list()`'s `box-`-prefixed
///    marker scan, so run-state bookkeeping is untouched.
///  * A single host-wide **resolver** (this file's `runResolver`) listens on
///    `127.0.0.1:<resolverPort>` and answers `A` queries for `<id>.box` from the
///    sidecars. It is a *lazy singleton*: `box run` calls `ensureResolver()`,
///    which spawns it only if not already up; it self-exits once no boxes remain,
///    so nothing lingers when the Mac is idle.
///  * `box net init` (`installResolver`) wires the Mac's resolver: it writes
///    `/etc/resolver/box` pointing `*.box` at `127.0.0.1:<resolverPort>` and
///    HUPs `mDNSResponder`. One-time, needs root.
///
/// Only the pure pieces (sidecar codec, DNS message parse/build) are unit-tested
/// here; the socket loop and process lifecycle are exercised end-to-end.
public enum BoxNet {
    /// UDP port the `.box` resolver listens on (loopback only). Non-privileged so
    /// the resolver needs no root; `/etc/resolver/box` points mDNSResponder here.
    public static let resolverPort: UInt16 = 5354
    /// The DNS suffix box owns.
    public static let domain = "box"

    // MARK: - Net sidecar (per-box IP/gateway, written by the runner)

    /// Per-box network facts, persisted next to the run marker.
    public struct NetState: Codable, Sendable, Equatable {
        /// The guest's IPv4 address on its vmnet subnet (bare, no prefix).
        public var guestIP: String
        /// The vmnet gateway = the Mac's address on that subnet (bare), if known.
        public var gateway: String?
        /// Host→guest published TCP ports (informational; inbound needs no
        /// firewall change since the guest INPUT chain is default-ACCEPT).
        public var publishedPorts: [Int]

        public init(guestIP: String, gateway: String? = nil, publishedPorts: [Int] = []) {
            self.guestIP = guestIP
            self.gateway = gateway
            self.publishedPorts = publishedPorts
        }
    }

    /// Sidecar path for a box id (`~/.box/run/net-<id>`).
    public static func sidecarURL(forBoxID id: String, in dir: URL = Box.runDir) -> URL {
        dir.appendingPathComponent("net-\(id)")
    }

    /// Persist a box's net state (called by the runner right after start).
    public static func write(_ state: NetState, forBoxID id: String, in dir: URL = Box.runDir)
        throws
    {
        let data = try JSONEncoder().encode(state)
        try data.write(to: sidecarURL(forBoxID: id, in: dir), options: [.atomic])
    }

    /// Remove a box's sidecar (called in the runner teardown `defer`). No-op if absent.
    public static func remove(forBoxID id: String, in dir: URL = Box.runDir) {
        try? FileManager.default.removeItem(at: sidecarURL(forBoxID: id, in: dir))
    }

    /// All live net sidecars as `(id, state)`, id recovered by stripping `net-`.
    /// Unreadable/corrupt sidecars are skipped. `dir` is injectable for testing.
    public static func all(in dir: URL = Box.runDir) -> [(id: String, state: NetState)] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: dir.path) else { return [] }
        var out: [(id: String, state: NetState)] = []
        for name in names.sorted() where name.hasPrefix("net-") {
            let url = dir.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: url),
                let state = try? JSONDecoder().decode(NetState.self, from: data)
            else { continue }
            out.append((id: String(name.dropFirst("net-".count)), state: state))
        }
        return out
    }

    /// Resolve `<id>.box` (or bare `<id>`) to a guest IP from the sidecars.
    /// Case-insensitive (DNS is), tolerant of a trailing dot and the `.box` suffix.
    public static func lookup(_ name: String, in dir: URL = Box.runDir) -> String? {
        var host = name.lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        if host.hasSuffix(".\(domain)") { host.removeLast(domain.count + 1) }
        guard !host.isEmpty else { return nil }
        return all(in: dir).first { $0.id.lowercased() == host }?.state.guestIP
    }

    // MARK: - Minimal DNS message codec (A queries only; pure + testable)

    /// The first question in a DNS query: its name, type, and the raw bytes of
    /// the whole question section (echoed verbatim into the response).
    public struct Question: Equatable {
        public let name: String
        public let type: UInt16
        public let rawBytes: [UInt8]
    }

    /// Parse a DNS query: header + first question. Returns nil on a malformed
    /// packet or zero questions. QNAME is decoded to a dotted string; question
    /// compression pointers aren't used in queries, so labels are read directly.
    public static func parseQuery(_ data: [UInt8]) -> (id: UInt16, rd: Bool, question: Question)? {
        guard data.count >= 12 else { return nil }
        let id = UInt16(data[0]) << 8 | UInt16(data[1])
        let rd = (data[2] & 0x01) != 0
        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard qdcount >= 1 else { return nil }

        var i = 12
        var labels: [String] = []
        while i < data.count {
            let len = Int(data[i])
            if len == 0 { i += 1; break }
            if len & 0xC0 != 0 { return nil }  // no compression pointers in a query
            guard i + 1 + len <= data.count else { return nil }
            let bytes = data[(i + 1)..<(i + 1 + len)]
            guard let label = String(bytes: bytes, encoding: .utf8) else { return nil }
            labels.append(label)
            i += 1 + len
        }
        guard i + 4 <= data.count else { return nil }
        let type = UInt16(data[i]) << 8 | UInt16(data[i + 1])
        let raw = Array(data[12..<(i + 4)])  // QNAME + QTYPE + QCLASS
        return (id, rd, Question(name: labels.joined(separator: "."), type: type, rawBytes: raw))
    }

    /// DNS A record type / IN class.
    static let typeA: UInt16 = 1
    static let classIN: UInt16 = 1

    /// Build a response for a parsed query. `ipv4` non-nil → a single A answer
    /// (TTL kept short since a box's IP changes per run); nil → NXDOMAIN.
    public static func buildResponse(
        id: UInt16, rd: Bool, question: Question, ipv4: String?
    ) -> [UInt8] {
        var out: [UInt8] = []
        func u16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF)) }

        let answerBytes = ipv4.flatMap(ipv4ToBytes)
        let hasAnswer = answerBytes != nil
        // Header: QR=1, AA=1, echo RD; RCODE 0 (answer) or 3 (NXDOMAIN).
        var flags: UInt16 = 0x8000 | 0x0400
        if rd { flags |= 0x0100 }
        if !hasAnswer { flags |= 0x0003 }
        u16(id)
        u16(flags)
        u16(1)  // QDCOUNT
        u16(hasAnswer ? 1 : 0)  // ANCOUNT
        u16(0)  // NSCOUNT
        u16(0)  // ARCOUNT
        out.append(contentsOf: question.rawBytes)  // echo the question
        if let ip = answerBytes {
            out.append(0xC0)
            out.append(0x0C)  // NAME → pointer to the question name at offset 12
            u16(typeA)
            u16(classIN)
            out.append(contentsOf: [0, 0, 0, 5])  // TTL = 5s
            u16(4)  // RDLENGTH
            out.append(contentsOf: ip)  // RDATA
        }
        return out
    }

    /// Parse a dotted IPv4 string into 4 network-order bytes, or nil if malformed.
    static func ipv4ToBytes(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for p in parts {
            guard let v = UInt8(p) else { return nil }
            bytes.append(v)
        }
        return bytes
    }

    // MARK: - Resolver process (lazy singleton)

    /// Pidfile for the singleton resolver.
    static func pidfileURL(in dir: URL = Box.runDir) -> URL {
        dir.appendingPathComponent("resolver.pid")
    }

    /// Is the resolver already running (live pid in the pidfile)?
    public static func isResolverRunning(in dir: URL = Box.runDir) -> Bool {
        guard let s = try? String(contentsOf: pidfileURL(in: dir), encoding: .utf8),
            let pid = pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return false }
        return kill(pid, 0) == 0
    }

    /// Ensure the resolver is up, spawning a detached `box __resolver` if not.
    /// Best-effort: a failure to spawn just means `.box` names won't resolve.
    public static func ensureResolver() {
        guard !isResolverRunning() else { return }
        guard let exe = boxExecutablePath() else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = ["__resolver"]
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()  // do NOT wait — it outlives us; it setsid()s itself
    }

    /// Absolute path to the running `box` binary, for re-spawning the resolver.
    static func boxExecutablePath() -> String? {
        if let path = Bundle.main.executablePath { return path }
        let arg0 = CommandLine.arguments.first ?? ""
        return arg0.isEmpty ? nil : arg0
    }

    /// Run the resolver loop (the body of the hidden `box __resolver` command).
    /// Detaches from the controlling terminal, writes its pidfile, binds
    /// `127.0.0.1:port` UDP, and answers `<id>.box` A queries from the sidecars.
    /// Self-exits when no boxes remain (checked on a periodic recv timeout), so
    /// it never lingers past the last box.
    public static func runResolver(port: UInt16 = resolverPort, dir: URL = Box.runDir) throws {
        setsid()  // detach from the launching box's TTY (best-effort)
        try Data("\(getpid())\n".utf8).write(to: pidfileURL(in: dir), options: [.atomic])
        defer { try? FileManager.default.removeItem(at: pidfileURL(in: dir)) }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw CBError("resolver socket() failed (errno \(errno))") }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw CBError("resolver bind(:\(port)) failed (errno \(errno))") }

        // Periodic wakeup so we can notice the last box leaving even with no traffic.
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var buf = [UInt8](repeating: 0, count: 512)
        while true {
            var from = sockaddr_storage()
            var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &from) { fp in
                fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &fromLen)
                }
            }
            if n < 0 {
                // Timeout (no packet): exit once the last box is gone.
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    if all(in: dir).isEmpty { return }
                    continue
                }
                continue
            }
            guard let query = parseQuery(Array(buf[0..<n])) else { continue }
            let ip = query.question.type == typeA ? lookup(query.question.name, in: dir) : nil
            let reply = buildResponse(
                id: query.id, rd: query.rd, question: query.question, ipv4: ip)
            _ = withUnsafePointer(to: &from) { fp in
                fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    reply.withUnsafeBytes { sendto(fd, $0.baseAddress, reply.count, 0, sa, fromLen) }
                }
            }
        }
    }

    // MARK: - Host resolver wiring (`box net init`)

    /// macOS per-domain resolver file that routes `*.box` to our UDP resolver.
    static let resolverFile = "/etc/resolver/\(domain)"

    static func resolverFileContents(port: UInt16 = resolverPort) -> String {
        "nameserver 127.0.0.1\nport \(port)\n"
    }

    public static func resolverFileCurrent(_ contents: String?, port: UInt16 = resolverPort) -> Bool
    {
        guard let contents else { return false }
        func directives(_ text: String) -> Set<String> {
            Set(
                text.split(whereSeparator: \.isNewline)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty })
        }
        return directives(resolverFileContents(port: port)).isSubset(of: directives(contents))
    }

    public static func resolverInstalled() -> Bool {
        resolverFileCurrent(try? String(contentsOfFile: resolverFile, encoding: .utf8), port: resolverPort)
    }

    /// Install the `/etc/resolver/box` entry and HUP mDNSResponder so the Mac
    /// routes `*.box` lookups to `127.0.0.1:<resolverPort>`. Needs root; throws a
    /// guidance error if the write is denied (re-run under sudo).
    public static func installResolver(port: UInt16 = resolverPort) throws {
        let content = resolverFileContents(port: port)
        do {
            try FileManager.default.createDirectory(
                atPath: "/etc/resolver", withIntermediateDirectories: true)
            try content.write(toFile: resolverFile, atomically: true, encoding: .utf8)
        } catch {
            throw CBError(
                "could not write \(resolverFile) (\(error)). "
                    + "Re-run with sudo: `sudo box net init`.")
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/killall")
        p.arguments = ["-HUP", "mDNSResponder"]
        try? p.run()
        p.waitUntilExit()
    }
}
