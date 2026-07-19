import ContainerizationExtras
import Foundation

/// Client side of the box-daemon protocol (see `Daemon`): `box run` leases and
/// releases an address on the daemon's shared network; the `box daemon` CLI
/// queries status and requests shutdown.
public enum DaemonClient {
    /// What a box needs to join the daemon's world: the network token to
    /// rehydrate, where the shared Envoy sidecar is, and the address this box may use.
    public struct Lease {
        public let token: Data
        public let sidecarIP: String
        public let leaseIP: IPv4Address
    }

    enum DaemonError: Error, CustomStringConvertible {
        /// Transport-level: nothing (healthy) is listening — spawning may fix it.
        case notRunning(String)
        /// The daemon answered and said no — retrying won't change its mind.
        case refused(String)

        var description: String {
            switch self {
            case .notRunning(let s): return s
            case .refused(let s): return s
            }
        }
    }

    /// Lease an address for `boxID` from the RUNNING daemon, registering this
    /// box's trusted project-allowlist content (nil/empty ⇒ global egress only).
    /// The daemon is a required service (like `container system start`): there
    /// is NO auto-spawn and NO fallback. If it isn't running — or refuses — this
    /// throws a clear, actionable error and the box does not launch.
    public static func lease(boxID: String, projectAllowlist: String? = nil) throws -> Lease {
        do {
            return try hello(boxID: boxID, projectAllowlist: projectAllowlist)
        } catch let e as DaemonError {
            switch e {
            case .notRunning:
                throw CBError(
                    "the box daemon isn't running — start it with `box system start` "
                        + "(or set `dedicatedProxy` for a standalone box)")
            case .refused(let msg):
                throw CBError("the box daemon refused this box: \(msg)")
            }
        }
    }

    /// Start the daemon if it isn't already up, and block until it's ready
    /// (`box system start`). Idempotent. Throws if it can't be spawned or never
    /// becomes ready. First start is slow — the daemon ensures the image and
    /// boots the shared Envoy sidecar.
    public static func start() throws {
        if (try? status()) != nil { return }  // already running
        try spawnDetached()
        for _ in 0..<240 {
            usleep(500_000)
            if (try? status()) != nil { return }
        }
        throw CBError("the box daemon did not come up (see \(Daemon.logURL.path))")
    }

    /// True if a healthy daemon is answering. Used by `box run` to fail fast
    /// with a clear message before doing any work.
    public static func isRunning() -> Bool { (try? status()) != nil }

    /// Return this box's lease. Best-effort: a dead daemon has no lease to
    /// return, and the box is exiting either way.
    public static func release(boxID: String) {
        _ = try? roundTrip(Daemon.Request(op: "release", boxID: boxID), timeoutSeconds: 5)
    }

    public static func status() throws -> Daemon.Response {
        try roundTrip(Daemon.Request(op: "status"), timeoutSeconds: 5)
    }

    public static func stop(force: Bool) throws -> Daemon.Response {
        try roundTrip(Daemon.Request(op: "stop", force: force), timeoutSeconds: 10)
    }

    // MARK: - internals

    static func hello(boxID: String, projectAllowlist: String? = nil) throws -> Lease {
        let resp = try roundTrip(
            Daemon.Request(
                op: "hello", boxID: boxID, version: Version.box,
                projectAllowlist: projectAllowlist),
            timeoutSeconds: 10)
        guard resp.ok else {
            throw DaemonError.refused(resp.error ?? "daemon refused hello")
        }
        guard let tokenB64 = resp.token, let token = Data(base64Encoded: tokenB64),
            let sidecarIP = resp.sidecarIP, let leaseStr = resp.leaseIP,
            let leaseIP = try? IPv4Address(leaseStr)
        else {
            throw DaemonError.refused("daemon hello response is missing lease fields")
        }
        return Lease(token: token, sidecarIP: sidecarIP, leaseIP: leaseIP)
    }

    /// One request/response over the unix socket. Throws `.notRunning` when
    /// nothing healthy is listening (connect failure, timeout, EOF, garbage).
    static func roundTrip(_ req: Daemon.Request, timeoutSeconds: Int) throws -> Daemon.Response {
        let path = Daemon.sockURL.path
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.notRunning("socket() failed: \(errno)") }
        defer { close(fd) }
        var tv = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard path.utf8.count <= maxLen else {
            throw DaemonError.notRunning("socket path too long: \(path)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            _ = path.utf8.withContiguousStorageIfAvailable { src in
                dst.copyBytes(from: UnsafeRawBufferPointer(start: src.baseAddress, count: src.count))
            }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) }
        }
        guard rc == 0 else {
            throw DaemonError.notRunning("no daemon at \(path) (connect: \(errno))")
        }

        var out = try JSONEncoder().encode(req)
        out.append(UInt8(ascii: "\n"))
        let wrote = out.withUnsafeBytes { raw -> Bool in
            var off = 0
            while off < raw.count {
                let w = write(fd, raw.baseAddress!.advanced(by: off), raw.count - off)
                if w <= 0 { return false }
                off += w
            }
            return true
        }
        guard wrote else { throw DaemonError.notRunning("daemon write failed: \(errno)") }

        var buf = Data()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            guard n > 0 else { throw DaemonError.notRunning("daemon closed mid-response") }
            if byte == UInt8(ascii: "\n") { break }
            buf.append(byte)
            if buf.count > 1 << 20 {
                throw DaemonError.notRunning("daemon response oversized")
            }
        }
        guard let resp = try? JSONDecoder().decode(Daemon.Response.self, from: buf) else {
            throw DaemonError.notRunning("daemon response malformed")
        }
        return resp
    }

    /// Spawn a detached `box __daemon`, its stdout/stderr appended to
    /// `daemon.log` (the daemon `setsid()`s itself, mirroring the resolver).
    static func spawnDetached() throws {
        guard let exe = BoxNet.boxExecutablePath() else {
            throw CBError("cannot resolve the box executable path")
        }
        let fm = FileManager.default
        try fm.createDirectory(at: Box.logsDir, withIntermediateDirectories: true)
        if !fm.fileExists(atPath: Daemon.logURL.path) {
            fm.createFile(atPath: Daemon.logURL.path, contents: nil)
        }
        let log = try FileHandle(forWritingTo: Daemon.logURL)
        log.seekToEndOfFile()
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = ["__daemon"]
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = log
        p.standardError = log
        try p.run()  // do NOT wait — it outlives us
    }
}
