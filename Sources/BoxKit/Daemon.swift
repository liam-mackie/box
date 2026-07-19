import Containerization
import ContainerizationExtras
import Foundation

/// The box daemon: a long-lived host process owning ONE vmnet network and ONE
/// Envoy proxy-sidecar VM that many boxes share.
///
/// Why a daemon at all: Virtualization.framework VMs live inside the process
/// that starts them (that's why `box stop` signals the run process), so a
/// sidecar meant to outlive any single `box run` needs its own process. The
/// network must ALSO be daemon-owned — a vmnet network dies with its creator,
/// and every attached VM loses egress with it.
///
/// Topology (all verified by `box __netprobe` / `--cross`):
///   daemon: creates network (subnet .0/24), boots sidecar at .2 (BOX_ROLE=
///   proxy), listens on a unix socket. Each `box run` (shared is the default)
///   sends `hello`, gets the network token + an IP lease (.10+), rehydrates the
///   network, boots its agent VM on it (BOX_ROLE=client, BOX_PROXY_ADDR=.2:3128),
///   and Envoy sees that box's REAL source address. `release` returns the
///   lease. The daemon stays warm when idle; `box daemon stop` tears it down.
///
/// If the daemon dies, attached boxes keep their VMs but lose egress (their
/// network vanished) — they must be restarted. Version skew is refused at
/// `hello` so a stale daemon can't serve a newer box; the client falls back to
/// its per-box proxy path and says why.
public enum Daemon {
    // MARK: - Paths

    public static var dir: URL { Box.runDir.appendingPathComponent("daemon", isDirectory: true) }
    public static var sockURL: URL { dir.appendingPathComponent("daemon.sock") }
    static var pidURL: URL { dir.appendingPathComponent("daemon.pid") }
    public static var logURL: URL { Box.logsDir.appendingPathComponent("daemon.log") }

    /// Host dir mounted into the sidecar at `guestPolicyDir`. The daemon writes
    /// each attached box's per-source policy into `<leaseIP>/` here; the sidecar
    /// renders per-box Envoy RBAC from it and reloads on change (see the
    /// entrypoint's render_envoy / poll_envoy_inputs).
    static var policyDir: URL { dir.appendingPathComponent("policy", isDirectory: true) }
    static let guestPolicyDir = "/run/box-shared"

    static let sharedLogID = "shared-proxy"
    /// Host offset of the sidecar on the daemon's subnet (.2; .1 = gateway).
    static let sidecarHostOffset: UInt32 = 2
    /// First host offset leased to boxes (.10+ keeps room for future fixed roles).
    static let firstLeaseOffset: UInt32 = 10

    // MARK: - Wire protocol (ndjson over the unix socket)

    public struct Request: Codable {
        public var op: String  // hello | release | status | stop
        public var boxID: String?
        public var version: String?
        public var force: Bool?
        /// hello: this box's TRUSTED project-allowlist content (domains, one per
        /// line), or nil/empty for none. The daemon writes it into the box's
        /// per-source policy so the sidecar's Envoy grants ONLY this box those
        /// extra domains. `box run` is a same-user local process on the daemon's
        /// unix socket, so sending the content (rather than a path the daemon
        /// would have to re-trust) is fine.
        public var projectAllowlist: String?

        public init(
            op: String, boxID: String? = nil, version: String? = nil,
            force: Bool? = nil, projectAllowlist: String? = nil
        ) {
            self.op = op
            self.boxID = boxID
            self.version = version
            self.force = force
            self.projectAllowlist = projectAllowlist
        }
    }

    public struct Response: Codable {
        public var ok: Bool
        public var error: String?
        public var version: String?
        public var token: String?  // base64 network token
        public var subnet: String?
        public var gateway: String?
        public var sidecarIP: String?
        public var leaseIP: String?
        public var boxes: [String: String]?  // boxID → leased IP
    }

    // MARK: - State

    /// Mutable daemon state, guarded by one lock: connection handler threads
    /// and the teardown path both touch it.
    final class State: @unchecked Sendable {
        private let lock = NSLock()
        private var leases: [String: IPv4Address] = [:]
        private var freed: [IPv4Address] = []
        private var nextOffset: UInt32
        private let subnetBase: UInt32

        init(subnet: CIDRv4) {
            self.subnetBase = subnet.lower.value
            self.nextOffset = Daemon.firstLeaseOffset
        }

        /// Lease an IP for `boxID` (idempotent: a re-hello for a live box —
        /// e.g. after a crashed run relaunches with the same id — returns the
        /// existing lease rather than leaking one).
        func lease(_ boxID: String) -> IPv4Address {
            lock.lock()
            defer { lock.unlock() }
            if let existing = leases[boxID] { return existing }
            let ip = freed.popLast() ?? {
                defer { nextOffset += 1 }
                return IPv4Address(subnetBase + nextOffset)
            }()
            leases[boxID] = ip
            return ip
        }

        /// Release `boxID`'s lease, returning the freed IP (nil if it held none)
        /// so the caller can clean up that box's per-source policy dir.
        @discardableResult
        func release(_ boxID: String) -> IPv4Address? {
            lock.lock()
            defer { lock.unlock() }
            guard let ip = leases.removeValue(forKey: boxID) else { return nil }
            freed.append(ip)
            return ip
        }

        var snapshot: [String: String] {
            lock.lock()
            defer { lock.unlock() }
            return leases.mapValues { "\($0)" }
        }

        var count: Int {
            lock.lock()
            defer { lock.unlock() }
            return leases.count
        }
    }

    // MARK: - Main

    /// Timestamped daemon log line (stderr → daemon.log via the spawner).
    static func dlog(_ message: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardError.write(Data("\(ts) \(message)\n".utf8))
    }

    public static func run() async throws {
        setsid()  // detach from the launching box's TTY (mirrors the resolver)
        // Single instance: if a live daemon answers on the socket, bow out;
        // otherwise clear stale artifacts from a previous crash and take over.
        if (try? DaemonClient.roundTrip(Request(op: "status"), timeoutSeconds: 2)) != nil {
            throw CBError("box daemon is already running")
        }
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        try? fm.removeItem(at: sockURL)
        // Start with an empty policy dir: any per-box subdirs from a previous
        // (crashed) daemon are stale — their boxes are gone and their leases
        // will be re-issued fresh.
        try? fm.removeItem(at: policyDir)
        try fm.createDirectory(at: policyDir, withIntermediateDirectories: true)
        try Assets.materialize()
        try Commands.ensureCA()

        let cfg = Config.load()  // global only: project layers belong to boxes
        let ref = try SharedVmnet.createNetwork()
        let token = try SharedVmnet.token(for: ref)
        let subnet = try SharedVmnet.subnet(of: ref)
        let sidecarIP = "\(IPv4Address(subnet.lower.value + sidecarHostOffset))"
        let state = State(subnet: subnet)

        Daemon.dlog("box daemon: network \(subnet) up; booting shared proxy sidecar…")
        let store = try ImageStore(path: Box.storeDir)
        let image = try await ImageBridge.ensure(store: store)
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: try SharedVmnetNetwork(reference: ref, hostOffsets: [sidecarHostOffset])
        )
        // Reclaim a stale sidecar registration from a previously CRASHED daemon
        // (a clean stop deletes it; a SIGKILL can't). Without this, `create`
        // below fails with "a file with the same name already exists" and every
        // future daemon is wedged. Safe on a clean store (removeItem no-ops).
        try? manager.delete("box-shared-proxy")

        // The sidecar's own proxy-side mounts (global allowlist, logs) plus
        // the per-box policy dir the daemon writes into.
        var pMounts = Runner.proxyMounts(
            cfg: cfg, configDir: Box.configDir.path, logsDir: Box.logsDir.path,
            id: sharedLogID, projectAllowlist: nil)
        pMounts.append(.share(source: policyDir.path, destination: guestPolicyDir, options: ["ro"]))
        let sidecar = try await manager.create(
            "box-shared-proxy",
            image: image,
            rootfsSizeInBytes: try Box.parseSize(cfg.rootfsSize)
        ) { config in
            config.process.capabilities = .allCapabilities
            config.process.arguments = ["/usr/local/bin/entrypoint.sh", "sleep", "infinity"]
            config.process.environmentVariables.append("BOX_ROLE=proxy")
            config.process.environmentVariables.append("BOX_ID=\(sharedLogID)")
            config.cpus = 1
            config.memoryInBytes = 1 << 30
            config.dns = DNS(nameservers: Box.dnsServers)
            config.mounts.append(contentsOf: pMounts)
        }
        try await sidecar.create()
        try await sidecar.start()

        try "\(getpid())\n".write(to: pidURL, atomically: true, encoding: .utf8)

        // Teardown rendezvous: SIGTERM/SIGINT and the `stop` op all funnel here.
        let stopSignal = AsyncStream<Void>.makeStream()
        let signalQueue = DispatchQueue(label: "box.daemon.signal")
        var signalSources: [DispatchSourceSignal] = []
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
            src.setEventHandler { stopSignal.continuation.yield() }
            src.resume()
            signalSources.append(src)
        }
        defer { for src in signalSources { src.cancel() } }

        let server = try UnixLineServer(path: sockURL.path) { request in
            handle(
                request, state: state, token: token, subnet: subnet,
                sidecarIP: sidecarIP,
                requestStop: { stopSignal.continuation.yield() })
        }
        Daemon.dlog("box daemon: ready — sidecar \(sidecarIP):3128, socket \(sockURL.path)")

        // Park until asked to stop, OR until the sidecar exits on its own
        // (without it the daemon would serve dead leases). We race a stop-signal
        // task against `sidecar.wait()` — but `wait()` does NOT honor Swift task
        // cancellation, so `cancelAll()` can't reclaim it. To let `withTaskGroup`
        // return, the stop path STOPS the sidecar, which makes `wait()` return
        // on its own; the signal task ends when the stream finishes.
        await withTaskGroup(of: Void.self) { group in
            group.addTask { _ = try? await sidecar.wait() }
            group.addTask {
                for await _ in stopSignal.stream { break }
                try? await sidecar.stop()  // unblocks the wait() task above
            }
            _ = await group.next()
            stopSignal.continuation.finish()  // end the signal task if it's still waiting
        }

        Daemon.dlog("box daemon: stopping (\(state.count) attached box(es))…")
        server.stop()
        try? await sidecar.stop()
        try? manager.delete("box-shared-proxy")
        try? fm.removeItem(at: sockURL)
        try? fm.removeItem(at: pidURL)
    }

    // MARK: - Request handling

    static func handle(
        _ req: Request, state: State, token: Data, subnet: CIDRv4,
        sidecarIP: String, requestStop: @escaping () -> Void,
        policyDir: URL = Daemon.policyDir
    ) -> Response {
        switch req.op {
        case "hello":
            guard let boxID = req.boxID, !boxID.isEmpty else {
                return Response(ok: false, error: "hello: missing boxID")
            }
            // Refuse skew in BOTH directions: mixed versions on one sidecar is
            // exactly the config drift the daemon is supposed to prevent.
            if let v = req.version, v != Version.box {
                return Response(
                    ok: false,
                    error: "version skew: daemon \(Version.box), client \(v) — "
                        + "run `box daemon stop` and retry",
                    version: Version.box)
            }
            let ip = state.lease(boxID)
            writePolicy(baseDir: policyDir, ip: ip, projectAllowlist: req.projectAllowlist)
            return Response(
                ok: true, version: Version.box,
                token: token.base64EncodedString(),
                subnet: "\(subnet)",
                gateway: "\(subnet.gateway)",
                sidecarIP: sidecarIP,
                leaseIP: "\(ip)")
        case "release":
            guard let boxID = req.boxID else {
                return Response(ok: false, error: "release: missing boxID")
            }
            if let ip = state.release(boxID) { removePolicy(baseDir: policyDir, ip: ip) }
            return Response(ok: true)
        case "status":
            return Response(
                ok: true, version: Version.box, subnet: "\(subnet)",
                sidecarIP: sidecarIP, boxes: state.snapshot)
        case "stop":
            let attached = state.count
            if attached > 0 && req.force != true {
                return Response(
                    ok: false,
                    error: "\(attached) box(es) still attached — stop them first "
                        + "or pass --force (their egress will break)")
            }
            requestStop()
            return Response(ok: true)
        default:
            return Response(ok: false, error: "unknown op '\(req.op)'")
        }
    }

    /// Write a box's per-source policy into `<policyDir>/<ip>/allowlist.txt` (the
    /// sidecar renders per-box Envoy RBAC from it and reloads). An empty or
    /// nil allowlist leaves an empty file — the entrypoint skips boxes whose file
    /// has no domains, so the box gets only the global allowlist. Best-effort:
    /// the box still runs on the shared sidecar with global egress if this fails.
    static func writePolicy(baseDir: URL, ip: IPv4Address, projectAllowlist: String?) {
        let boxDir = baseDir.appendingPathComponent("\(ip)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: boxDir, withIntermediateDirectories: true)
            try Data((projectAllowlist ?? "").utf8).write(
                to: boxDir.appendingPathComponent("allowlist.txt"), options: [.atomic])
        } catch {
            dlog("box daemon: failed to stage policy for \(ip): \(error)")
        }
    }

    /// Remove a detached box's per-source policy dir so its ACLs drop on the
    /// next sidecar reconcile and its freed IP can be re-leased cleanly.
    static func removePolicy(baseDir: URL, ip: IPv4Address) {
        try? FileManager.default.removeItem(
            at: baseDir.appendingPathComponent("\(ip)", isDirectory: true))
    }
}

/// Minimal blocking unix-socket line server: one accept thread, one thread per
/// connection, newline-delimited JSON in/out. Mirrors the raw-POSIX style of
/// `ExecServer` — the daemon's async work must never block on a stuck client.
final class UnixLineServer: @unchecked Sendable {
    private var listenFD: Int32 = -1
    private let stopped = LockedBool()
    private let handler: (Daemon.Request) -> Daemon.Response

    init(path: String, handler: @escaping (Daemon.Request) -> Daemon.Response) throws {
        self.handler = handler
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CBError("daemon: socket() failed: \(errno)") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard path.utf8.count <= maxLen else {
            close(fd)
            throw CBError("daemon: socket path too long: \(path)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            _ = path.utf8.withContiguousStorageIfAvailable { src in
                dst.copyBytes(from: UnsafeRawBufferPointer(start: src.baseAddress, count: src.count))
            }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) }
        }
        guard bound == 0, listen(fd, 16) == 0 else {
            close(fd)
            throw CBError("daemon: bind/listen on \(path) failed: \(errno)")
        }
        chmod(path, 0o600)  // the daemon speaks only for this user
        self.listenFD = fd

        let thread = Thread { self.acceptLoop() }
        thread.name = "box.daemon.accept"
        thread.start()
    }

    func stop() {
        stopped.set(true)
        if listenFD >= 0 {
            close(listenFD)
            listenFD = -1
        }
    }

    private func acceptLoop() {
        while !stopped.value {
            let cfd = accept(listenFD, nil, nil)
            if cfd < 0 { break }  // listener closed (stop) or fatal error
            let t = Thread { self.serve(cfd) }
            t.name = "box.daemon.conn"
            t.start()
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        var buf = Data()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            if n <= 0 { return }
            if byte != UInt8(ascii: "\n") {
                buf.append(byte)
                if buf.count > 64 * 1024 { return }  // oversized request: drop
                continue
            }
            let line = buf
            buf.removeAll(keepingCapacity: true)
            let response: Daemon.Response
            if let req = try? JSONDecoder().decode(Daemon.Request.self, from: line) {
                response = handler(req)
            } else {
                response = Daemon.Response(ok: false, error: "malformed request")
            }
            guard var out = try? JSONEncoder().encode(response) else { return }
            out.append(UInt8(ascii: "\n"))
            let ok = out.withUnsafeBytes { raw -> Bool in
                var off = 0
                while off < raw.count {
                    let w = write(fd, raw.baseAddress!.advanced(by: off), raw.count - off)
                    if w <= 0 { return false }
                    off += w
                }
                return true
            }
            if !ok { return }
        }
    }
}
