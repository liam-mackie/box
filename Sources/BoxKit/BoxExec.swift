import Containerization
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation

/// Exec into a RUNNING box (`box exec`, and `box shell` when a box for this
/// directory is already up) — run extra shells, background commands, or dev
/// servers in the SAME microVM as the live Claude session.
///
/// box is daemonless: the VM is a child of the launching `box` process, and
/// only that process holds the `LinuxContainer` handle that can spawn
/// additional guest processes (`LinuxContainer.exec`). So the owning process
/// hosts a tiny per-box control server on a unix socket
/// (`~/.box/run/exec-<pid>.sock`), and a second `box` invocation connects as a
/// client and proxies its terminal through it.
///
/// Wire protocol (both directions framed as `type(1) len(4,BE) payload`):
///   client → server:  0x01 header JSON (argv, size, TERM)
///                     0x02 stdin bytes · 0x03 resize JSON · 0x04 stdin EOF
///   server → client:  0x11 output bytes · 0x12 exit code (4 bytes BE)
///
/// Exec'd processes run as the agent (uid 501) with EMPTY capabilities and
/// no_new_privileges — strictly weaker than the entrypoint — so a second shell
/// cannot touch iptables or otherwise widen the box's isolation. They live and
/// die with the box session: anything started here is gone when the box exits.
public enum ExecWire {
    public enum FrameType: UInt8 {
        case header = 0x01
        case stdin = 0x02
        case resize = 0x03
        case stdinEOF = 0x04
        case output = 0x11
        case exit = 0x12
    }

    /// First client frame: what to run and the client terminal's shape.
    public struct Header: Codable, Equatable, Sendable {
        public var args: [String]
        public var cols: UInt16
        public var rows: UInt16
        public var term: String

        public init(args: [String], cols: UInt16, rows: UInt16, term: String) {
            self.args = args
            self.cols = cols
            self.rows = rows
            self.term = term
        }
    }

    public struct Resize: Codable, Equatable, Sendable {
        public var cols: UInt16
        public var rows: UInt16

        public init(cols: UInt16, rows: UInt16) {
            self.cols = cols
            self.rows = rows
        }
    }

    /// `type + length(BE) + payload`.
    public static func encode(_ type: FrameType, _ payload: Data) -> Data {
        var out = Data(capacity: payload.count + 5)
        out.append(type.rawValue)
        var len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }

    /// Decode one frame from the buffer's prefix. Returns nil while the buffer
    /// is still incomplete; `consumed` tells the caller how much to drop.
    /// Unknown types are surfaced (raw byte) so callers can skip them.
    public static func decode(_ buffer: Data) -> (type: UInt8, payload: Data, consumed: Int)? {
        guard buffer.count >= 5 else { return nil }
        let type = buffer[buffer.startIndex]
        var len: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &len) { dst in
            buffer.subdata(in: buffer.startIndex + 1..<buffer.startIndex + 5)
                .copyBytes(to: dst)
        }
        let payloadLen = Int(UInt32(bigEndian: len))
        guard buffer.count >= 5 + payloadLen else { return nil }
        let payload = buffer.subdata(
            in: buffer.startIndex + 5..<buffer.startIndex + 5 + payloadLen)
        return (type, payload, 5 + payloadLen)
    }

    /// The exit frame's 4-byte big-endian payload.
    public static func encodeExitCode(_ code: Int32) -> Data {
        var be = UInt32(bitPattern: code).bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }

    public static func decodeExitCode(_ payload: Data) -> Int32 {
        guard payload.count == 4 else { return 1 }
        var be: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &be) { payload.copyBytes(to: $0) }
        return Int32(bitPattern: UInt32(bigEndian: be))
    }

    /// The control-socket path for a box, derived from the pid embedded in its
    /// id (`box-<dir>-<pid>`), so clients can find it from the id alone.
    public static func socketURL(forPID pid: pid_t) -> URL {
        Box.runDir.appendingPathComponent("exec-\(pid).sock")
    }
}

// MARK: - POSIX helpers shared by server and client

/// Write all of `data` to `fd`, retrying partial writes and EINTR.
private func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
        var offset = 0
        while offset < raw.count {
            let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
            if n > 0 {
                offset += n
            } else if n < 0 && errno == EINTR {
                continue
            } else {
                throw CBError("socket write failed (errno \(errno))")
            }
        }
    }
}

/// Bind-or-connect address setup for a unix socket path.
private func withSockaddrUn<T>(
    _ path: String, _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T
) throws -> T {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
    guard path.utf8.count <= maxLen else {
        throw CBError("socket path too long: \(path)")
    }
    withUnsafeMutableBytes(of: &addr.sun_path) { dst in
        _ = path.utf8.withContiguousStorageIfAvailable { src in
            dst.copyBytes(from: UnsafeRawBufferPointer(start: src.baseAddress, count: src.count))
        }
    }
    return try withUnsafePointer(to: &addr) { p in
        try p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            try body(sa, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

// MARK: - Server (runs inside the owning `box` process)

/// Per-box control server: accepts connections on the unix socket and turns
/// each into a `LinuxContainer.exec`'d process with its stdio proxied over the
/// connection. Blocking socket I/O runs on dedicated `Thread`s (NOT the Swift
/// concurrency pool — the runner's own async work must never be starved by a
/// stuck connection); only the framework calls hop into async Tasks.
final class ExecServer: @unchecked Sendable {
    private let container: LinuxContainer
    private let workingDirectory: String
    private let baseEnv: [String]
    private let socketPath: String
    private var listenFD: Int32 = -1
    private let execCounter = Locked(0)

    /// Env the entrypoint would give the agent, minus TERM (per-connection).
    /// See entrypoint.sh's final `gosu agent env …`. `proxyURL` is the agent's
    /// egress proxy: local squid (single-VM) or the sidecar's vmnet IP (split)
    /// (`--devcontainer` split mode), so exec sessions get the same egress path.
    static func agentEnv(cfg: Config, proxyURL: String = "http://127.0.0.1:3128") -> [String] {
        let proxy = proxyURL
        var env = [
            "HOME=/home/agent", "USER=agent", "LOGNAME=agent",
            "PATH=\(LinuxProcessConfiguration.defaultPath)",
            "HTTP_PROXY=\(proxy)", "HTTPS_PROXY=\(proxy)",
            "http_proxy=\(proxy)", "https_proxy=\(proxy)",
            "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
        ]
        env += Runner.guestEnv(cfg)
        // The same injected env the entrypoint sources for the main process.
        var dotenv: [String: String] = [:]
        if let path = cfg.envFile,
            let text = try? String(contentsOfFile: expandTilde(path), encoding: .utf8)
        {
            dotenv = EnvInjection.parseDotenv(text)
        }
        let merged = EnvInjection.mergedEnv(configEnv: cfg.env, dotenv: dotenv)
        env += merged.keys.sorted().map { "\($0)=\(merged[$0]!)" }
        return env
    }

    /// Start serving, or return nil (with a warning) if the socket can't be
    /// created — the box still runs, just without exec support.
    static func start(
        container: LinuxContainer, cfg: Config, cwd: String,
        proxyURL: String = "http://127.0.0.1:3128"
    ) -> ExecServer? {
        let url = ExecWire.socketURL(forPID: getpid())
        let server = ExecServer(
            container: container, cwd: cwd,
            env: agentEnv(cfg: cfg, proxyURL: proxyURL), socketPath: url.path)
        do {
            try server.listen()
        } catch {
            FileHandle.standardError.write(
                Data(
                    "box: exec server unavailable (\(error)); `box exec` into this box won't work\n"
                        .utf8))
            return nil
        }
        return server
    }

    private init(container: LinuxContainer, cwd: String, env: [String], socketPath: String) {
        self.container = container
        self.workingDirectory = cwd
        self.baseEnv = env
        self.socketPath = socketPath
    }

    private func listen() throws {
        unlink(socketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CBError("socket() failed (errno \(errno))") }
        do {
            try withSockaddrUn(socketPath) { sa, len in
                guard bind(fd, sa, len) == 0 else {
                    throw CBError("bind(\(socketPath)) failed (errno \(errno))")
                }
            }
            // Owner-only: the socket grants shells inside the box.
            chmod(socketPath, 0o600)
            guard Darwin.listen(fd, 8) == 0 else {
                throw CBError("listen() failed (errno \(errno))")
            }
        } catch {
            close(fd)
            throw error
        }
        listenFD = fd
        Thread.detachNewThread { [weak self] in self?.acceptLoop(fd) }
    }

    /// Close the socket; in-flight sessions get EOF as their fds close.
    func stop() {
        if listenFD >= 0 { close(listenFD) }
        listenFD = -1
        unlink(socketPath)
    }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let conn = accept(fd, nil, nil)
            guard conn >= 0 else { return }  // listener closed (stop) or error
            var one: Int32 = 1
            setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            Thread.detachNewThread { [weak self] in self?.connectionLoop(conn) }
        }
    }

    /// One connection: blocking frame reader on this thread; the exec'd
    /// process's lifecycle runs in the async world and reports back through
    /// the (locked) socket writer.
    private func connectionLoop(_ conn: Int32) {
        defer { close(conn) }
        let writer = FrameWriter(fd: conn)
        let stdin = StreamBox()
        let processBox = Locked<LinuxProcess?>(nil)
        var buffer = Data()
        var readBuf = [UInt8](repeating: 0, count: 64 * 1024)
        var started = false

        while true {
            let n = read(conn, &readBuf, readBuf.count)
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { break }  // client hung up (or exit already sent)
            buffer.append(contentsOf: readBuf[0..<n])

            while let frame = ExecWire.decode(buffer) {
                buffer.removeFirst(frame.consumed)
                switch ExecWire.FrameType(rawValue: frame.type) {
                case .header where !started:
                    started = true
                    guard
                        let header = try? JSONDecoder().decode(
                            ExecWire.Header.self, from: frame.payload)
                    else {
                        try? writer.write(
                            Data(
                                "box exec: malformed header (client/server version mismatch?)\r\n"
                                    .utf8))
                        writer.sendExit(1)
                        return
                    }
                    startProcess(
                        header: header, stdin: stdin, writer: writer,
                        processBox: processBox)
                case .stdin:
                    stdin.yield(frame.payload)
                case .resize:
                    if let r = try? JSONDecoder().decode(
                        ExecWire.Resize.self,
                        from: frame.payload),
                        let process = processBox.value
                    {
                        Task {
                            try? await process.resize(
                                to: Terminal.Size(width: r.cols, height: r.rows))
                        }
                    }
                case .stdinEOF:
                    stdin.finish()
                default:
                    break  // unknown/duplicate frame: ignore
                }
            }
        }
        // Client gone: end stdin and hang up the process so it can't linger
        // holding the pty open forever.
        stdin.finish()
        if let process = processBox.value {
            Task { try? await process.kill(.hup) }
        }
    }

    private func startProcess(
        header: ExecWire.Header, stdin: StreamBox, writer: FrameWriter,
        processBox: Locked<LinuxProcess?>
    ) {
        let container = self.container
        let cwd = self.workingDirectory
        let env =
            self.baseEnv
            + ["TERM=\(header.term.isEmpty ? "xterm-256color" : header.term)"]
        let execID = "exec-\(execCounter.increment())"
        let args = header.args.isEmpty ? ["bash"] : header.args

        Task {
            do {
                let process = try await container.exec(execID) { config in
                    config.arguments = args
                    config.environmentVariables = env
                    config.workingDirectory = cwd
                    // The agent, with strictly FEWER privileges than the
                    // entrypoint gives it: no capabilities at all, and none
                    // acquirable — a second shell must not be able to touch
                    // iptables or otherwise widen the box's isolation.
                    config.user = User(uid: 501, gid: 501)
                    config.capabilities = LinuxCapabilities()
                    config.noNewPrivileges = true
                    config.terminal = true
                    config.stdin = stdin
                    config.stdout = writer
                    // No stderr writer: with terminal=true the guest pty merges
                    // stderr into stdout, and the framework REJECTS a configured
                    // stderr ("stderr should not be configured with terminal=true").
                }
                processBox.value = process
                try await process.start()
                try? await process.resize(
                    to: Terminal.Size(width: header.cols, height: header.rows))
                let status = try await process.wait()
                writer.sendExit(status.exitCode)
                try? await process.delete()
            } catch {
                // Report to the CLIENT, never to this process's stderr — that
                // is the live Claude TUI, and writing there scribbles over it.
                // \r\n because the client terminal is in raw mode (no OPOST).
                try? writer.write(Data("box exec: session failed: \(error)\r\n".utf8))
                writer.sendExit(1)
            }
            writer.shutdown()  // wakes the connection thread's read() with EOF
        }
    }
}

/// A tiny generic lock-box (NSLock-guarded value).
final class Locked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            stored = newValue
        }
    }
    func withLock<R>(_ body: (inout T) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body(&stored)
    }
}

extension Locked where T == Int {
    func increment() -> Int {
        withLock {
            $0 += 1
            return $0
        }
    }
}

/// The exec'd process's stdin: frames decoded on the connection thread are
/// yielded into an AsyncStream the framework consumes.
final class StreamBox: ReaderStream, @unchecked Sendable {
    private let streamValue: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation

    init() {
        var c: AsyncStream<Data>.Continuation!
        streamValue = AsyncStream { c = $0 }
        continuation = c
    }

    func stream() -> AsyncStream<Data> { streamValue }
    func yield(_ data: Data) { continuation.yield(data) }
    func finish() { continuation.finish() }
}

/// The exec'd process's stdout/stderr: frames guest output back over the
/// socket. Lock-serialized — output arrives from framework tasks while exit
/// and resize traffic comes from elsewhere.
final class FrameWriter: Writer, @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()

    init(fd: Int32) { self.fd = fd }

    func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try writeAll(fd, ExecWire.encode(.output, data))
    }

    func close() throws {}  // connection lifetime is managed by the server

    func sendExit(_ code: Int32) {
        lock.lock()
        defer { lock.unlock() }
        try? writeAll(fd, ExecWire.encode(.exit, ExecWire.encodeExitCode(code)))
    }

    /// Half-close so the connection thread's blocking read() sees EOF.
    func shutdown() {
        Darwin.shutdown(fd, SHUT_RDWR)
    }
}

// MARK: - Client (`box exec` / `box shell` into a running box)

public enum ExecClient {
    /// True if `id` has a live control socket to connect to.
    public static func available(forBoxID id: String) -> Bool {
        guard let pid = RunState.pid(fromID: id) else { return false }
        return FileManager.default.fileExists(atPath: ExecWire.socketURL(forPID: pid).path)
    }

    /// Connect to the box's control socket and run `command` (default: bash)
    /// interactively, proxying this terminal. Returns the guest exit code.
    public static func run(boxID: String, command: [String]) throws -> Int32 {
        guard let pid = RunState.pid(fromID: boxID) else {
            throw CBError("\"\(boxID)\" is not a valid box id (expected box-<dir>-<pid>).")
        }
        let path = ExecWire.socketURL(forPID: pid).path
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CBError("socket() failed (errno \(errno))") }
        defer { close(fd) }
        try withSockaddrUn(path) { sa, len in
            guard connect(fd, sa, len) == 0 else {
                throw CBError(
                    "cannot connect to box \"\(boxID)\" (\(path), errno \(errno)) — "
                        + "is it still running? (`box ls`)")
            }
        }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        // Terminal setup (raw mode so the guest pty owns line discipline).
        let term = try? Terminal.current
        let size = (try? term?.size) ?? Terminal.Size(width: 120, height: 40)
        let sendLock = NSLock()
        @Sendable func send(_ type: ExecWire.FrameType, _ payload: Data) {
            sendLock.lock()
            defer { sendLock.unlock() }
            try? writeAll(fd, ExecWire.encode(type, payload))
        }

        let header = ExecWire.Header(
            args: command, cols: size.width, rows: size.height,
            term: env("TERM") ?? "xterm-256color")
        send(.header, try JSONEncoder().encode(header))

        try? term?.setraw()
        defer { term?.tryReset() }

        // Resize propagation.
        signal(SIGWINCH, SIG_IGN)
        let winch = DispatchSource.makeSignalSource(
            signal: SIGWINCH,
            queue: DispatchQueue(label: "box.exec.winch"))
        winch.setEventHandler {
            if let s = try? Terminal.current.size,
                let payload = try? JSONEncoder().encode(
                    ExecWire.Resize(
                        cols: s.width,
                        rows: s.height))
            {
                send(.resize, payload)
            }
        }
        winch.resume()
        defer { winch.cancel() }

        // Stdin pump on its own thread.
        Thread.detachNewThread {
            var buf = [UInt8](repeating: 0, count: 16 * 1024)
            while true {
                let n = read(STDIN_FILENO, &buf, buf.count)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else {
                    send(.stdinEOF, Data())
                    return
                }
                send(.stdin, Data(buf[0..<n]))
            }
        }

        // This thread: pump server frames until exit/EOF.
        var buffer = Data()
        var readBuf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            if let frame = ExecWire.decode(buffer) {
                buffer.removeFirst(frame.consumed)
                switch ExecWire.FrameType(rawValue: frame.type) {
                case .output:
                    FileHandle.standardOutput.write(frame.payload)
                case .exit:
                    return ExecWire.decodeExitCode(frame.payload)
                default:
                    break
                }
                continue
            }
            let n = read(fd, &readBuf, readBuf.count)
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else {
                throw CBError("connection to box \"\(boxID)\" closed unexpectedly")
            }
            buffer.append(contentsOf: readBuf[0..<n])
        }
    }
}
