import Containerization
import Foundation
import vmnet

/// Cross-PROCESS half of the vmnet probe (`box __netprobe --cross`): can a VM
/// in process B attach to a vmnet network created in process A?
///
/// This is the validation harness for the `SharedVmnet` primitives the shared
/// proxy-sidecar daemon is built on (see SharedVmnet.swift for the mechanism
/// and the Virtualization.framework caveat it answers). Topology proven on
/// PASS: A creates network + token file + a server VM; B rehydrates from the
/// token, boots a client VM on the SAME network, and TCP-connects to A's VM —
/// exactly daemon-sidecar ↔ dev VM. Kept as a hidden diagnostic so an OS
/// update that changes vmnet behavior is one command to re-check.
public enum NetProbeCross {
    static let tokenFile = "network.bin"
    static let serverIPFile = "server-ip"

    /// Process A: create the network, drop its token + the server VM's IP into
    /// `dir`, then park until the orchestrator kills us (the network dies with
    /// its creating process).
    public static func serve(dir: String) async throws {
        let dirURL = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)

        let ref = try SharedVmnet.createNetwork()
        try SharedVmnet.token(for: ref).write(
            to: dirURL.appendingPathComponent(tokenFile), options: [.atomic])

        let store = try ImageStore(path: Box.storeDir)
        let image = try await ImageBridge.ensure(store: store)
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: try SharedVmnetNetwork(reference: ref, hostOffsets: [2])
        )
        let server = try await manager.create(
            "box-xprobe-server", image: image, rootfsSizeInBytes: 4 << 30
        ) { config in
            config.process.arguments = [
                "/bin/sh", "-c",
                "python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1",
            ]
            config.cpus = 1
            config.memoryInBytes = 1 << 30
        }
        try await server.create()
        try await server.start()
        guard let iface = server.interfaces.first else {
            throw CBError("cross-probe: server VM got no interface")
        }
        try "\(iface.ipv4Address.address)".write(
            to: dirURL.appendingPathComponent(serverIPFile), atomically: true, encoding: .utf8)
        FileHandle.standardError.write(
            Data("cross-probe[serve]: network + server VM up, parked\n".utf8))
        _ = try await server.wait()
        try? manager.delete("box-xprobe-server")
    }

    /// Process B: rehydrate the network from A's token and try to put a VM on
    /// it. Exit codes: 0 full PASS; 7 attach OK but no guest→guest traffic;
    /// 8 rehydration failed; 9 VZ refused the cross-process network.
    public static func join(dir: String) async throws -> Int32 {
        let dirURL = URL(fileURLWithPath: dir, isDirectory: true)
        let token = try Data(contentsOf: dirURL.appendingPathComponent(tokenFile))
        let serverIP = try String(
            contentsOf: dirURL.appendingPathComponent(serverIPFile), encoding: .utf8
        ).trimmingCharacters(in: .whitespacesAndNewlines)

        let ref: vmnet_network_ref
        do {
            ref = try SharedVmnet.network(fromToken: token)
        } catch {
            print("cross-probe: FAIL — rehydration in second process: \(error)")
            return 8
        }
        FileHandle.standardError.write(
            Data("cross-probe[join]: network rehydrated; booting client VM…\n".utf8))

        let store = try ImageStore(path: Box.storeDir)
        let image = try await ImageBridge.ensure(store: store)
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: try SharedVmnetNetwork(reference: ref, hostOffsets: [10])
        )
        let script = """
            for i in $(seq 1 20); do
                curl -s -o /dev/null -m 2 http://\(serverIP):8000/ && exit 0
                sleep 1
            done
            exit 7
            """
        let client = try await manager.create(
            "box-xprobe-client", image: image, rootfsSizeInBytes: 4 << 30
        ) { config in
            config.process.arguments = ["/bin/sh", "-c", script]
            config.cpus = 1
            config.memoryInBytes = 1 << 30
        }
        try await client.create()
        do {
            try await client.start()
        } catch {
            print("cross-probe: FAIL — VZ refused the cross-process network: \(error)")
            try? await client.stop()
            return 9
        }
        let statusCode = try await client.wait(timeoutInSeconds: 60)
        try? await client.stop()
        try? manager.delete("box-xprobe-client")

        switch statusCode.exitCode {
        case 0:
            print("cross-probe: PASS — cross-process network + direct guest→guest TCP")
        case 7:
            print("cross-probe: PARTIAL — VM attached cross-process, but no guest→guest traffic")
        default:
            print("cross-probe: INCONCLUSIVE — client exited \(statusCode.exitCode)")
        }
        return statusCode.exitCode
    }

    /// One-command orchestration: spawn ourselves as the serve half, wait for
    /// its artifacts, run the join half, tear down.
    public static func orchestrate() async throws -> Int32 {
        let dir = Box.runDir.appendingPathComponent("xprobe-\(getpid())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        guard let exe = Bundle.main.executablePath else {
            throw CBError("cross-probe: cannot resolve own executable path")
        }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: exe)
        child.arguments = ["__netprobe", "--cross-serve", dir.path]
        try child.run()
        defer { if child.isRunning { child.terminate() } }

        // Wait for the serve half to publish the server VM's IP (it writes the
        // token first, the IP once its VM is up).
        let ipFile = dir.appendingPathComponent(serverIPFile).path
        for _ in 0..<120 {
            if FileManager.default.fileExists(atPath: ipFile) { break }
            if !child.isRunning {
                throw CBError("cross-probe: serve half exited early — see its stderr above")
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        guard FileManager.default.fileExists(atPath: ipFile) else {
            throw CBError("cross-probe: timed out waiting for the serve half")
        }
        return try await join(dir: dir.path)
    }
}
