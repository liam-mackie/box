import Containerization
import Foundation
import XPC
import vmnet

/// Hidden diagnostic (`box __netprobe`): can two microVMs on ONE `VmnetNetwork`
/// open a TCP connection to each other DIRECTLY?
///
/// Why this exists: split-proxy mode currently routes the dev VM's egress
/// through a host TCP relay (`ProxyRelay`) because guest→guest traffic was
/// observed not to work. But that observation was made from inside a client VM
/// whose own iptables lockdown was already active (OUTPUT default-deny to
/// everything but the gateway), so it may have measured the box's OWN firewall,
/// not vmnet. Apple's `VZVmnetNetworkDeviceAttachment` documentation explicitly
/// says the shared-network attachment lets "multiple virtual machines appear on
/// the same network and connect with each other". This probe settles it: two
/// firewall-free VMs (entrypoint bypassed), one `python3 -m http.server`, one
/// curl loop against the server's vmnet IP. Exit 0 ⇒ direct guest→guest TCP
/// works and the relay can go; exit 7 ⇒ vmnet really does isolate guests.
public enum NetProbe {
    /// Probe half 2 (`box __netprobe --inspect`): what does
    /// `vmnet_network_copy_serialization` produce, and does
    /// `vmnet_network_create_with_serialization` round-trip it in-process?
    /// The serialization's XPC type decides the daemon's handoff channel: a
    /// plain data/dictionary payload can cross any pipe; an embedded mach port
    /// forces a real XPC connection (launchd mach service).
    public static func inspectSerialization() throws {
        var status = vmnet_return_t.VMNET_FAILURE
        guard let config = vmnet_network_configuration_create(.VMNET_SHARED_MODE, &status) else {
            throw CBError("vmnet_network_configuration_create failed: \(status)")
        }
        vmnet_network_configuration_disable_dhcp(config)
        guard let network = vmnet_network_create(config, &status) else {
            throw CBError("vmnet_network_create failed: \(status)")
        }
        var subnet = in_addr()
        var mask = in_addr()
        vmnet_network_get_ipv4_subnet(network, &subnet, &mask)
        print("original network subnet: \(Self.ipString(subnet))/\(Self.ipString(mask))")

        guard let ser = vmnet_network_copy_serialization(network, &status) else {
            throw CBError("vmnet_network_copy_serialization failed: \(status)")
        }
        let type = xpc_get_type(ser)
        let typeName = String(cString: xpc_type_get_name(type))
        print("serialization xpc type: \(typeName)")
        print("serialization description:\n\(String(cString: xpc_copy_description(ser)))")

        var status2 = vmnet_return_t.VMNET_FAILURE
        guard let network2 = vmnet_network_create_with_serialization(ser, &status2) else {
            print("round-trip: vmnet_network_create_with_serialization FAILED: \(status2)")
            return
        }
        var subnet2 = in_addr()
        var mask2 = in_addr()
        vmnet_network_get_ipv4_subnet(network2, &subnet2, &mask2)
        print("round-trip network subnet: \(Self.ipString(subnet2))/\(Self.ipString(mask2))")
        print("round-trip: OK (same-process)")
    }

    private static func ipString(_ addr: in_addr) -> String {
        var a = addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
        let bytes = buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    public static func run() async throws -> Int32 {
        let store = try ImageStore(path: Box.storeDir)
        let image = try await ImageBridge.ensure(store: store)
        let kernel = Kernel(path: try Box.kernelPath(), platform: .linuxArm)
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: Box.vminitRef,
            imageStore: store,
            network: try VmnetNetwork()
        )

        let rootfs: UInt64 = 4 << 30
        FileHandle.standardError.write(Data("netprobe: booting server VM…\n".utf8))
        let server = try await manager.create(
            "box-netprobe-server", image: image, rootfsSizeInBytes: rootfs
        ) { config in
            // Entrypoint bypassed: NO squid, NO iptables — a bare TCP listener.
            config.process.arguments = [
                "/bin/sh", "-c",
                "python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1",
            ]
            config.cpus = 1
            config.memoryInBytes = 1 << 30
        }
        try await server.create()
        try await server.start()
        defer { Task { try? await server.stop() } }
        guard let iface = server.interfaces.first else {
            throw CBError("netprobe: server VM got no network interface")
        }
        let serverIP = "\(iface.ipv4Address.address)"
        let gateway = iface.ipv4Gateway.map { "\($0)" } ?? "?"
        FileHandle.standardError.write(
            Data("netprobe: server \(serverIP):8000 (gateway \(gateway)); booting client VM…\n".utf8))

        // Client retries for up to ~20s (covers the server VM's python startup),
        // then reports: 0 = connected, 7 = never reachable. The gateway curl is a
        // control — host↔guest is known-good, so if the control ALSO fails the
        // probe itself is broken, not vmnet.
        let script = """
            for i in $(seq 1 20); do
                curl -s -o /dev/null -m 2 http://\(serverIP):8000/ && exit 0
                sleep 1
            done
            exit 7
            """
        let client = try await manager.create(
            "box-netprobe-client", image: image, rootfsSizeInBytes: rootfs
        ) { config in
            config.process.arguments = ["/bin/sh", "-c", script]
            config.cpus = 1
            config.memoryInBytes = 1 << 30
        }
        try await client.create()
        try await client.start()
        let status = try await client.wait(timeoutInSeconds: 60)
        try? await client.stop()
        try? await server.stop()
        // Reclaim both registrations so the diagnostic leaves no orphans.
        try? manager.delete("box-netprobe-client")
        try? manager.delete("box-netprobe-server")

        switch status.exitCode {
        case 0:
            print("netprobe: PASS — direct guest→guest TCP works on this VmnetNetwork")
        case 7:
            print("netprobe: FAIL — guest→guest TCP blocked (vmnet isolation confirmed)")
        default:
            print("netprobe: INCONCLUSIVE — client exited \(status.exitCode)")
        }
        return status.exitCode
    }
}
