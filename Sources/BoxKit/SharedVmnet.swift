import Containerization
import ContainerizationExtras
import Foundation
import XPC
import vmnet

/// Raw vmnet-network primitives for topologies the framework's `VmnetNetwork`
/// can't express: networks that OUTLIVE one VM's runner process and are shared
/// ACROSS processes. The daemon creates a network here, serializes it to a
/// portable token (a plain ~120-byte blob — verified mach-port-free, so any
/// channel can carry it), and each `box run` rehydrates a ref from the token
/// and attaches its dev VM. Guests on one network reach each other directly
/// (`box __netprobe`), so the shared squid sidecar needs no host relay and
/// sees every box's real source IP.
///
/// Rehydration satisfies Virtualization.framework's "a VM can only use a
/// network created by the same application process" rule because
/// `vmnet_network_create_with_serialization` IS an in-process creation
/// (verified cross-process end-to-end — `box __netprobe --cross`).
public enum SharedVmnet {
    /// The single key observed in `vmnet_network_copy_serialization`'s XPC
    /// dictionary. We ship only its data payload and rebuild the dictionary on
    /// rehydration, failing loudly if the shape ever changes.
    static let serializationKey = "networkSerialization"

    /// Create a raw shared-mode (NAT) network with DHCP off — same settings as
    /// the framework's `VmnetNetwork`, but exposing the ref for serialization.
    /// The ref dies with the creating process; everything attached loses its
    /// network then, which is why the DAEMON must be the creator.
    public static func createNetwork() throws -> vmnet_network_ref {
        var status = vmnet_return_t.VMNET_FAILURE
        guard let config = vmnet_network_configuration_create(.VMNET_SHARED_MODE, &status) else {
            throw CBError("vmnet: network configuration failed: \(status)")
        }
        vmnet_network_configuration_disable_dhcp(config)
        guard let ref = vmnet_network_create(config, &status) else {
            throw CBError("vmnet: network creation failed: \(status)")
        }
        return ref
    }

    /// The portable token for `ref` (the serialization dictionary's payload).
    public static func token(for ref: vmnet_network_ref) throws -> Data {
        var status = vmnet_return_t.VMNET_FAILURE
        guard let ser = vmnet_network_copy_serialization(ref, &status),
            let payload = xpc_dictionary_get_value(ser, serializationKey),
            xpc_get_type(payload) == XPC_TYPE_DATA,
            let ptr = xpc_data_get_bytes_ptr(payload)
        else {
            throw CBError(
                "vmnet: serialization did not contain '\(serializationKey)' data "
                    + "(status \(status)); the OS serialization shape may have changed")
        }
        return Data(bytes: ptr, count: xpc_data_get_length(payload))
    }

    /// Rehydrate a network ref from a token minted by another process. The
    /// resulting ref is valid only while the MINTING process (and so the
    /// underlying network) is alive.
    public static func network(fromToken token: Data) throws -> vmnet_network_ref {
        let payload = token.withUnsafeBytes { xpc_data_create($0.baseAddress, token.count) }
        let dict = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_value(dict, serializationKey, payload)
        var status = vmnet_return_t.VMNET_FAILURE
        guard let ref = vmnet_network_create_with_serialization(dict, &status) else {
            throw CBError("vmnet: network rehydration failed: \(status) (daemon restarted?)")
        }
        return ref
    }

    /// The IPv4 subnet of a raw ref (mirrors `VmnetNetwork`'s private helper).
    public static func subnet(of ref: vmnet_network_ref) throws -> CIDRv4 {
        var s = in_addr()
        var m = in_addr()
        vmnet_network_get_ipv4_subnet(ref, &s, &m)
        let sa = UInt32(bigEndian: s.s_addr)
        let mv = UInt32(bigEndian: m.s_addr)
        let lower = IPv4Address(sa & mv)
        let upper = IPv4Address(lower.value + ~mv)
        return try CIDRv4(lower: lower, upper: upper)
    }
}

/// `Network` conformance over an externally-managed `vmnet_network_ref`, with
/// EXPLICIT address assignment: interfaces are handed the pooled IPs in order.
/// IP coordination lives OUTSIDE (the daemon leases addresses; a `box run`
/// pools exactly its one leased IP) because in-process allocators can't see
/// each other across processes sharing one subnet.
public struct SharedVmnetNetwork: Network {
    nonisolated(unsafe) let reference: vmnet_network_ref
    public let subnet: CIDRv4
    private var pool: [IPv4Address]

    /// Pool from host offsets relative to the subnet base (e.g. `[2]` → .2).
    public init(reference: vmnet_network_ref, hostOffsets: [UInt32]) throws {
        self.reference = reference
        let subnet = try SharedVmnet.subnet(of: reference)
        self.subnet = subnet
        self.pool = hostOffsets.map { IPv4Address(subnet.lower.value + $0) }
    }

    /// Pool of concrete addresses (must lie inside the ref's subnet).
    public init(reference: vmnet_network_ref, ips: [IPv4Address]) throws {
        self.reference = reference
        self.subnet = try SharedVmnet.subnet(of: reference)
        self.pool = ips
    }

    public mutating func createInterface(_ id: String) throws -> Containerization.Interface? {
        guard !pool.isEmpty else {
            throw CBError("shared vmnet: no pooled IP left for interface \(id)")
        }
        let ip = pool.removeFirst()
        return VmnetNetwork.Interface(
            reference: reference,
            ipv4Address: try CIDRv4(ip, prefix: subnet.prefix),
            ipv4Gateway: subnet.gateway)
    }

    public mutating func releaseInterface(_ id: String) throws {}
}
