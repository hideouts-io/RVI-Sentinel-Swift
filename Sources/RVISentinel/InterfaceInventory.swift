import Darwin
import Foundation

enum InterfaceInventoryError: LocalizedError {
    case enumerationFailed(Int32)

    var errorDescription: String? {
        switch self {
        case let .enumerationFailed(code):
            "macOS interface enumeration failed with errno \(code): \(String(cString: strerror(code)))"
        }
    }
}

private struct InterfaceAccumulator {
    let name: String
    var flags: UInt32
    var ipv4Addresses: Set<String>
    var ipv6Addresses: Set<String>
    var macAddress: String?
}

struct InterfaceInventoryService: Sendable {
    func inventory() throws -> [NetworkInterfaceInfo] {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        let result = getifaddrs(&pointer)
        guard result == 0, let first = pointer else {
            throw InterfaceInventoryError.enumerationFailed(errno)
        }
        defer { freeifaddrs(pointer) }

        var accumulators: [String: InterfaceAccumulator] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let record = current.pointee
            let name = String(cString: record.ifa_name)
            var accumulator = accumulators[name] ?? InterfaceAccumulator(
                name: name,
                flags: record.ifa_flags,
                ipv4Addresses: [],
                ipv6Addresses: [],
                macAddress: nil
            )
            accumulator.flags = record.ifa_flags
            if let address = record.ifa_addr {
                let family = Int32(address.pointee.sa_family)
                if family == AF_INET, let value = numericAddress(address: address) {
                    accumulator.ipv4Addresses.insert(value)
                } else if family == AF_INET6, let value = numericAddress(address: address) {
                    accumulator.ipv6Addresses.insert(value)
                } else if family == AF_LINK {
                    accumulator.macAddress = macAddress(address: address)
                }
            }
            accumulators[name] = accumulator
            cursor = record.ifa_next
        }
        return accumulators.values
            .map(interfaceInfo(from:))
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}

private func numericAddress(address: UnsafePointer<sockaddr>) -> String? {
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let length: socklen_t = address.pointee.sa_family == UInt8(AF_INET)
        ? socklen_t(MemoryLayout<sockaddr_in>.size)
        : socklen_t(MemoryLayout<sockaddr_in6>.size)
    let result = getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
    guard result == 0 else { return nil }
    let bytes = host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
}

private func macAddress(address: UnsafePointer<sockaddr>) -> String? {
    let link = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_dl.self).pointee
    guard link.sdl_alen > 0 else { return nil }
    let nameLength = Int(link.sdl_nlen)
    let addressLength = Int(link.sdl_alen)
    return withUnsafeBytes(of: link.sdl_data) { bytes in
        let start = nameLength
        let end = start + addressLength
        guard end <= bytes.count else { return nil }
        return bytes[start..<end].map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

private func interfaceInfo(from accumulator: InterfaceAccumulator) -> NetworkInterfaceInfo {
    let classification = classifyInterface(name: accumulator.name)
    return NetworkInterfaceInfo(
        name: accumulator.name,
        friendlyType: classification.friendlyType,
        isUp: accumulator.flags & UInt32(IFF_UP) != 0,
        ipv4Addresses: accumulator.ipv4Addresses.sorted(),
        ipv6Addresses: accumulator.ipv6Addresses.sorted(),
        macAddress: accumulator.macAddress,
        mtu: nil,
        flags: decodedFlags(accumulator.flags),
        linkType: accumulator.macAddress == nil ? "Network interface" : "Ethernet-style link",
        associatedService: classification.associatedService,
        owner: classification.owner,
        isSelectable: classification.isSelectable,
        evidenceSource: "macOS getifaddrs; ownership is name-based classification"
    )
}

struct InterfaceClassification: Equatable {
    let friendlyType: String
    let associatedService: String
    let owner: InterfaceOwner
    let isSelectable: Bool
}

func captureReportedIOSInterfaces(names: [String]) -> [NetworkInterfaceInfo] {
    let uniqueNames: Set<String> = Set(names.filter { !$0.isEmpty && !isTemporaryRVIInterface(name: $0) })
    return uniqueNames.map { name in
        let classification: InterfaceClassification = classifyObservedIOSInterface(name: name)
        return NetworkInterfaceInfo(
            name: name,
            friendlyType: classification.friendlyType,
            isUp: true,
            ipv4Addresses: [],
            ipv6Addresses: [],
            macAddress: nil,
            mtu: nil,
            flags: ["OBSERVED"],
            linkType: "Capture metadata",
            associatedService: classification.associatedService,
            owner: .ios,
            isSelectable: false,
            evidenceSource: "Packet metadata field frame.interface_name"
        )
    }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
}

func isTemporaryRVIInterface(name: String) -> Bool {
    name.range(of: #"^rvi[0-9]+$"#, options: .regularExpression) != nil
}

func classifyObservedIOSInterface(name: String) -> InterfaceClassification {
    if name.hasPrefix("pdp_ip") {
        return InterfaceClassification(friendlyType: "Cellular packet data", associatedService: "iOS cellular networking", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("utun") {
        return InterfaceClassification(friendlyType: "User tunnel", associatedService: "iOS VPN or system tunnel", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("en") {
        return InterfaceClassification(friendlyType: "Ethernet or Wi-Fi", associatedService: "iOS network interface", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("lo") {
        return InterfaceClassification(friendlyType: "Loopback", associatedService: "Local iOS traffic", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("awdl") {
        return InterfaceClassification(friendlyType: "Apple Wireless Direct Link", associatedService: "AirDrop, AirPlay, and peer services", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("llw") {
        return InterfaceClassification(friendlyType: "Low-latency Wi-Fi", associatedService: "Apple peer networking", owner: .ios, isSelectable: false)
    }
    if name.hasPrefix("ipsec") {
        return InterfaceClassification(friendlyType: "IPsec tunnel", associatedService: "iOS encrypted tunnel", owner: .ios, isSelectable: false)
    }
    return InterfaceClassification(friendlyType: "Capture-reported interface", associatedService: "iOS role not established", owner: .ios, isSelectable: false)
}

func classifyInterface(name: String) -> InterfaceClassification {
    if name.hasPrefix("rvi") {
        return InterfaceClassification(friendlyType: "Remote Virtual Interface", associatedService: "Apple RVI", owner: .remoteVirtualInterface, isSelectable: true)
    }
    if name.hasPrefix("utun") {
        return InterfaceClassification(friendlyType: "User tunnel", associatedService: "VPN or system tunnel", owner: .vpn, isSelectable: true)
    }
    if name == "lo0" {
        return InterfaceClassification(friendlyType: "Loopback", associatedService: "Local host", owner: .mac, isSelectable: true)
    }
    if name == "awdl0" {
        return InterfaceClassification(friendlyType: "Apple Wireless Direct Link", associatedService: "AirDrop, AirPlay, and peer services", owner: .mac, isSelectable: true)
    }
    if name == "llw0" {
        return InterfaceClassification(friendlyType: "Low-latency Wi-Fi", associatedService: "Apple peer networking", owner: .mac, isSelectable: true)
    }
    if name.hasPrefix("bridge") {
        return InterfaceClassification(friendlyType: "Network bridge", associatedService: "macOS bridge", owner: .mac, isSelectable: true)
    }
    if name.hasPrefix("en") {
        return InterfaceClassification(friendlyType: "Ethernet or Wi-Fi", associatedService: "macOS network service", owner: .mac, isSelectable: true)
    }
    if name.hasPrefix("gif") || name.hasPrefix("stf") {
        return InterfaceClassification(friendlyType: "IP tunnel", associatedService: "macOS tunnel", owner: .vpn, isSelectable: true)
    }
    if name.hasPrefix("pdp_ip") {
        return InterfaceClassification(friendlyType: "Packet data interface", associatedService: "Host-reported cellular-style interface", owner: .unknown, isSelectable: true)
    }
    return InterfaceClassification(friendlyType: "Other interface", associatedService: "Unclassified macOS interface", owner: .unknown, isSelectable: true)
}

private func decodedFlags(_ flags: UInt32) -> [String] {
    let values: [(UInt32, String)] = [
        (UInt32(IFF_UP), "UP"),
        (UInt32(IFF_RUNNING), "RUNNING"),
        (UInt32(IFF_LOOPBACK), "LOOPBACK"),
        (UInt32(IFF_BROADCAST), "BROADCAST"),
        (UInt32(IFF_MULTICAST), "MULTICAST"),
        (UInt32(IFF_POINTOPOINT), "POINT_TO_POINT")
    ]
    return values.compactMap { mask, name in flags & mask != 0 ? name : nil }
}
