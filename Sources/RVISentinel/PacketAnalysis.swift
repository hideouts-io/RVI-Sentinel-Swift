import Darwin
import Foundation

private struct EndpointAccumulator {
    let address: String
    let version: String
    let classification: String
    var firstSeen: Date
    var lastSeen: Date
    var sourcePackets: Int
    var destinationPackets: Int
    var sourceBytes: Int64
    var destinationBytes: Int64
    var protocols: Set<ProtocolKind>
    var ports: Set<String>
}

private struct ProtocolAccumulator {
    var packetCount: Int
    var byteCount: Int64
    var evidence: Set<String>
}

private struct PortAccumulator {
    var packetCount: Int
}

private struct ProtocolDetailAccumulator {
    let protocolKind: ProtocolKind
    let category: String
    let label: String
    let field: TSharkField
    let value: String
    var occurrenceCount: Int
}

private struct ProtocolFieldKey: Hashable {
    let protocolKind: ProtocolKind
    let field: TSharkField
}

let protocolDetailMaximumDistinctValuesPerField = 250

struct AnalysisAccumulator {
    private(set) var packetCount = 0
    private(set) var byteCount: Int64 = 0
    private(set) var firstPacket: Date?
    private(set) var lastPacket: Date?
    private(set) var interfaces: Set<String> = []
    private var endpoints: [String: EndpointAccumulator] = [:]
    private var hostnameEvidence: [String: HostnameEvidence] = [:]
    private var protocols: [ProtocolKind: ProtocolAccumulator] = [:]
    private var ports: [String: PortAccumulator] = [:]
    private var protocolDetails: [String: ProtocolDetailAccumulator] = [:]
    private var protocolDetailDistinctCounts: [ProtocolFieldKey: Int] = [:]
    private var omittedProtocolDetailOccurrences: [ProtocolFieldKey: Int] = [:]
    private var protocolDetailDefinitions: [ProtocolFieldKey: ProtocolDetailDefinition] = [:]

    mutating func consume(packet: DecodedPacket) throws {
        guard let timestampText = packet.first(.frameTimeEpoch),
              let timestampValue = TimeInterval(timestampText),
              let lengthText = packet.first(.frameLength),
              let length = Int64(lengthText) else {
            throw NativeAnalysisError.malformedRow("frame time or length was absent or invalid")
        }
        let timestamp = Date(timeIntervalSince1970: timestampValue)
        packetCount += 1
        byteCount += length
        firstPacket = minDate(firstPacket, timestamp)
        lastPacket = maxDate(lastPacket, timestamp)
        if let interfaceName = packet.first(.frameInterfaceName), !interfaceName.isEmpty {
            interfaces.insert(interfaceName)
        }

        let observedProtocols = protocolKinds(packet: packet)
        for protocolKind in observedProtocols {
            var accumulator = protocols[protocolKind] ?? ProtocolAccumulator(packetCount: 0, byteCount: 0, evidence: [])
            accumulator.packetCount += 1
            accumulator.byteCount += length
            accumulator.evidence.formUnion(protocolEvidence(packet: packet, protocolKind: protocolKind))
            protocols[protocolKind] = accumulator
        }
        addProtocolDetails(packet: packet, observedProtocols: observedProtocols)

        let sourceAddress = packet.first(.ipv4Source) ?? packet.first(.ipv6Source)
        let destinationAddress = packet.first(.ipv4Destination) ?? packet.first(.ipv6Destination)
        let sourcePort = transportPort(packet: packet, source: true)
        let destinationPort = transportPort(packet: packet, source: false)
        let transport = packet.first(.tcpSourcePort) == nil ? "UDP" : "TCP"
        if let sourceAddress {
            updateEndpoint(address: sourceAddress, timestamp: timestamp, length: length, asSource: true, protocols: observedProtocols, port: sourcePort.map { "\(transport)/\($0)" })
        }
        if let destinationAddress {
            updateEndpoint(address: destinationAddress, timestamp: timestamp, length: length, asSource: false, protocols: observedProtocols, port: destinationPort.map { "\(transport)/\($0)" })
        }
        if let sourcePort { updatePort(transport: transport, port: sourcePort) }
        if let destinationPort { updatePort(transport: transport, port: destinationPort) }

        addHostnameEvidence(packet: packet, timestamp: timestamp, destinationAddress: destinationAddress)
    }

    func result(captureURL: URL, hash: String, coverage: AnalysisCoverage) -> NativeAnalysisResult {
        let endpointRows = endpoints.values.map { value in
            EndpointObservation(
                address: value.address,
                version: value.version,
                classification: value.classification,
                firstSeen: value.firstSeen,
                lastSeen: value.lastSeen,
                sourcePackets: value.sourcePackets,
                destinationPackets: value.destinationPackets,
                sourceBytes: value.sourceBytes,
                destinationBytes: value.destinationBytes,
                protocols: value.protocols.sorted { $0.rawValue < $1.rawValue },
                ports: value.ports.sorted(),
                processAttribution: .unavailable(sourceHost: "Capture source")
            )
        }.sorted { left, right in
            let leftBytes = left.sourceBytes + left.destinationBytes
            let rightBytes = right.sourceBytes + right.destinationBytes
            return leftBytes == rightBytes ? left.address < right.address : leftBytes > rightBytes
        }
        var protocolRows: [ProtocolObservation] = []
        for (kind, value) in protocols {
            let row = ProtocolObservation(
                protocolKind: kind,
                packetCount: value.packetCount,
                byteCount: value.byteCount,
                identification: value.evidence.sorted().joined(separator: "; ")
            )
            protocolRows.append(row)
        }
        protocolRows.sort { left, right in
            left.packetCount == right.packetCount
                ? left.protocolKind.rawValue < right.protocolKind.rawValue
                : left.packetCount > right.packetCount
        }
        var portRows: [PortObservation] = []
        for (key, value) in ports {
            let pieces = key.split(separator: "/")
            guard pieces.count == 2, let port = Int(pieces[1]) else { continue }
            let transport = String(pieces[0])
            let description = describePort(transport: transport, port: port)
            let row = PortObservation(
                transport: transport,
                port: port,
                packetCount: value.packetCount,
                standardService: description.service,
                explanation: description.explanation,
                evidenceBoundary: "The port number is direct evidence; the standard service label does not prove the application protocol."
            )
            portRows.append(row)
        }
        portRows.sort { left, right in
            left.packetCount == right.packetCount ? left.port < right.port : left.packetCount > right.packetCount
        }
        var detailRows = protocolDetails.values.map { value in
            ProtocolDetailObservation(
                protocolKind: value.protocolKind,
                category: value.category,
                label: value.label,
                field: value.field,
                value: value.value,
                occurrenceCount: value.occurrenceCount,
                evidenceBoundary: protocolDetailEvidenceBoundary(protocolKind: value.protocolKind)
            )
        }
        for (key, omittedCount) in omittedProtocolDetailOccurrences {
            guard let definition = protocolDetailDefinitions[key] else { continue }
            detailRows.append(ProtocolDetailObservation(
                protocolKind: definition.protocolKind,
                category: definition.category,
                label: definition.label,
                field: key.field,
                value: "Additional distinct values omitted after the per-field limit of \(protocolDetailMaximumDistinctValuesPerField)",
                occurrenceCount: omittedCount,
                evidenceBoundary: "The detail list is bounded to protect memory on large captures; aggregate protocol, endpoint, packet, and byte counts remain available."
            ))
        }
        detailRows.sort { left, right in
            if left.protocolKind != right.protocolKind { return left.protocolKind.rawValue < right.protocolKind.rawValue }
            if left.label != right.label { return left.label < right.label }
            if left.occurrenceCount != right.occurrenceCount { return left.occurrenceCount > right.occurrenceCount }
            return left.value < right.value
        }
        return NativeAnalysisResult(
            summary: AnalysisSummary(
                captureURL: captureURL,
                captureSHA256: hash,
                packetCount: packetCount,
                byteCount: byteCount,
                firstPacket: firstPacket,
                lastPacket: lastPacket,
                interfaces: interfaces.sorted()
            ),
            endpoints: endpointRows,
            hostnames: hostnameEvidence.values.sorted { $0.firstSeen == $1.firstSeen ? $0.hostname < $1.hostname : $0.firstSeen < $1.firstSeen },
            protocols: protocolRows,
            protocolDetails: detailRows,
            ports: portRows,
            coverage: coverage
        )
    }

    private mutating func addProtocolDetails(packet: DecodedPacket, observedProtocols: Set<ProtocolKind>) {
        for field in TSharkField.allCases {
            guard let definition = protocolDetailDefinition(field: field, observedProtocols: observedProtocols) else { continue }
            for value in packet.all(field) where !value.isEmpty {
                let key = "\(definition.protocolKind.rawValue)|\(field.rawValue)|\(value)"
                if var existing = protocolDetails[key] {
                    existing.occurrenceCount += 1
                    protocolDetails[key] = existing
                    continue
                }
                let fieldKey = ProtocolFieldKey(protocolKind: definition.protocolKind, field: field)
                protocolDetailDefinitions[fieldKey] = definition
                let distinctCount = protocolDetailDistinctCounts[fieldKey] ?? 0
                guard distinctCount < protocolDetailMaximumDistinctValuesPerField else {
                    omittedProtocolDetailOccurrences[fieldKey, default: 0] += 1
                    continue
                }
                protocolDetails[key] = ProtocolDetailAccumulator(
                    protocolKind: definition.protocolKind,
                    category: definition.category,
                    label: definition.label,
                    field: field,
                    value: value,
                    occurrenceCount: 1
                )
                protocolDetailDistinctCounts[fieldKey] = distinctCount + 1
            }
        }
    }

    private mutating func updateEndpoint(
        address: String,
        timestamp: Date,
        length: Int64,
        asSource: Bool,
        protocols observedProtocols: Set<ProtocolKind>,
        port: String?
    ) {
        var value = endpoints[address] ?? EndpointAccumulator(
            address: address,
            version: address.contains(":") ? "IPv6" : "IPv4",
            classification: classifyIPAddress(address),
            firstSeen: timestamp,
            lastSeen: timestamp,
            sourcePackets: 0,
            destinationPackets: 0,
            sourceBytes: 0,
            destinationBytes: 0,
            protocols: [],
            ports: []
        )
        value.firstSeen = min(value.firstSeen, timestamp)
        value.lastSeen = max(value.lastSeen, timestamp)
        if asSource {
            value.sourcePackets += 1
            value.sourceBytes += length
        } else {
            value.destinationPackets += 1
            value.destinationBytes += length
        }
        value.protocols.formUnion(observedProtocols)
        if let port { value.ports.insert(port) }
        endpoints[address] = value
    }

    private mutating func updatePort(transport: String, port: Int) {
        let key = "\(transport)/\(port)"
        var value = ports[key] ?? PortAccumulator(packetCount: 0)
        value.packetCount += 1
        ports[key] = value
    }

    private mutating func addHostnameEvidence(packet: DecodedPacket, timestamp: Date, destinationAddress: String?) {
        for name in packet.all(.dnsQueryName) {
            addHostname(
                name,
                address: nil,
                provenance: capturedDNSProvenance(name: name, isResponse: false, packet: packet),
                timestamp: timestamp
            )
        }
        let answerAddresses = packet.all(.dnsA) + packet.all(.dnsAAAA)
        let responseNames = packet.all(.dnsResponseName)
        for name in responseNames {
            let provenance = capturedDNSProvenance(name: name, isResponse: true, packet: packet)
            if answerAddresses.isEmpty {
                addHostname(name, address: nil, provenance: provenance, timestamp: timestamp)
            } else {
                for address in answerAddresses {
                    addHostname(name, address: address, provenance: provenance, timestamp: timestamp)
                }
            }
        }
        addHostnames(packet.all(.dnsPTR), address: nil, provenance: .capturedPTR, timestamp: timestamp)
        let sniProvenance: EvidenceProvenance = frameProtocolTokens(packet: packet).contains("quic") ? .quicHandshake : .tlsSNI
        addHostnames(packet.all(.tlsSNI), address: destinationAddress, provenance: sniProvenance, timestamp: timestamp)
        addHostnames(packet.all(.certificateDNSName), address: destinationAddress, provenance: .certificate, timestamp: timestamp)
        addHostnames(packet.all(.httpHost), address: destinationAddress, provenance: .httpHost, timestamp: timestamp)
        addHostnames(packet.all(.http2Authority), address: destinationAddress, provenance: .http2Authority, timestamp: timestamp)
        addHostnames(packet.all(.http3Authority), address: destinationAddress, provenance: .http3Authority, timestamp: timestamp)
        addResolvedHostnames(addresses: packet.all(.ipv4Source), hostnames: packet.all(.ipv4SourceHost), timestamp: timestamp)
        addResolvedHostnames(addresses: packet.all(.ipv4Destination), hostnames: packet.all(.ipv4DestinationHost), timestamp: timestamp)
        addResolvedHostnames(addresses: packet.all(.ipv6Source), hostnames: packet.all(.ipv6SourceHost), timestamp: timestamp)
        addResolvedHostnames(addresses: packet.all(.ipv6Destination), hostnames: packet.all(.ipv6DestinationHost), timestamp: timestamp)
    }

    private mutating func addResolvedHostnames(addresses: [String], hostnames: [String], timestamp: Date) {
        for pair in resolvedHostnamePairs(addresses: addresses, hostnames: hostnames) {
            addHostname(pair.hostname, address: pair.address, provenance: .activeReverseLookup, timestamp: timestamp)
        }
    }

    private mutating func addHostnames(_ names: [String], address: String?, provenance: EvidenceProvenance, timestamp: Date) {
        for name in names { addHostname(name, address: address, provenance: provenance, timestamp: timestamp) }
    }

    private mutating func addHostname(_ name: String, address: String?, provenance: EvidenceProvenance, timestamp: Date) {
        let normalized = name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !normalized.isEmpty else { return }
        let isPostCaptureEnrichment: Bool = provenance == .activeReverseLookup || provenance == .localResolver
        let confidence: ConfidenceLevel = provenance == .activeReverseLookup ? .low : .direct
        let key = "\(normalized)|\(address ?? "")|\(provenance.rawValue)"
        if let existing = hostnameEvidence[key] {
            hostnameEvidence[key] = HostnameEvidence(
                hostname: existing.hostname,
                address: existing.address,
                provenance: existing.provenance,
                firstSeen: min(existing.firstSeen, timestamp),
                lastSeen: max(existing.lastSeen, timestamp),
                confidence: existing.confidence,
                isPostCaptureEnrichment: existing.isPostCaptureEnrichment
            )
        } else {
            hostnameEvidence[key] = HostnameEvidence(
                hostname: normalized,
                address: address,
                provenance: provenance,
                firstSeen: timestamp,
                lastSeen: timestamp,
                confidence: confidence,
                isPostCaptureEnrichment: isPostCaptureEnrichment
            )
        }
    }
}

func capturedDNSProvenance(name: String, isResponse: Bool, packet: DecodedPacket) -> EvidenceProvenance {
    if isDNSSDName(name) { return .capturedDNSSD }
    if frameProtocolTokens(packet: packet).contains("mdns") { return .capturedMDNS }
    return isResponse ? .capturedDNSAnswer : .capturedDNSQuery
}

func isDNSSDName(_ value: String) -> Bool {
    let labels = value
        .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        .lowercased()
        .split(separator: ".")
        .map(String.init)
    guard labels.first?.hasPrefix("_") == true else { return false }
    return labels.contains("_tcp") || labels.contains("_udp")
}

func resolvedHostnamePairs(addresses: [String], hostnames: [String]) -> [(address: String, hostname: String)] {
    guard addresses.count == hostnames.count else { return [] }
    return zip(addresses, hostnames).compactMap { address, hostname in
        let normalizedHostname: String = hostname.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !normalizedHostname.isEmpty,
              normalizedHostname.caseInsensitiveCompare(address) != .orderedSame,
              !isIPAddress(normalizedHostname) else {
            return nil
        }
        return (address: address, hostname: normalizedHostname)
    }
}

func isIPAddress(_ value: String) -> Bool {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, value, &ipv4) == 1 { return true }
    var ipv6 = in6_addr()
    return inet_pton(AF_INET6, value, &ipv6) == 1
}

func decodePacketRow(row: String, fields: [TSharkField]) throws -> DecodedPacket {
    let columns = try parseQuotedTSV(row)
    guard columns.count == fields.count else {
        throw NativeAnalysisError.malformedRow("received \(columns.count) columns for \(fields.count) requested fields")
    }
    let occurrenceSeparator: Character = "\u{1e}"
    var values: [TSharkField: [String]] = [:]
    for (index, field) in fields.enumerated() {
        let occurrences = columns[index]
            .split(separator: occurrenceSeparator, omittingEmptySubsequences: true)
            .map(String.init)
            .filter { !$0.isEmpty }
        if !occurrences.isEmpty { values[field] = occurrences }
    }
    return DecodedPacket(values: values)
}

func parseQuotedTSV(_ row: String) throws -> [String] {
    var fields: [String] = []
    var current = ""
    var insideQuotes = false
    var index = row.startIndex
    while index < row.endIndex {
        let character = row[index]
        if character == "\"" {
            let next = row.index(after: index)
            if insideQuotes, next < row.endIndex, row[next] == "\"" {
                current.append("\"")
                index = row.index(after: next)
                continue
            }
            insideQuotes.toggle()
        } else if character == "\t", !insideQuotes {
            fields.append(current)
            current = ""
        } else {
            current.append(character)
        }
        index = row.index(after: index)
    }
    guard !insideQuotes else {
        throw NativeAnalysisError.malformedRow("unterminated quoted field")
    }
    fields.append(current)
    return fields
}

func protocolKinds(packet: DecodedPacket) -> Set<ProtocolKind> {
    let tokens = frameProtocolTokens(packet: packet)
    var result = Set(tokens.compactMap(protocolKind(token:)))
    if !packet.all(.tlsSNI).isEmpty { result.insert(.tls) }
    if !packet.all(.http2Authority).isEmpty { result.insert(.http2) }
    if !packet.all(.http3Authority).isEmpty { result.insert(.http3) }
    if !packet.all(.quicVersion).isEmpty { result.insert(.quic) }
    if packet.all(.dnsQueryName).contains(where: { $0.hasPrefix("_") }) { result.insert(.dnsSD) }
    if packet.all(.tlsSNI).contains(where: { $0.lowercased().contains("push.apple.com") }) { result.insert(.applePush) }
    if let interfaceName = packet.first(.frameInterfaceName), interfaceName.hasPrefix("utun") { result.insert(.vpn) }
    let transportOnly: Set<ProtocolKind> = [.ethernet, .ipv4, .ipv6, .icmp, .icmpv6, .tcp, .udp]
    if result.isEmpty || result.isSubset(of: transportOnly) { result.insert(.unknown) }
    return result
}

func frameProtocolTokens(packet: DecodedPacket) -> Set<String> {
    Set((packet.first(.frameProtocols) ?? "").lowercased().split(separator: ":").map(String.init))
}

func protocolKind(token: String) -> ProtocolKind? {
    switch token {
    case "eth", "ethertype": .ethernet
    case "arp": .arp
    case "ip": .ipv4
    case "ipv6": .ipv6
    case "icmp": .icmp
    case "icmpv6": .icmpv6
    case "tcp": .tcp
    case "udp": .udp
    case "dns": .dns
    case "mdns": .mdns
    case "dhcp", "bootp": .dhcp
    case "dhcpv6": .dhcpv6
    case "tls": .tls
    case "http": .http
    case "http2": .http2
    case "http3": .http3
    case "quic": .quic
    case "stun": .stun
    case "turnchannel", "turn": .turn
    case "webrtc": .webRTC
    case "dtls": .dtls
    case "rtp": .rtp
    case "rtcp": .rtcp
    case "ssh": .ssh
    case "smb", "smb2": .smb
    case "ntp": .ntp
    case "ssdp": .ssdp
    case "upnp": .upnp
    case "xml": nil
    case "llmnr": .llmnr
    case "esp", "isakmp": .esp
    case "wg", "wireguard": .wireGuard
    case "websocket": .websocket
    case "sctp": .sctp
    case "gre": .gre
    case "ipip": .ipInIP
    case "mqtt": .mqtt
    case "coap": .coap
    case "ocsp": .ocsp
    case "kerberos": .kerberos
    case "ldap": .ldap
    case "ftp", "ftp-data": .ftp
    case "tftp": .tftp
    case "sip": .sip
    default: nil
    }
}

func protocolEvidence(packet: DecodedPacket, protocolKind: ProtocolKind) -> Set<String> {
    switch protocolKind {
    case .tls:
        return Set(packet.all(.tlsVersion).map { "captured TLS version \($0)" } + packet.all(.tlsSNI).map { _ in "captured ClientHello SNI" })
    case .dns:
        return Set(packet.all(.dnsQueryName).map { _ in "captured DNS query" } + packet.all(.dnsResponseName).map { _ in "captured DNS response" })
    case .quic:
        return Set(packet.all(.quicVersion).map { "captured QUIC version \($0)" })
    case .dnsSD:
        return ["captured DNS service name beginning with underscore"]
    case .applePush:
        return ["captured TLS SNI matching an Apple Push hostname"]
    case .vpn:
        return ["capture metadata reported a utun interface"]
    case .unknown:
        return ["no supported application protocol was identified; addresses, ports, sizes, timing, and volume remain available"]
    default:
        return ["TShark frame protocol stack"]
    }
}

func transportPort(packet: DecodedPacket, source: Bool) -> Int? {
    let value = source
        ? packet.first(.tcpSourcePort) ?? packet.first(.udpSourcePort)
        : packet.first(.tcpDestinationPort) ?? packet.first(.udpDestinationPort)
    return value.flatMap(Int.init)
}

func classifyIPAddress(_ value: String) -> String {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, value, &ipv4) == 1 {
        let host = UInt32(bigEndian: ipv4.s_addr)
        if host & 0xff00_0000 == 0x7f00_0000 { return "Loopback" }
        if host & 0xff00_0000 == 0x0a00_0000
            || host & 0xfff0_0000 == 0xac10_0000
            || host & 0xffff_0000 == 0xc0a8_0000 { return "Private" }
        if host & 0xffc0_0000 == 0x6440_0000 { return "Carrier-grade NAT" }
        if host & 0xffff_0000 == 0xa9fe_0000 { return "Link-local" }
        if host & 0xf000_0000 == 0xe000_0000 { return "Multicast" }
        if value == "255.255.255.255" { return "Broadcast" }
        if host & 0xffff_ff00 == 0xc000_0200
            || host & 0xffff_ff00 == 0xc633_6400
            || host & 0xffff_ff00 == 0xcb00_7100 { return "Documentation" }
        return "Public"
    }
    let lower = value.lowercased()
    if lower == "::1" { return "Loopback" }
    if lower.hasPrefix("fe80:") { return "Link-local" }
    if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return "Unique local" }
    if lower.hasPrefix("ff") { return "Multicast" }
    if lower.hasPrefix("2001:db8:") { return "Documentation" }
    return "Public or unclassified"
}

func describePort(transport: String, port: Int) -> (service: String, explanation: String) {
    let key = "\(transport.uppercased())/\(port)"
    let known: [String: (String, String)] = [
        "TCP/22": ("SSH", "Secure remote shell and file transfer."),
        "UDP/53": ("DNS", "Domain-name queries and responses."),
        "TCP/53": ("DNS", "DNS over TCP, often for large replies or zone operations."),
        "UDP/67": ("DHCP server", "IPv4 address and network configuration service."),
        "UDP/68": ("DHCP client", "IPv4 address and network configuration client."),
        "TCP/80": ("HTTP", "Unencrypted web traffic when the payload confirms HTTP."),
        "UDP/123": ("NTP", "Network clock synchronization."),
        "UDP/443": ("HTTPS/QUIC", "Often QUIC or HTTP/3, but the port alone is not proof."),
        "TCP/443": ("HTTPS", "Often TLS-protected web traffic, but the port alone is not proof."),
        "UDP/500": ("IKE", "IPsec key exchange."),
        "UDP/1900": ("SSDP", "UPnP device and service discovery."),
        "UDP/3478": ("STUN/TURN", "NAT traversal and relay negotiation."),
        "UDP/4500": ("IPsec NAT-T", "IPsec encapsulated for NAT traversal."),
        "UDP/5353": ("mDNS", "Multicast DNS and Bonjour local discovery."),
        "UDP/5355": ("LLMNR", "Link-local multicast name resolution."),
        "TCP/5223": ("Apple Push", "Common Apple Push Notification service transport."),
        "TCP/445": ("SMB", "Network file sharing when the payload confirms SMB.")
    ]
    return known[key] ?? ("Unassigned or application-specific", "No reliable standard-service explanation is available for this transport and port combination.")
}

private func minDate(_ current: Date?, _ candidate: Date) -> Date {
    guard let current else { return candidate }
    return min(current, candidate)
}

private func maxDate(_ current: Date?, _ candidate: Date) -> Date {
    guard let current else { return candidate }
    return max(current, candidate)
}
