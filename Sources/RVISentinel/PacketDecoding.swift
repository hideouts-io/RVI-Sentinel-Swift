import Darwin
import Foundation

/// Parses decimal epochs without converting the source timestamp to floating point.
func decodePacketTimestamp(_ text: String) throws -> PacketTimestamp {
    let pieces = text.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...2).contains(pieces.count) else { throw PacketDomainError.invalidTimestamp }
    let negative = pieces[0].hasPrefix("-")
    let digits = negative ? pieces[0].dropFirst() : pieces[0][...]
    guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }),
          let seconds = Int64(pieces[0]) else { throw PacketDomainError.invalidTimestamp }
    let fraction = pieces.count == 2 ? String(pieces[1]) : "0"
    guard !fraction.isEmpty, fraction.utf8.count <= 9, fraction.utf8.allSatisfy({ (48...57).contains($0) }),
          let nanoseconds = UInt32(fraction.padding(toLength: 9, withPad: "0", startingAt: 0)) else {
        throw PacketDomainError.invalidTimestamp
    }
    if negative && nanoseconds > 0 {
        let (floorSeconds, overflow) = seconds.subtractingReportingOverflow(1)
        guard !overflow else { throw PacketDomainError.invalidTimestamp }
        return PacketTimestamp(epochSeconds: floorSeconds, nanoseconds: 1_000_000_000 - nanoseconds, originalText: text)
    }
    return PacketTimestamp(epochSeconds: seconds, nanoseconds: nanoseconds, originalText: text)
}

/// Compact per-frame decoding retains no payload or full decoder field dictionary.
func decodePacketRecord(packet: DecodedPacket, artifact: PacketCaptureArtifact) throws -> PacketRecord {
    let frame = try requiredDecimal(packet: packet, field: .frameNumber, maximum: UInt64.max)
    guard frame > 0 else { throw invalidPacketField(.frameNumber, "frame numbering starts at 1") }
    let timestamp = try decodePacketTimestamp(requiredText(packet: packet, field: .frameTimeEpoch, maximumBytes: 40))
    let length = try requiredDecimal(packet: packet, field: .frameLength, maximum: UInt64(UInt32.max))
    let capturedLength = try optionalDecimal(packet: packet, field: .frameCapturedLength, maximum: UInt64(UInt32.max))
    guard capturedLength.map({ $0 <= length }) ?? true else {
        throw invalidPacketField(.frameCapturedLength, "captured length exceeds the wire length")
    }
    let stackText = try requiredText(packet: packet, field: .frameProtocols, maximumBytes: 1_024)
    let stack = stackText.lowercased().split(separator: ":", omittingEmptySubsequences: false).map(String.init)
    guard stack.count <= 64, stack.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 || $0 == 45 || $0 == 46 }) }) else {
        throw invalidPacketField(.frameProtocols, "protocol stack contains unsupported token syntax or too many layers")
    }
    let ipv4Sources = try decodeAddresses(packet: packet, field: .ipv4Source, family: .ipv4)
    let ipv4Destinations = try decodeAddresses(packet: packet, field: .ipv4Destination, family: .ipv4)
    let ipv6Sources = try decodeAddresses(packet: packet, field: .ipv6Source, family: .ipv6)
    let ipv6Destinations = try decodeAddresses(packet: packet, field: .ipv6Destination, family: .ipv6)
    let tcpSources = try decimalValues(packet: packet, field: .tcpSourcePort, maximum: UInt64(UInt16.max))
    let tcpDestinations = try decimalValues(packet: packet, field: .tcpDestinationPort, maximum: UInt64(UInt16.max))
    let udpSources = try decimalValues(packet: packet, field: .udpSourcePort, maximum: UInt64(UInt16.max))
    let udpDestinations = try decimalValues(packet: packet, field: .udpDestinationPort, maximum: UInt64(UInt16.max))
    let tcpStreams = try decimalValues(packet: packet, field: .tcpStream, maximum: UInt64(UInt32.max))
    let udpStreams = try decimalValues(packet: packet, field: .udpStream, maximum: UInt64(UInt32.max))
    let hasIPv4 = !ipv4Sources.isEmpty || !ipv4Destinations.isEmpty || stack.contains("ip")
    let hasIPv6 = !ipv6Sources.isEmpty || !ipv6Destinations.isEmpty || stack.contains("ipv6")
    let hasTCP = !tcpSources.isEmpty || !tcpDestinations.isEmpty || !tcpStreams.isEmpty || stack.contains("tcp")
    let hasUDP = !udpSources.isEmpty || !udpDestinations.isEmpty || !udpStreams.isEmpty || stack.contains("udp")
    let networkAmbiguous = [ipv4Sources.count, ipv4Destinations.count, ipv6Sources.count, ipv6Destinations.count].contains(where: { $0 > 1 }) || (hasIPv4 && hasIPv6) || stack.filter({ $0 == "ip" || $0 == "ipv6" }).count > 1
    let transportCounts = [tcpSources.count, tcpDestinations.count, udpSources.count, udpDestinations.count, tcpStreams.count, udpStreams.count,
        packet.all(.tcpFlags).count, packet.all(.tcpSequenceRaw).count, packet.all(.tcpAcknowledgmentRaw).count, packet.all(.tcpPayloadLength).count]
    let transportAmbiguous = transportCounts.contains(where: { $0 > 1 }) || (hasTCP && hasUDP) || stack.filter({ $0 == "tcp" || $0 == "udp" }).count > 1
    let sourceAddress = networkAmbiguous ? nil : (ipv4Sources.first ?? ipv6Sources.first)
    let destinationAddress = networkAmbiguous ? nil : (ipv4Destinations.first ?? ipv6Destinations.first)
    let transport: PacketTransport? = transportAmbiguous ? nil : (hasTCP ? .tcp : (hasUDP ? .udp : nil))
    let sourcePortValue = transport == .tcp ? tcpSources.first : (transport == .udp ? udpSources.first : nil)
    let destinationPortValue = transport == .tcp ? tcpDestinations.first : (transport == .udp ? udpDestinations.first : nil)
    let stream = transport == .tcp ? tcpStreams.first : (transport == .udp ? udpStreams.first : nil)
    let tcp = try decodeTCPMetadata(packet: packet, transport: transport)
    let process = try decodeProcessMetadata(packet: packet, fields: [(.applePCAPNG, .darwinProcessID, .darwinProcessName), (.pktapHeader, .pktapProcessID, .pktapProcessName)])
    let effectiveProcess = try decodeProcessMetadata(packet: packet, fields: [(.applePCAPNG, .darwinEffectiveProcessID, .darwinEffectiveProcessName), (.pktapHeader, .pktapEffectiveProcessID, .pktapEffectiveProcessName)])
    let interface = try decodeInterfaceMetadata(packet: packet)
    let direction = try decodeDirectionMetadata(packet: packet)
    var diagnostics: [PacketDiagnostic] = []
    if networkAmbiguous { diagnostics.append(.ambiguousNetworkLayers) }
    if transportAmbiguous { diagnostics.append(.ambiguousTransportLayers) }
    if !networkAmbiguous && (hasIPv4 || hasIPv6) && (sourceAddress == nil || destinationAddress == nil) { diagnostics.append(.incompleteNetworkHeader) }
    if !transportAmbiguous && transport != nil && (sourcePortValue == nil || destinationPortValue == nil) { diagnostics.append(.incompleteTransportHeader) }
    if transport != nil && stream == nil { diagnostics.append(.missingStream) }
    if process.state == .conflict { diagnostics.append(.processMetadataConflict) }
    if effectiveProcess.state == .conflict { diagnostics.append(.effectiveProcessMetadataConflict) }
    if interface.state == .conflict { diagnostics.append(.interfaceMetadataConflict) }
    if direction.state == .conflict { diagnostics.append(.directionMetadataConflict) }
    return PacketRecord(
        id: PacketRecordID(artifactID: artifact.id, frameNumber: frame), timestamp: timestamp,
        wireLength: UInt32(length), capturedLength: capturedLength.map(UInt32.init),
        protocolStack: stack, protocols: protocolKinds(packet: packet).sorted { $0.rawValue < $1.rawValue },
        sourceAddress: sourceAddress, destinationAddress: destinationAddress,
        sourcePort: sourcePortValue.map(UInt16.init), destinationPort: destinationPortValue.map(UInt16.init),
        transport: transport, stream: stream, tcp: tcp, process: process, effectiveProcess: effectiveProcess,
        interface: interface, direction: direction, recordedNames: try decodeRecordedNames(packet: packet), diagnostics: diagnostics
    )
}

private func invalidPacketField(_ field: TSharkField, _ detail: String) -> PacketDomainError {
    .invalidField(field: field, detail: detail)
}

private func boundedValues(packet: DecodedPacket, field: TSharkField, maximumBytes: Int) throws -> [String] {
    let values = packet.all(field)
    guard values.count <= 128 else { throw invalidPacketField(field, "more than 128 occurrences") }
    guard values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= maximumBytes && !$0.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) }) else {
        throw invalidPacketField(field, "empty, oversized, or control-character value")
    }
    return values
}

private func requiredText(packet: DecodedPacket, field: TSharkField, maximumBytes: Int) throws -> String {
    let values = try boundedValues(packet: packet, field: field, maximumBytes: maximumBytes)
    guard values.count == 1, let text = values.first else { throw invalidPacketField(field, "exactly one value is required") }
    return text
}

private func decimalValue(_ text: String, field: TSharkField, maximum: UInt64) throws -> UInt64 {
    guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }), let number = UInt64(text), number <= maximum else {
        throw invalidPacketField(field, "expected an unsigned decimal integer within its field range")
    }
    return number
}

private func decimalValues(packet: DecodedPacket, field: TSharkField, maximum: UInt64) throws -> [UInt64] {
    try boundedValues(packet: packet, field: field, maximumBytes: 20).map { try decimalValue($0, field: field, maximum: maximum) }
}

private func requiredDecimal(packet: DecodedPacket, field: TSharkField, maximum: UInt64) throws -> UInt64 {
    try decimalValue(requiredText(packet: packet, field: field, maximumBytes: 20), field: field, maximum: maximum)
}

private func optionalDecimal(packet: DecodedPacket, field: TSharkField, maximum: UInt64) throws -> UInt64? {
    let values = try decimalValues(packet: packet, field: field, maximum: maximum)
    guard values.count <= 1 else { throw invalidPacketField(field, "multiple values cannot identify one field") }
    return values.first
}

private func flagValue(_ text: String, field: TSharkField, maximum: UInt64) throws -> UInt64 {
    if text.hasPrefix("0x") {
        let digits = text.dropFirst(2)
        guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
              let value = UInt64(digits, radix: 16), value <= maximum else { throw invalidPacketField(field, "invalid hexadecimal flags") }
        return value
    }
    return try decimalValue(text, field: field, maximum: maximum)
}

private func decodeAddresses(packet: DecodedPacket, field: TSharkField, family: PacketIPFamily) throws -> [PacketIPAddress] {
    try boundedValues(packet: packet, field: field, maximumBytes: 45).map { text in
        let address = try packetIPAddress(text)
        guard address.family == family else { throw invalidPacketField(field, "address family does not match the field") }
        return address
    }
}

func packetIPAddress(_ text: String) throws -> PacketIPAddress {
    let family: PacketIPFamily = text.contains(":") ? .ipv6 : .ipv4
    let field: TSharkField = family == .ipv6 ? .ipv6Source : .ipv4Source
    guard !text.isEmpty, text.utf8.count <= 45, !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw invalidPacketField(field, "IP address is empty, oversized, or contains control characters")
    }
    var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    switch family {
    case .ipv4:
        var address = in_addr()
        guard inet_pton(AF_INET, text, &address) == 1, inet_ntop(AF_INET, &address, &output, socklen_t(output.count)) != nil else {
            throw invalidPacketField(field, "invalid IPv4 address")
        }
    case .ipv6:
        var address = in6_addr()
        guard inet_pton(AF_INET6, text, &address) == 1, inet_ntop(AF_INET6, &address, &output, socklen_t(output.count)) != nil else {
            throw invalidPacketField(field, "invalid IPv6 address")
        }
    }
    let bytes = output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return PacketIPAddress(rawValue: String(decoding: bytes, as: UTF8.self), family: family)
}

private func decodeTCPMetadata(packet: DecodedPacket, transport: PacketTransport?) throws -> PacketTCPMetadata? {
    let flags = try boundedValues(packet: packet, field: .tcpFlags, maximumBytes: 10).map { try flagValue($0, field: .tcpFlags, maximum: UInt64(UInt16.max)) }
    let sequences = try decimalValues(packet: packet, field: .tcpSequenceRaw, maximum: UInt64(UInt32.max))
    let acknowledgments = try decimalValues(packet: packet, field: .tcpAcknowledgmentRaw, maximum: UInt64(UInt32.max))
    let lengths = try decimalValues(packet: packet, field: .tcpPayloadLength, maximum: UInt64(UInt32.max))
    guard transport == .tcp, [flags.count, sequences.count, acknowledgments.count, lengths.count].allSatisfy({ $0 <= 1 }) else { return nil }
    return PacketTCPMetadata(flags: flags.first.map(UInt16.init), sequenceRaw: sequences.first.map(UInt32.init), acknowledgmentRaw: acknowledgments.first.map(UInt32.init), payloadLength: lengths.first.map(UInt32.init))
}

private func decodeProcessMetadata(packet: DecodedPacket, fields: [(PacketMetadataSource, TSharkField, TSharkField)]) throws -> PacketProcessMetadata {
    var labels: [PacketProcessLabel] = []
    var repeated = false
    for (source, pidField, nameField) in fields {
        let ids = try decimalValues(packet: packet, field: pidField, maximum: UInt64(Int32.max))
        let names = try boundedValues(packet: packet, field: nameField, maximumBytes: 256)
        if ids.count > 1 || names.count > 1 {
            repeated = true
            labels.append(contentsOf: ids.map { PacketProcessLabel(source: source, processID: $0 == 0 ? nil : Int32($0), name: nil) })
            labels.append(contentsOf: names.map { PacketProcessLabel(source: source, processID: nil, name: $0) })
        } else if !ids.isEmpty || !names.isEmpty {
            labels.append(PacketProcessLabel(source: source, processID: ids.first.flatMap { $0 == 0 ? nil : Int32($0) }, name: names.first))
        }
    }
    let observedIDs = Set(labels.compactMap(\.processID))
    let observedNames = Set(labels.compactMap(\.name))
    let hasValue = !observedIDs.isEmpty || !observedNames.isEmpty
    let state: PacketMetadataState = repeated || observedIDs.count > 1 || observedNames.count > 1 ? .conflict : (hasValue ? .recorded : .unknown)
    return PacketProcessMetadata(state: state, labels: labels)
}

private func decodeInterfaceMetadata(packet: DecodedPacket) throws -> PacketInterfaceMetadata {
    let frameNames = try boundedValues(packet: packet, field: .frameInterfaceName, maximumBytes: 256)
    let pktapNames = try boundedValues(packet: packet, field: .pktapInterfaceName, maximumBytes: 256)
    let labels = frameNames.map { PacketInterfaceLabel(source: .captureFrame, name: $0) } + pktapNames.map { PacketInterfaceLabel(source: .pktapHeader, name: $0) }
    let conflict = frameNames.count > 1 || pktapNames.count > 1 || Set(labels.map(\.name)).count > 1
    return PacketInterfaceMetadata(state: conflict ? .conflict : (labels.isEmpty ? .unknown : .recorded), labels: labels)
}

private func decodeDirectionMetadata(packet: DecodedPacket) throws -> PacketDirectionMetadata {
    let frameDirections = try boundedValues(packet: packet, field: .framePacketDirection, maximumBytes: 10).map { text -> PacketDirectionLabel in
        let value = try flagValue(text, field: .framePacketDirection, maximum: 3)
        return PacketDirectionLabel(source: .pcapngPacketOptions, direction: value == 1 ? .inbound : (value == 2 ? .outbound : .unknown))
    }
    let pktapDirections = try boundedValues(packet: packet, field: .pktapFlags, maximumBytes: 10).map { text -> PacketDirectionLabel in
        let value = try flagValue(text, field: .pktapFlags, maximum: UInt64(UInt32.max)) & 3
        return PacketDirectionLabel(source: .pktapHeader, direction: value == 1 ? .inbound : (value == 2 ? .outbound : .unknown))
    }
    let labels = frameDirections + pktapDirections
    let known = Set(labels.map(\.direction).filter { $0 != .unknown })
    let conflict = frameDirections.count > 1 || pktapDirections.count > 1 || known.count > 1
    let ordered = labels.filter { $0.direction != .unknown } + labels.filter { $0.direction == .unknown }
    return PacketDirectionMetadata(state: conflict ? .conflict : (known.isEmpty ? .unknown : .recorded), labels: ordered)
}

private func decodeRecordedNames(packet: DecodedPacket) throws -> [RecordedPacketName] {
    let fields: [TSharkField] = [.dnsQueryName, .dnsResponseName, .dnsCNAME, .dnsPTR, .tlsSNI, .httpHost, .http2Authority, .http3Authority, .certificateDNSName]
    return try fields.flatMap { field in
        try boundedValues(packet: packet, field: field, maximumBytes: 512).map { RecordedPacketName(field: field, value: $0) }
    }
}
