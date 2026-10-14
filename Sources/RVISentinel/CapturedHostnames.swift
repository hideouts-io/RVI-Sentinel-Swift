import Foundation

struct CapturedHostnameAssociation: Codable, Hashable, Sendable {
    let name: String
    let address: String?
    let supportingPackets: [PacketRecordID]
    let validUntil: PacketTimestamp?
    let canonicalNameChain: [String]
    let provenance: EvidenceProvenance
    let isInferred: Bool
    let detail: String
}

private struct CapturedStreamNameKey: Hashable {
    let field: TSharkField
    let value: String
}

private struct CapturedStreamName {
    let name: RecordedPacketName
    let packet: PacketRecord
    let provenance: EvidenceProvenance
}

/// Direct names stay on their source frame. Only earlier SNI/Host/authority values propagate
/// within an exact capture, stream, metadata context, and direction-independent endpoint pair.
/// Without a retained request role, propagation names a conversation, never one endpoint.
func resolveCapturedHostnames(
    messages: [CapturedDNSMessage],
    packets: [PacketRecord],
    maximumAssociations: Int
) throws -> [PacketRecordID: [CapturedHostnameAssociation]] {
    try Task.checkCancellation()
    var result = try resolveCapturedDNSNames(messages: messages, packets: packets, maximumAssociations: maximumAssociations)
    guard !messages.isEmpty || packets.contains(where: { !$0.recordedNames.isEmpty }) else { return result }
    let messagesByID = Dictionary(grouping: messages, by: \.packetID)
    var previousNames: [PacketSessionKey: [CapturedStreamNameKey: CapturedStreamName]] = [:]
    var count = result.values.reduce(0) { $0 + $1.count }
    let ordered = packets.sorted {
        if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
        return $0.id.frameNumber < $1.id.frameNumber
    }
    for (index, packet) in ordered.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        var evidence = Set(result[packet.id] ?? [])
        let key = packetSessionKey(record: packet, source: .unknown)
        if let key {
            for prior in (previousNames[key] ?? [:]).values {
                evidence.insert(CapturedHostnameAssociation(
                    name: prior.name.value, address: nil, supportingPackets: [prior.packet.id], validUntil: nil,
                    canonicalNameChain: [], provenance: prior.provenance, isInferred: true,
                    detail: "Earlier \(prior.name.field.rawValue) in frame \(prior.packet.id.frameNumber) at epoch \(prior.packet.timestamp.originalText), within the same capture, transport stream, interface, process metadata, and endpoint pair. This inferred conversation context does not establish the selected packet's hostname or one endpoint's identity; connection reuse and multiplexing can retain several names."
                ))
            }
        }
        for name in packet.recordedNames {
            guard let provenance = capturedNameProvenance(name: name, packet: packet) else { continue }
            evidence.insert(CapturedHostnameAssociation(
                name: name.value, address: nil, supportingPackets: [packet.id], validUntil: nil, canonicalNameChain: [],
                provenance: provenance, isInferred: false,
                detail: "Directly decoded \(name.field.rawValue) in frame \(packet.id.frameNumber) at epoch \(packet.timestamp.originalText). This records a name in this frame; it does not independently verify a peer identity or assign the name to an address."
            ))
            if let key, [.tlsSNI, .httpHost, .http2Authority, .http3Authority].contains(name.field) {
                previousNames[key, default: [:]][CapturedStreamNameKey(field: name.field, value: name.value)] = CapturedStreamName(name: name, packet: packet, provenance: provenance)
            }
        }
        for message in messagesByID[packet.id] ?? [] {
            for question in message.questions {
                evidence.insert(CapturedHostnameAssociation(
                    name: question.name, address: nil, supportingPackets: [packet.id], validUntil: nil,
                    canonicalNameChain: [], provenance: packet.protocolStack.contains("mdns") ? .capturedMDNS : .capturedDNSQuery, isInferred: false,
                    detail: "Captured DNS question for type \(question.recordType), class \(question.recordClass), in frame \(packet.id.frameNumber) at epoch \(packet.timestamp.originalText), protocol stack \(packet.protocolStack.joined(separator: ":")). A question alone does not associate a later endpoint with this name."
                ))
            }
            for record in message.answers {
                let observed = directDNSRecordEvidence(record: record, packet: packet)
                evidence.formUnion(observed)
            }
        }
        let priorCount = result[packet.id]?.count ?? 0
        count += evidence.count - priorCount
        guard count <= maximumAssociations else { throw CapturedDNSError.resourceLimit("more than \(maximumAssociations) captured name records and associations") }
        if !evidence.isEmpty {
            result[packet.id] = evidence.sorted {
                ($0.name, $0.provenance.rawValue, $0.isInferred ? 1 : 0, $0.detail) < ($1.name, $1.provenance.rawValue, $1.isInferred ? 1 : 0, $1.detail)
            }
        }
    }
    return result
}

private func capturedNameProvenance(name: RecordedPacketName, packet: PacketRecord) -> EvidenceProvenance? {
    switch name.field {
    case .tlsSNI: packet.protocolStack.contains("quic") ? .quicHandshake : .tlsSNI
    case .httpHost: .httpHost
    case .http2Authority: .http2Authority
    case .http3Authority: .http3Authority
    case .certificateDNSName: .certificate
    case .dnsQueryName: packet.protocolStack.contains("mdns") ? .capturedMDNS : .capturedDNSQuery
    case .dnsResponseName, .dnsCNAME: packet.protocolStack.contains("mdns") ? .capturedMDNS : .capturedDNSAnswer
    case .dnsPTR: .capturedPTR
    default: nil
    }
}

private func directDNSRecordEvidence(record: CapturedDNSResourceRecord, packet: PacketRecord) -> [CapturedHostnameAssociation] {
    let names: [String]
    let address: String?
    let rendered: String
    let provenance: EvidenceProvenance
    switch record.value {
    case let .ipv4(value), let .ipv6(value):
        names = record.owner.map { [$0] } ?? []
        address = value; rendered = value; provenance = packet.protocolStack.contains("mdns") ? .capturedMDNS : .capturedDNSAnswer
    case let .canonicalName(value):
        names = [record.owner, value].compactMap { $0 }
        address = nil; rendered = value; provenance = packet.protocolStack.contains("mdns") ? .capturedMDNS : .capturedDNSAnswer
    case let .pointerName(value):
        names = [record.owner, value].compactMap { $0 }
        address = nil; rendered = value; provenance = .capturedPTR
    case let .service(target, port, priority, weight):
        names = [record.owner, target].compactMap { $0 }
        address = nil; rendered = "target \(target), port \(port), priority \(priority), weight \(weight)"; provenance = .capturedDNSSD
    }
    return names.map { name in
        CapturedHostnameAssociation(
            name: name, address: address, supportingPackets: [packet.id], validUntil: nil, canonicalNameChain: [],
            provenance: provenance, isInferred: false,
            detail: "Observed DNS RR type \(record.recordType), class \(record.recordClass), owner \(record.owner ?? "not emitted by decoder"), value \(rendered), TTL \(record.ttlSeconds) seconds, in frame \(packet.id.frameNumber) at epoch \(packet.timestamp.originalText), protocol stack \(packet.protocolStack.joined(separator: ":")). This is the recorded resource record, not an attribution of the selected frame's endpoints."
        )
    }
}

private struct DNSClientScope: Hashable {
    let artifactID: PacketArtifactID
    let client: PacketIPAddress
    let interface: PacketInterfaceMetadata
}

private struct DNSTimedRecord {
    let record: CapturedDNSResourceRecord
    let packet: PacketRecord
    let scope: DNSClientScope
    let supportingPackets: [PacketRecordID]
    let validityEnd: DNSPosition
}

/// Frame order disambiguates observations that share the same exact timestamp.
private struct DNSPosition: Hashable, Comparable {
    let timestamp: PacketTimestamp
    let frameNumber: UInt64

    static func < (left: Self, right: Self) -> Bool {
        if left.timestamp != right.timestamp { return left.timestamp < right.timestamp }
        return left.frameNumber < right.frameNumber
    }
}

private struct DNSAddressBinding {
    let scope: DNSClientScope
    let name: String
    let address: String
    let start: DNSPosition
    let end: DNSPosition
    let chain: [String]
    let dependencies: [DNSTimedRecord]
}

private struct DNSBindingIdentity: Hashable {
    let scope: DNSClientScope
    let name: String
    let address: String
    let start: DNSPosition
    let end: DNSPosition
    let chain: [String]
    let supportingPackets: [PacketRecordID]
}

private struct DNSBindingCursor {
    var nextIndex: Int
    var active: [Int: DNSAddressBinding]
}

private struct DNSAddressKey: Hashable {
    let scope: DNSClientScope
    let address: String
}

private struct DNSOwnerKey: Hashable {
    let scope: DNSClientScope
    let owner: String
}

private struct DNSOwnerTypeKey: Hashable {
    let owner: DNSOwnerKey
    let recordType: UInt16
}

/// Passive address links require a unicast DNS receiver, exact RR ownership, and live TTL intervals.
/// PTR, service records, and query-only packets remain observations without endpoint associations.
func resolveCapturedDNSNames(
    messages: [CapturedDNSMessage],
    packets: [PacketRecord],
    maximumAssociations: Int
) throws -> [PacketRecordID: [CapturedHostnameAssociation]] {
    guard maximumAssociations > 0 else { throw CapturedDNSError.resourceLimit("association limit must be positive") }
    guard !messages.isEmpty else { return [:] }
    var packetsByID: [PacketRecordID: PacketRecord] = [:]
    for (index, packet) in packets.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard packetsByID.updateValue(packet, forKey: packet.id) == nil else {
            throw CapturedDNSError.malformed(frame: packet.id.frameNumber, reason: "duplicate packet identity")
        }
    }
    let messagesByID = Dictionary(grouping: messages, by: \.packetID)
    var timed: [DNSTimedRecord] = []
    var eventsByType: [DNSOwnerTypeKey: [DNSPosition]] = [:]
    var negativeNameEvents: [DNSOwnerKey: [DNSPosition]] = [:]
    for (index, message) in messages.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard let packet = packetsByID[message.packetID] else {
            throw CapturedDNSError.malformed(frame: message.packetID.frameNumber, reason: "DNS record has no matching retained packet")
        }
        guard message.isResponse, !message.isTruncated, packet.sourcePort == 53,
              let client = packet.destinationAddress, let server = packet.sourceAddress,
              !dnsIsMulticast(client), packet.interface.state != .conflict,
              message.questions.allSatisfy({ $0.recordClass & 0x7fff == 1 }) else { continue }
        let scope = DNSClientScope(artifactID: packet.id.artifactID, client: client, interface: packet.interface)
        let position = dnsPosition(packet: packet)
        let names = Set(message.questions.map(\.name) + message.answers.filter { $0.recordClass & 0x7fff == 1 }.compactMap(\.owner))
        if message.responseCode == 3 {
            for name in names { negativeNameEvents[DNSOwnerKey(scope: scope, owner: name), default: []].append(position) }
        }
        guard message.responseCode == 0, message.questions.allSatisfy({ $0.recordClass & 0x7fff == 1 }) else { continue }
        let typedOwners = Set(message.questions.map {
            DNSOwnerTypeKey(owner: DNSOwnerKey(scope: scope, owner: $0.name), recordType: $0.recordType)
        } + message.answers.filter { $0.recordClass & 0x7fff == 1 }.compactMap { record in
            record.owner.map { DNSOwnerTypeKey(owner: DNSOwnerKey(scope: scope, owner: $0), recordType: record.recordType) }
        })
        // Positive replacements and NOERROR/NODATA questions invalidate the prior owner/type.
        for key in typedOwners { eventsByType[key, default: []].append(position) }
        var supportingPackets = [packet.id]
        if let queryFrame = message.responseToFrame {
            let queryID = PacketRecordID(artifactID: packet.id.artifactID, frameNumber: queryFrame)
            if let queryPacket = packetsByID[queryID], let queryMessages = messagesByID[queryID], queryMessages.count == 1,
               let query = queryMessages.first, !query.isResponse, query.transactionID == message.transactionID,
               query.questions == message.questions, queryPacket.sourceAddress == client, queryPacket.destinationAddress == server,
               queryPacket.sourcePort == packet.destinationPort, queryPacket.destinationPort == packet.sourcePort,
               queryPacket.transport == packet.transport, queryPacket.stream == packet.stream,
               queryPacket.interface == packet.interface, queryPacket.timestamp <= packet.timestamp {
                supportingPackets.append(queryID)
            }
        }
        for record in message.answers where record.ttlSeconds > 0 {
            guard record.recordClass & 0x7fff == 1 else { continue }
            guard record.recordType == 1 || record.recordType == 28 || record.recordType == 5 else { continue }
            let (seconds, overflow) = packet.timestamp.epochSeconds.addingReportingOverflow(Int64(record.ttlSeconds))
            guard !overflow else { throw CapturedDNSError.malformed(frame: packet.id.frameNumber, reason: "DNS TTL overflows capture time") }
            timed.append(DNSTimedRecord(
                record: record, packet: packet, scope: scope, supportingPackets: supportingPackets,
                validityEnd: DNSPosition(timestamp: PacketTimestamp(epochSeconds: seconds, nanoseconds: packet.timestamp.nanoseconds, originalText: try computedDNSExpiryText(seconds: seconds, nanoseconds: packet.timestamp.nanoseconds)), frameNumber: 0)
            ))
        }
    }
    let sortedTypeEvents = eventsByType.mapValues { Array(Set($0)).sorted() }
    let sortedNegativeEvents = negativeNameEvents.mapValues { Array(Set($0)).sorted() }
    var validRecords: [DNSTimedRecord] = []
    for (index, item) in timed.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard let owner = item.record.owner else { throw CapturedDNSError.malformed(frame: item.packet.id.frameNumber, reason: "address or CNAME record has no owner") }
        let ownerKey = DNSOwnerKey(scope: item.scope, owner: owner)
        let start = dnsPosition(packet: item.packet)
        var end = item.validityEnd
        if let next = nextDNSPosition(sortedTypeEvents[DNSOwnerTypeKey(owner: ownerKey, recordType: item.record.recordType)] ?? [], after: start) { end = min(end, next) }
        if let next = nextDNSPosition(sortedNegativeEvents[ownerKey] ?? [], after: start) { end = min(end, next) }
        guard start < end else { continue }
        validRecords.append(DNSTimedRecord(record: item.record, packet: item.packet, scope: item.scope, supportingPackets: item.supportingPackets, validityEnd: end))
    }
    let aliases = try Dictionary(grouping: validRecords.filter { $0.record.recordType == 5 }, by: { item in
        guard case let .canonicalName(target) = item.record.value else {
            throw CapturedDNSError.malformed(frame: item.packet.id.frameNumber, reason: "CNAME RR has a nonalias value")
        }
        return DNSOwnerKey(scope: item.scope, owner: target)
    })
    var bindings: [DNSAddressKey: [DNSAddressBinding]] = [:]
    var bindingCount = 0
    let (maximumComparisons, comparisonOverflow) = maximumAssociations.multipliedReportingOverflow(by: 64)
    guard !comparisonOverflow else { throw CapturedDNSError.resourceLimit("association limit exceeds the supported comparison budget") }
    var comparisons = 0
    var identities: Set<DNSBindingIdentity> = []
    for item in validRecords where item.record.recordType == 1 || item.record.recordType == 28 {
        try Task.checkCancellation()
        guard let owner = item.record.owner else { throw CapturedDNSError.malformed(frame: item.packet.id.frameNumber, reason: "address record has no owner") }
        let address: String
        switch item.record.value {
        case let .ipv4(value), let .ipv6(value): address = value
        default: throw CapturedDNSError.malformed(frame: item.packet.id.frameNumber, reason: "address RR has a nonaddress value")
        }
        var queue = [DNSAddressBinding(scope: item.scope, name: owner, address: address, start: dnsPosition(packet: item.packet), end: item.validityEnd, chain: [owner], dependencies: [item])]
        var index = 0
        while index < queue.count {
            if index.isMultiple(of: 512) { try Task.checkCancellation() }
            let binding = queue[index]
            index += 1
            let supporting = Set(binding.dependencies.flatMap(\.supportingPackets)).sorted { $0.frameNumber < $1.frameNumber }
            let identity = DNSBindingIdentity(scope: binding.scope, name: binding.name, address: binding.address, start: binding.start, end: binding.end, chain: binding.chain, supportingPackets: supporting)
            guard identities.insert(identity).inserted else { continue }
            bindingCount += 1
            guard bindingCount <= maximumAssociations else { throw CapturedDNSError.resourceLimit("more than \(maximumAssociations) DNS bindings") }
            bindings[DNSAddressKey(scope: binding.scope, address: binding.address), default: []].append(binding)
            for (aliasIndex, alias) in (aliases[DNSOwnerKey(scope: binding.scope, owner: binding.name)] ?? []).enumerated() {
                if aliasIndex.isMultiple(of: 512) { try Task.checkCancellation() }
                comparisons += 1
                guard comparisons <= maximumComparisons else { throw CapturedDNSError.resourceLimit("DNS alias matching exceeds \(maximumComparisons) candidate comparisons") }
                guard let aliasOwner = alias.record.owner, !binding.chain.contains(aliasOwner) else { continue }
                guard binding.chain.count < 64 else { throw CapturedDNSError.resourceLimit("CNAME chain exceeds 64 records") }
                let start = max(binding.start, dnsPosition(packet: alias.packet))
                let end = min(binding.end, alias.validityEnd)
                guard start < end else { continue }
                queue.append(DNSAddressBinding(
                    scope: binding.scope, name: aliasOwner, address: address, start: start, end: end,
                    chain: [aliasOwner] + binding.chain, dependencies: binding.dependencies + [alias]
                ))
                guard queue.count <= maximumAssociations else { throw CapturedDNSError.resourceLimit("DNS alias graph exceeds \(maximumAssociations) entries") }
            }
        }
    }
    let orderedBindings = bindings.mapValues { $0.sorted { $0.start < $1.start } }
    let orderedPackets = packets.sorted { dnsPosition(packet: $0) < dnsPosition(packet: $1) }
    var cursors: [DNSAddressKey: DNSBindingCursor] = [:]
    var result: [PacketRecordID: [CapturedHostnameAssociation]] = [:]
    var associationCount = 0
    for (index, packet) in orderedPackets.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard let source = packet.sourceAddress, let destination = packet.destinationAddress, packet.interface.state != .conflict else { continue }
        var linked: Set<CapturedHostnameAssociation> = []
        for (client, remote) in [(source, destination), (destination, source)] {
            let scope = DNSClientScope(artifactID: packet.id.artifactID, client: client, interface: packet.interface)
            let key = DNSAddressKey(scope: scope, address: remote.rawValue)
            guard let candidates = orderedBindings[key] else { continue }
            let position = dnsPosition(packet: packet)
            var cursor = cursors[key] ?? DNSBindingCursor(nextIndex: 0, active: [:])
            cursor.active = cursor.active.filter { $0.value.end > position }
            while cursor.nextIndex < candidates.count, candidates[cursor.nextIndex].start <= position {
                if cursor.nextIndex.isMultiple(of: 512) { try Task.checkCancellation() }
                let candidate = candidates[cursor.nextIndex]
                if candidate.end > position { cursor.active[cursor.nextIndex] = candidate }
                cursor.nextIndex += 1
            }
            for binding in cursor.active.values {
                let supporting = Set(binding.dependencies.flatMap(\.supportingPackets)).sorted { $0.frameNumber < $1.frameNumber }
                linked.insert(CapturedHostnameAssociation(
                    name: binding.name, address: remote.rawValue, supportingPackets: supporting, validUntil: binding.end.timestamp,
                    canonicalNameChain: binding.chain, provenance: .capturedDNSAnswer, isInferred: true,
                    detail: "DNS answer-to-packet association is inferred within the same capture, receiver IP, and interface. Owner/RDATA and CNAME edges are paired. Validity ends at epoch \(binding.end.timestamp.originalText), frame position \(binding.end.frameNumber), after intersecting TTL intervals with the next replacement or negative answer. Frame position 0 means the TTL time boundary; shared addresses can retain multiple candidate names."
                ))
                guard associationCount + linked.count <= maximumAssociations else {
                    throw CapturedDNSError.resourceLimit("more than \(maximumAssociations) packet-name associations")
                }
            }
            cursors[key] = cursor
        }
        if !linked.isEmpty {
            associationCount += linked.count
            guard associationCount <= maximumAssociations else { throw CapturedDNSError.resourceLimit("more than \(maximumAssociations) packet-name associations") }
            result[packet.id] = linked.sorted { left, right in
                if left.name != right.name { return left.name < right.name }
                switch (left.address, right.address) {
                case (nil, .some): return true
                case (.some, nil): return false
                case let (.some(leftAddress), .some(rightAddress)) where leftAddress != rightAddress: return leftAddress < rightAddress
                default: return left.canonicalNameChain.joined(separator: ".") < right.canonicalNameChain.joined(separator: ".")
                }
            }
        }
    }
    return result
}

private func dnsPosition(packet: PacketRecord) -> DNSPosition {
    DNSPosition(timestamp: packet.timestamp, frameNumber: packet.id.frameNumber)
}

/// Returns the first strictly later event in a pre-sorted owner/type list.
private func nextDNSPosition(_ positions: [DNSPosition], after position: DNSPosition) -> DNSPosition? {
    var lower = 0
    var upper = positions.count
    while lower < upper {
        let middle = lower + (upper - lower) / 2
        if positions[middle] <= position { lower = middle + 1 }
        else { upper = middle }
    }
    return lower < positions.count ? positions[lower] : nil
}

/// Produces display text for a computed normalized epoch; it is not original capture text.
private func computedDNSExpiryText(seconds: Int64, nanoseconds: UInt32) throws -> String {
    guard nanoseconds < 1_000_000_000 else { throw PacketDomainError.invalidTimestamp }
    if seconds < 0, nanoseconds > 0 {
        return "-\(-(seconds + 1)).\(String(format: "%09u", 1_000_000_000 - nanoseconds))"
    }
    return "\(seconds).\(String(format: "%09u", nanoseconds))"
}

private func dnsIsMulticast(_ address: PacketIPAddress) -> Bool {
    if address.family == .ipv6 { return address.rawValue.lowercased().hasPrefix("ff") }
    guard let first = address.rawValue.split(separator: ".").first.flatMap({ UInt8($0) }) else { return true }
    return (224...239).contains(first) || address.rawValue == "255.255.255.255"
}
