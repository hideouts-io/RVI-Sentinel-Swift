import Foundation

struct PacketSessionPage: Sendable {
    let sessions: [PacketSession]
    let matchingCount: Int
    let nextOffset: Int?
}

/// Session search uses only recorded context and separately validated captured-name links.
func pagePacketSessions(result: PacketAnalysisResult, query: PacketRecordQuery, names: [PacketRecordID: [CapturedHostnameAssociation]], page: PacketPageRequest) throws -> PacketSessionPage {
    guard page.offset >= 0, (1...1_000).contains(page.limit) else { throw PacketDomainError.invalidPage }
    let tokens = query.text.lowercased().split(whereSeparator: \.isWhitespace).map(String.init)
    var packets: [PacketRecordID: PacketRecord] = [:]
    for record in result.records {
        guard packets.updateValue(record, forKey: record.id) == nil else { throw PacketDomainError.duplicateFrame(record.id.frameNumber) }
    }
    var rows: [PacketSession] = []
    var count = 0
    for (index, session) in result.sessions.enumerated() {
        if index.isMultiple(of: 128) { try Task.checkCancellation() }
        if let transport = query.transport, session.transport != transport { continue }
        if let interface = query.interfaceName, !session.interface.labels.contains(where: { $0.name == interface }) { continue }
        if let direction = query.direction, !session.packetIDs.contains(where: { packets[$0]?.direction.direction == direction }) { continue }
        if let kind = query.protocolKind, !session.packetIDs.contains(where: { packets[$0]?.protocols.contains(kind) == true }) { continue }
        if let ids = query.recordIDs, !session.packetIDs.contains(where: { ids.contains($0) }) { continue }
        let labels = session.process.labels + session.effectiveProcess.labels
        if let pid = query.processID, !labels.contains(where: { $0.processID == pid }) { continue }
        var values = [session.transport.rawValue, session.firstEndpoint.address.rawValue, session.secondEndpoint.address.rawValue, String(session.firstEndpoint.port), String(session.secondEndpoint.port)]
        values += session.interface.labels.map(\.name)
        values += labels.flatMap { [$0.name, $0.processID.map(String.init)].compactMap { $0 } }
        if !tokens.isEmpty {
            var memberValues: Set<String> = []
            for (memberIndex, id) in session.packetIDs.enumerated() {
                if memberIndex.isMultiple(of: 512) { try Task.checkCancellation() }
                if let packet = packets[id] {
                    memberValues.formUnion(packet.protocolStack)
                    memberValues.formUnion(packet.protocols.map(\.rawValue))
                    memberValues.formUnion(packet.recordedNames.map(\.value))
                }
                memberValues.formUnion(names[id]?.map(\.name) ?? [])
            }
            values += memberValues
            let text = values.joined(separator: " ").lowercased()
            guard tokens.allSatisfy({ text.contains($0) }) else { continue }
        }
        if count >= page.offset, rows.count < page.limit { rows.append(session) }
        count += 1
    }
    let (next, overflow) = page.offset.addingReportingOverflow(rows.count)
    return PacketSessionPage(sessions: rows, matchingCount: count, nextOffset: !overflow && next < count ? next : nil)
}

func packetEndpointLabel(address: PacketIPAddress?, port: UInt16?) -> String {
    guard let address else { return "Unknown" }
    guard let port else { return address.rawValue }
    return address.family == .ipv6 ? "[\(address.rawValue)]:\(port)" : "\(address.rawValue):\(port)"
}

func packetProcessLabel(_ metadata: PacketProcessMetadata) -> String {
    switch metadata.state {
    case .unknown: return "Unknown"
    case .conflict: return "Conflicting labels"
    case .recorded: return metadata.labels.map { "\($0.name ?? "Unknown") · PID \($0.processID.map(String.init) ?? "?")" }.joined(separator: "; ")
    }
}

func packetOriginLabel(_ source: PacketSourceProvenance) -> String {
    switch source {
    case .liveDeviceRVI: "Completed device RVI capture"
    case .userDeclaredRVI: "User-declared device RVI import"
    case .unknown: "Imported capture · origin unknown"
    }
}
