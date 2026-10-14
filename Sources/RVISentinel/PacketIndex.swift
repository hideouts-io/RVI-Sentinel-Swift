import Foundation

struct PacketRecordQuery: Hashable, Sendable {
    let text: String
    let transport: PacketTransport?
    let protocolKind: ProtocolKind?
    let interfaceName: String?
    let processID: Int32?
    let direction: PacketDirection?
    let recordIDs: Set<PacketRecordID>?
}

struct PacketPageRequest: Hashable, Sendable {
    let offset: Int
    let limit: Int
}

struct PacketPage: Equatable, Sendable {
    let records: [PacketRecord]
    let matchingCount: Int
    let nextOffset: Int?
}

/// Estimates retained value storage, not actual RSS. Exceeding a bound fails explicitly.
struct PacketIndexAccumulator {
    let artifact: PacketCaptureArtifact
    let limits: PacketIndexLimits
    private var records: [PacketRecord]
    private var frameNumbers: Set<UInt64>
    private var estimatedBytes: Int

    init(artifact: PacketCaptureArtifact, limits: PacketIndexLimits) throws {
        guard limits.maximumRecords > 0, limits.maximumEstimatedBytes > 0 else { throw PacketDomainError.invalidIndexLimits }
        self.artifact = artifact
        self.limits = limits
        records = []
        frameNumbers = []
        estimatedBytes = 0
    }

    mutating func consume(packet: DecodedPacket) throws {
        try append(record: decodePacketRecord(packet: packet, artifact: artifact))
    }

    mutating func append(record: PacketRecord) throws {
        guard record.id.artifactID == artifact.id else { throw PacketDomainError.artifactMismatch }
        guard records.count < limits.maximumRecords else { throw PacketDomainError.recordLimitExceeded(limits.maximumRecords) }
        guard !frameNumbers.contains(record.id.frameNumber) else { throw PacketDomainError.duplicateFrame(record.id.frameNumber) }
        let (size, overflow) = estimatedBytes.addingReportingOverflow(estimatedPacketStorage(record))
        guard !overflow, size <= limits.maximumEstimatedBytes else { throw PacketDomainError.memoryLimitExceeded(limits.maximumEstimatedBytes) }
        records.append(record)
        frameNumbers.insert(record.id.frameNumber)
        estimatedBytes = size
    }

    func result() throws -> PacketAnalysisResult {
        try Task.checkCancellation()
        let ordered = records.sorted(by: packetChronologicalOrder)
        let sessions = try makePacketSessions(records: ordered, artifact: artifact)
        let groupedCount = sessions.reduce(0) { $0 + $1.packetCount }
        return PacketAnalysisResult(artifact: artifact, records: ordered, sessions: sessions,
            coverage: PacketIndexCoverage(recordCount: records.count, estimatedBytes: estimatedBytes,
                maximumRecords: limits.maximumRecords, maximumEstimatedBytes: limits.maximumEstimatedBytes,
                ungroupedPackets: records.count - groupedCount))
    }
}

func packetChronologicalOrder(_ left: PacketRecord, _ right: PacketRecord) -> Bool {
    if left.timestamp.epochSeconds != right.timestamp.epochSeconds || left.timestamp.nanoseconds != right.timestamp.nanoseconds {
        return left.timestamp < right.timestamp
    }
    return left.id.frameNumber < right.id.frameNumber
}

/// Filter and page immutable records on a consumer-owned background task.
func pagePacketRecords(result: PacketAnalysisResult, query: PacketRecordQuery, page: PacketPageRequest) throws -> PacketPage {
    try pagePacketRecords(result: result, query: query, names: [:], page: page)
}

func pagePacketRecords(result: PacketAnalysisResult, query: PacketRecordQuery, names: [PacketRecordID: [CapturedHostnameAssociation]], page: PacketPageRequest) throws -> PacketPage {
    guard page.offset >= 0, (1...1_000).contains(page.limit) else { throw PacketDomainError.invalidPage }
    let text = query.text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let tokens = text.split(whereSeparator: \.isWhitespace).map(String.init)
    var matchingCount = 0
    var records: [PacketRecord] = []
    for (index, record) in result.records.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard matchesPacket(record, query: query, tokens: tokens, names: names[record.id] ?? []) else { continue }
        if matchingCount >= page.offset && records.count < page.limit { records.append(record) }
        matchingCount += 1
    }
    let (nextOffset, overflow) = page.offset.addingReportingOverflow(records.count)
    return PacketPage(records: records, matchingCount: matchingCount,
        nextOffset: !overflow && nextOffset < matchingCount ? nextOffset : nil)
}

private func matchesPacket(_ record: PacketRecord, query: PacketRecordQuery, tokens: [String], names: [CapturedHostnameAssociation]) -> Bool {
    if let ids = query.recordIDs, !ids.contains(record.id) { return false }
    if let transport = query.transport, record.transport != transport { return false }
    if let kind = query.protocolKind, !record.protocols.contains(kind) { return false }
    if let name = query.interfaceName, !record.interface.labels.contains(where: { $0.name == name }) { return false }
    if let pid = query.processID, !record.process.labels.contains(where: { $0.processID == pid }) && !record.effectiveProcess.labels.contains(where: { $0.processID == pid }) { return false }
    if let direction = query.direction, record.direction.direction != direction { return false }
    guard !tokens.isEmpty else { return true }
    let candidates = (packetSearchValues(record) + names.map(\.name)).map { $0.lowercased() }
    return tokens.allSatisfy { token in candidates.contains(where: { $0.contains(token) }) }
}

private func packetSearchValues(_ record: PacketRecord) -> [String] {
    var values = record.protocolStack + record.protocols.map(\.rawValue) + record.recordedNames.map(\.value) + record.interface.labels.map(\.name)
    values.append(contentsOf: (record.process.labels + record.effectiveProcess.labels).flatMap { label in
        [label.name, label.processID.map(String.init)].compactMap { $0 }
    })
    values.append(contentsOf: [record.sourceAddress?.rawValue, record.destinationAddress?.rawValue, record.sourcePort.map(String.init), record.destinationPort.map(String.init), record.stream.map(String.init)].compactMap { $0 })
    return values
}

private func estimatedPacketStorage(_ record: PacketRecord) -> Int {
    let strings = packetSearchValues(record) + [record.timestamp.originalText]
    // Covers the fixed record, identity/set slots, and eventual session membership.
    let metadataEntries = record.process.labels.count + record.effectiveProcess.labels.count + record.interface.labels.count + record.direction.labels.count
    return 1_024 + strings.reduce(0) { $0 + $1.utf8.count + 32 } + (record.recordedNames.count + metadataEntries) * 64
}
