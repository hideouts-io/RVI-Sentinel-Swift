import Foundation

struct PacketEndpoint: Codable, Hashable, Comparable, Sendable {
    let address: PacketIPAddress
    let port: UInt16

    static func < (left: Self, right: Self) -> Bool {
        if left.address.rawValue != right.address.rawValue { return left.address.rawValue < right.address.rawValue }
        return left.port < right.port
    }
}

struct PacketSessionKey: Codable, Hashable, Sendable {
    let artifactID: PacketArtifactID
    let source: PacketSourceProvenance
    let interface: PacketInterfaceMetadata
    let process: PacketProcessMetadata
    let effectiveProcess: PacketProcessMetadata
    let transport: PacketTransport
    let stream: UInt64
    let firstEndpoint: PacketEndpoint
    let secondEndpoint: PacketEndpoint
}

struct PacketSession: Codable, Identifiable, Equatable, Sendable {
    let id: PacketSessionKey
    let firstTimestamp: PacketTimestamp
    let lastTimestamp: PacketTimestamp
    let packetIDs: [PacketRecordID]
    let wireBytes: UInt64

    var packetCount: Int { packetIDs.count }
    var firstEndpoint: PacketEndpoint { id.firstEndpoint }
    var secondEndpoint: PacketEndpoint { id.secondEndpoint }
    var interface: PacketInterfaceMetadata { id.interface }
    var process: PacketProcessMetadata { id.process }
    var effectiveProcess: PacketProcessMetadata { id.effectiveProcess }
    var transport: PacketTransport { id.transport }
    var stream: UInt64 { id.stream }
}

private struct PacketSessionAccumulator {
    let key: PacketSessionKey
    let firstTimestamp: PacketTimestamp
    var lastTimestamp: PacketTimestamp
    var packetIDs: [PacketRecordID]
    var wireBytes: UInt64
}

/// The input is chronologically ordered; groups never mix artifacts or metadata contexts.
func makePacketSessions(records: [PacketRecord], artifact: PacketCaptureArtifact) throws -> [PacketSession] {
    var groups: [PacketSessionKey: PacketSessionAccumulator] = [:]
    var orderedKeys: [PacketSessionKey] = []
    for (index, record) in records.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        guard record.id.artifactID == artifact.id else { throw PacketDomainError.artifactMismatch }
        guard let key = packetSessionKey(record: record, source: artifact.source) else { continue }
        if let previousBytes = groups[key]?.wireBytes {
            let (bytes, overflow) = previousBytes.addingReportingOverflow(UInt64(record.wireLength))
            guard !overflow else { throw PacketDomainError.byteCountOverflow }
            groups[key]?.lastTimestamp = record.timestamp
            groups[key]?.packetIDs.append(record.id)
            groups[key]?.wireBytes = bytes
        } else {
            orderedKeys.append(key)
            groups[key] = PacketSessionAccumulator(key: key, firstTimestamp: record.timestamp, lastTimestamp: record.timestamp, packetIDs: [record.id], wireBytes: UInt64(record.wireLength))
        }
    }
    return orderedKeys.compactMap { key in
        groups[key].map { group in
            PacketSession(id: key, firstTimestamp: group.firstTimestamp, lastTimestamp: group.lastTimestamp, packetIDs: group.packetIDs, wireBytes: group.wireBytes)
        }
    }
}

func packetSessionKey(record: PacketRecord, source: PacketSourceProvenance) -> PacketSessionKey? {
    guard record.diagnostics.isEmpty,
          let sourceAddress = record.sourceAddress, let destinationAddress = record.destinationAddress,
          let sourcePort = record.sourcePort, let destinationPort = record.destinationPort,
          let transport = record.transport, let stream = record.stream else { return nil }
    let left = PacketEndpoint(address: sourceAddress, port: sourcePort)
    let right = PacketEndpoint(address: destinationAddress, port: destinationPort)
    return PacketSessionKey(artifactID: record.id.artifactID, source: source, interface: record.interface,
        process: record.process, effectiveProcess: record.effectiveProcess, transport: transport, stream: stream,
        firstEndpoint: min(left, right), secondEndpoint: max(left, right))
}
