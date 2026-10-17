import Foundation

/// Repeated stream observations are stored once each, not expanded into every later frame.
/// Keys let searches test the first observation; indexed predecessor reads find the precise
/// supporting frame for a selected packet without retaining the stream's history in memory.
func createStoredStreamNames(database: PacketDatabase) throws {
    try database.execute("CREATE TABLE stream_name_keys(session TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, search TEXT NOT NULL, first_seconds INTEGER NOT NULL, first_nanos INTEGER NOT NULL, first_frame INTEGER NOT NULL, PRIMARY KEY(session,field,value)) WITHOUT ROWID", values: [])
    try database.execute("CREATE TABLE stream_name_observations(session TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, seconds INTEGER NOT NULL, nanos INTEGER NOT NULL, frame INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(session,field,value,seconds,nanos,frame)) WITHOUT ROWID", values: [])
}

func appendStoredPacketNames(database: PacketDatabase, record: PacketRecord, session: String?) throws {
    let encoder = JSONEncoder()
    var direct: [CapturedHostnameAssociation] = []
    for name in Set(record.recordedNames) {
        guard let provenance = capturedNameProvenance(name: name, packet: record) else { continue }
        direct.append(CapturedHostnameAssociation(name: name.value, address: nil, supportingPackets: [record.id],
            validUntil: nil, canonicalNameChain: [], provenance: provenance, isInferred: false,
            detail: "Directly decoded \(name.field.rawValue) in frame \(record.id.frameNumber) at epoch \(record.timestamp.originalText). This records a name in this frame; it does not independently verify a peer identity or assign the name to an address."))
        guard let session, [.tlsSNI, .httpHost, .http2Authority, .http3Authority].contains(name.field) else { continue }
        let frame = try packetStorageInteger(record.id.frameNumber)
        let key: [PacketSQLValue] = [.text(session), .text(name.field.rawValue), .text(name.value.precomposedStringWithCanonicalMapping)]
        let stamp: [PacketSQLValue] = [.integer(record.timestamp.epochSeconds), .integer(Int64(record.timestamp.nanoseconds)), .integer(frame)]
        let earlier = "(excluded.first_seconds,excluded.first_nanos,excluded.first_frame)<(first_seconds,first_nanos,first_frame)"
        try database.execute("""
            INSERT INTO stream_name_keys(session,field,value,search,first_seconds,first_nanos,first_frame) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(session,field,value) DO UPDATE SET
            first_seconds=MIN(first_seconds,excluded.first_seconds),
            first_nanos=CASE WHEN \(earlier) THEN excluded.first_nanos ELSE first_nanos END,
            first_frame=CASE WHEN \(earlier) THEN excluded.first_frame ELSE first_frame END
            """, values: key + [.text(packetStorageSearch(name.value))] + stamp)
        let inferred = CapturedHostnameAssociation(name: name.value, address: nil, supportingPackets: [record.id],
            validUntil: nil, canonicalNameChain: [], provenance: provenance, isInferred: true,
            detail: "Earlier \(name.field.rawValue) in frame \(record.id.frameNumber) at epoch \(record.timestamp.originalText), within the same capture, transport stream, interface, process metadata, and endpoint pair. This inferred conversation context does not establish the selected packet's hostname or one endpoint's identity; connection reuse and multiplexing can retain several names.")
        try database.execute("INSERT INTO stream_name_observations(session,field,value,seconds,nanos,frame,payload) VALUES(?,?,?,?,?,?,?)", values: key + stamp + [.bytes(try encoder.encode(inferred))])
    }
    if !direct.isEmpty { try storeFrameCapturedNames(database: database, id: record.id, evidence: direct) }
}

func storeFrameCapturedNames(database: PacketDatabase, id: PacketRecordID, evidence: [CapturedHostnameAssociation]) throws {
    let combined = sortedStoredNames(Set(try storedFrameCapturedNames(database: database, id: id)).union(evidence))
    guard !combined.isEmpty else { return }
    try database.execute("INSERT INTO captured_names(frame,payload,search) VALUES(?,?,?) ON CONFLICT(frame) DO UPDATE SET payload=excluded.payload,search=excluded.search", values: [
        .integer(try packetStorageInteger(id.frameNumber)), .bytes(try JSONEncoder().encode(combined)),
        .text(packetStorageSearch(combined.map(\.name).joined(separator: "\u{1f}")))
    ])
}

func storedCapturedNames(database: PacketDatabase, id: PacketRecordID) throws -> [CapturedHostnameAssociation] {
    var evidence = Set(try storedFrameCapturedNames(database: database, id: id))
    var session: String?
    var seconds: Int64?
    var nanos: Int64?
    try database.rows("SELECT session,seconds,nanos FROM packets WHERE frame=?", values: [.integer(try packetStorageInteger(id.frameNumber))]) { row in
        session = try row.optionalText(0)
        seconds = try row.integer(1)
        nanos = try row.integer(2)
    }
    guard let session, let seconds, let nanos else { return sortedStoredNames(evidence) }
    let position: [PacketSQLValue] = [.integer(seconds), .integer(nanos), .integer(try packetStorageInteger(id.frameNumber))]
    try database.rows("SELECT field,value FROM stream_name_keys WHERE session=? AND (first_seconds,first_nanos,first_frame)<(?,?,?)", values: [.text(session)] + position) { row in
        let field = try row.text(0)
        let value = try row.text(1)
        try database.rows("SELECT payload FROM stream_name_observations WHERE session=? AND field=? AND value=? AND (seconds,nanos,frame)<(?,?,?) ORDER BY seconds DESC,nanos DESC,frame DESC LIMIT 1", values: [.text(session), .text(field), .text(value)] + position) { observation in
            evidence.insert(try JSONDecoder().decode(CapturedHostnameAssociation.self, from: observation.bytes(0)))
        }
    }
    return sortedStoredNames(evidence)
}

private func sortedStoredNames(_ evidence: Set<CapturedHostnameAssociation>) -> [CapturedHostnameAssociation] {
    evidence.sorted { ($0.name, $0.provenance.rawValue, $0.isInferred ? 1 : 0, $0.detail) < ($1.name, $1.provenance.rawValue, $1.isInferred ? 1 : 0, $1.detail) }
}

func indexStoredHostnameEvidence(storage: PacketDiskStorage, artifact: PacketArtifactID, messages: [CapturedDNSMessage]) throws {
    try withPacketDatabase(files: storage.files, access: .write) { database in
        try database.execute("BEGIN", values: [])
        try storeDNSMessages(messages: messages, artifact: artifact, database: database)
        try database.execute("COMMIT", values: [])
    }
    try finalizeStoredHostnameEvidence(storage: storage, artifact: artifact)
}

func finalizeStoredHostnameEvidence(storage: PacketDiskStorage, artifact: PacketArtifactID) throws {
    try withPacketDatabase(files: storage.files, access: .write) { database in
        try database.execute("BEGIN", values: [])
        try indexStoredDNSBindings(database: database, artifact: artifact)
        try appendStoredDNSNames(database: database, artifact: artifact)
        try database.execute("COMMIT", values: [])
    }
}
