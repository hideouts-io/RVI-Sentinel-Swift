import CryptoKit
import Foundation

/// Initializes capture-private DNS storage. The caller owns the surrounding transaction.
/// Messages, replacement events, pending bindings, and interval indexes remain on disk.
func createStoredDNSEvidence(database: PacketDatabase) throws {
    let statements = [
        "CREATE TABLE IF NOT EXISTS dns_state(id INTEGER PRIMARY KEY CHECK(id=1),artifact TEXT,indexed INTEGER NOT NULL)",
        "INSERT OR IGNORE INTO dns_state(id,indexed) VALUES(1,0)",
        "CREATE TABLE IF NOT EXISTS dns_messages(id INTEGER PRIMARY KEY,frame INTEGER NOT NULL,payload BLOB NOT NULL)",
        "CREATE INDEX IF NOT EXISTS dns_message_frame ON dns_messages(frame,id)",
        "CREATE TABLE IF NOT EXISTS dns_events(scope TEXT NOT NULL,owner TEXT NOT NULL,kind INTEGER NOT NULL,seconds INTEGER NOT NULL,nanos INTEGER NOT NULL,frame INTEGER NOT NULL,stamp BLOB NOT NULL,PRIMARY KEY(scope,owner,kind,seconds,nanos,frame)) WITHOUT ROWID",
        "CREATE TABLE IF NOT EXISTS dns_records(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,target TEXT,kind INTEGER NOT NULL,start_seconds INTEGER NOT NULL,start_nanos INTEGER NOT NULL,start_frame INTEGER NOT NULL,end_seconds INTEGER NOT NULL,end_nanos INTEGER NOT NULL,end_frame INTEGER NOT NULL,payload BLOB NOT NULL)",
        "CREATE TABLE IF NOT EXISTS dns_positions(position INTEGER PRIMARY KEY,seconds INTEGER NOT NULL,nanos INTEGER NOT NULL,frame INTEGER NOT NULL,UNIQUE(seconds,nanos,frame))",
        "CREATE TABLE IF NOT EXISTS dns_alias_ranges(id INTEGER PRIMARY KEY,record_id INTEGER NOT NULL)",
        "CREATE VIRTUAL TABLE IF NOT EXISTS dns_alias_index USING rtree_i32(id,min_hi,max_hi,min_lo,max_lo,min_key,max_key)",
        "CREATE TABLE IF NOT EXISTS dns_bindings(id INTEGER PRIMARY KEY,identity TEXT NOT NULL UNIQUE,scope TEXT NOT NULL,address TEXT NOT NULL,name TEXT NOT NULL,start_seconds INTEGER NOT NULL,start_nanos INTEGER NOT NULL,start_frame INTEGER NOT NULL,end_seconds INTEGER NOT NULL,end_nanos INTEGER NOT NULL,end_frame INTEGER NOT NULL,payload BLOB NOT NULL)",
        "CREATE TABLE IF NOT EXISTS dns_binding_ranges(id INTEGER PRIMARY KEY,binding_id INTEGER NOT NULL)",
        "CREATE VIRTUAL TABLE IF NOT EXISTS dns_binding_index USING rtree_i32(id,min_hi,max_hi,min_lo,max_lo,min_key,max_key)"
    ]
    for statement in statements { try database.execute(statement, values: []) }
}

/// Persists a validated decoder batch, never a capture-wide message array. Packets must
/// already exist in this database. Ingestion must finish before binding indexing starts.
func storeDNSMessages(messages: [CapturedDNSMessage], artifact: PacketArtifactID, database: PacketDatabase) throws {
    try claimStoredDNSArtifact(database: database, artifact: artifact)
    guard try database.integer("SELECT indexed FROM dns_state WHERE id=1", values: []) == 0 else {
        throw PacketStorageError.invalidValue("DNS ingestion after binding finalization")
    }
    for message in messages {
        try Task.checkCancellation()
        guard message.packetID.artifactID == artifact,
              let packet = try storedPacket(database: database, artifact: artifact, id: message.packetID), packet.id == message.packetID else {
            throw CapturedDNSError.malformed(frame: message.packetID.frameNumber, reason: "DNS record has no matching indexed packet")
        }
        try database.execute("INSERT INTO dns_messages(frame,payload) VALUES(?,?)", values: [
            .integer(try packetStorageInteger(packet.id.frameNumber)), .bytes(try JSONEncoder().encode(message))
        ])
        let messageID = try database.integer("SELECT last_insert_rowid()", values: [])
        guard message.isResponse, !message.isTruncated, packet.sourcePort == 53,
              let client = packet.destinationAddress, packet.sourceAddress != nil,
              !storedDNSIsMulticast(client), packet.interface.state != .conflict,
              message.questions.allSatisfy({ $0.recordClass & 0x7fff == 1 }) else { continue }
        let scope = try storedDNSScope(artifact: artifact, client: client, interface: packet.interface)
        let start = StoredDNSPosition(timestamp: packet.timestamp, frame: packet.id.frameNumber)
        if message.responseCode == 3 {
            let owners = Set(message.questions.map(\.name) + message.answers.filter { $0.recordClass & 0x7fff == 1 }.compactMap(\.owner))
            for owner in owners { try insertStoredDNSEvent(database: database, scope: scope, owner: owner, kind: -1, position: start) }
        }
        guard message.responseCode == 0 else { continue }
        for question in message.questions {
            try insertStoredDNSEvent(database: database, scope: scope, owner: question.name, kind: Int64(question.recordType), position: start)
        }
        for record in message.answers where record.recordClass & 0x7fff == 1 {
            try Task.checkCancellation()
            if let owner = record.owner {
                try insertStoredDNSEvent(database: database, scope: scope, owner: owner, kind: Int64(record.recordType), position: start)
            }
            guard record.ttlSeconds > 0, [1, 28, 5].contains(record.recordType) else { continue }
            guard record.owner != nil else { throw CapturedDNSError.malformed(frame: start.frame, reason: "address or CNAME record has no owner") }
            let (seconds, overflow) = packet.timestamp.epochSeconds.addingReportingOverflow(Int64(record.ttlSeconds))
            guard !overflow else { throw CapturedDNSError.malformed(frame: start.frame, reason: "DNS TTL overflows capture time") }
            let end = StoredDNSPosition(timestamp: PacketTimestamp(epochSeconds: seconds, nanoseconds: packet.timestamp.nanoseconds,
                originalText: storedDNSExpiryText(seconds: seconds, nanos: packet.timestamp.nanoseconds)), frame: 0)
            let value = StoredDNSRecord(messageID: messageID, scope: scope, record: record, start: start, end: end, supportingPackets: [packet.id])
            let target: PacketSQLValue
            if case let .canonicalName(name) = record.value { target = .text(name.precomposedStringWithCanonicalMapping) }
            else { target = .null }
            try database.execute("INSERT INTO dns_records(scope,target,kind,start_seconds,start_nanos,start_frame,end_seconds,end_nanos,end_frame,payload) VALUES(?,?,?,?,?,?,?,?,?,?)", values:
                [.text(scope), target, .integer(Int64(record.recordType))] + start.sqlValues + end.sqlValues + [.bytes(try JSONEncoder().encode(value))])
        }
    }
}

/// Finalizes exact validity intervals and expands CNAMEs through indexed interval overlaps.
/// Only one record/binding and its at-most-64-name chain are held in Swift at a time.
/// The caller must discard/roll back its write transaction if this operation fails.
func indexStoredDNSBindings(database: PacketDatabase, artifact: PacketArtifactID) throws {
    try claimStoredDNSArtifact(database: database, artifact: artifact)
    if try database.integer("SELECT indexed FROM dns_state WHERE id=1", values: []) == 1 { return }
    var cursor: Int64 = 0
    while let row = try nextStoredDNSRecord(database: database, after: cursor) {
        try Task.checkCancellation()
        cursor = row.id
        let item = row.record
        guard let owner = item.record.owner else { throw PacketStorageError.invalidValue("DNS record owner") }
        var end = item.end
        for kind in [Int64(item.record.recordType), -1] {
            try database.rows("SELECT seconds,nanos,frame,stamp FROM dns_events WHERE scope=? AND owner=? AND kind=? AND (seconds,nanos,frame)>(?,?,?) ORDER BY seconds,nanos,frame LIMIT 1",
                values: [.text(item.scope), .text(owner.precomposedStringWithCanonicalMapping), .integer(kind)] + item.start.sqlValues) { event in
                let timestamp = try JSONDecoder().decode(PacketTimestamp.self, from: event.bytes(3))
                let position = StoredDNSPosition(timestamp: timestamp, frame: UInt64(try event.integer(2)))
                end = min(end, position)
            }
        }
        let supporting = try storedDNSQuerySupport(database: database, item: item, artifact: artifact)
        let adjusted = StoredDNSRecord(messageID: item.messageID, scope: item.scope, record: item.record, start: item.start, end: end, supportingPackets: supporting)
        try database.execute("UPDATE dns_records SET end_seconds=?,end_nanos=?,end_frame=?,payload=? WHERE id=?",
            values: end.sqlValues + [.bytes(try JSONEncoder().encode(adjusted)), .integer(row.id)])
    }
    // Dense positions preserve signed seconds, nanoseconds, and frame order exactly.
    // Splitting each Int64 ordinal into two signed Int32 coordinates avoids float R-tree
    // rounding and any Int32 total-record ceiling. An interval needs at most three boxes.
    try database.execute("""
        INSERT INTO dns_positions(seconds,nanos,frame)
        SELECT seconds,nanos,frame FROM (
          SELECT start_seconds AS seconds,start_nanos AS nanos,start_frame AS frame FROM dns_records
          UNION SELECT end_seconds,end_nanos,end_frame FROM dns_records
        ) ORDER BY seconds,nanos,frame
        """, values: [])
    cursor = 0
    while let row = try nextStoredDNSRecord(database: database, after: cursor) {
        try Task.checkCancellation()
        cursor = row.id
        let item = row.record
        guard item.start < item.end else { continue }
        if item.record.recordType == 5 {
            guard case let .canonicalName(target) = item.record.value else {
                throw CapturedDNSError.malformed(frame: item.start.frame, reason: "CNAME RR has a nonalias value")
            }
            let boxes = try storedDNSIntervalBoxes(database: database, start: item.start, end: item.end)
            let key = try storedDNSLookupKey(scope: item.scope, value: target)
            for box in boxes {
                try database.execute("INSERT INTO dns_alias_ranges(record_id) VALUES(?)", values: [.integer(row.id)])
                let rangeID = try database.integer("SELECT last_insert_rowid()", values: [])
                try database.execute("INSERT INTO dns_alias_index VALUES(?,?,?,?,?,?,?)", values: [.integer(rangeID)] + box.sqlValues + [.integer(key), .integer(key)])
            }
        } else {
            let address: String
            switch item.record.value {
            case let .ipv4(value), let .ipv6(value): address = value
            default: throw CapturedDNSError.malformed(frame: item.start.frame, reason: "address RR has a nonaddress value")
            }
            guard let owner = item.record.owner else { throw PacketStorageError.invalidValue("DNS address owner") }
            try insertStoredDNSBinding(database: database, binding: StoredDNSBinding(scope: item.scope, name: owner, address: address,
                start: item.start, end: item.end, chain: [owner], supportingPackets: item.supportingPackets.sorted { $0.frameNumber < $1.frameNumber }))
        }
    }
    // Bindings form a persistent FIFO. Newly expanded chains are appended on disk;
    // candidate queries use the immutable alias R-tree, never a historical alias scan.
    cursor = 0
    while let row = try nextStoredDNSBinding(database: database, after: cursor) {
        try Task.checkCancellation()
        cursor = row.id
        let binding = row.binding
        let boxes = try storedDNSIntervalBoxes(database: database, start: binding.start, end: binding.end)
        let key = try storedDNSLookupKey(scope: binding.scope, value: binding.name)
        let selections = boxes.map { _ in "SELECT id FROM dns_alias_index WHERE min_hi<=? AND max_hi>=? AND min_lo<=? AND max_lo>=? AND min_key<=? AND max_key>=?" }
        let rangeValues = boxes.flatMap { $0.overlapValues + [.integer(key), .integer(key)] }
        let sql = "SELECT payload FROM dns_records WHERE id IN (SELECT record_id FROM dns_alias_ranges WHERE id IN (\(selections.joined(separator: " UNION ")))) AND scope=? AND target=? AND (start_seconds,start_nanos,start_frame)<(?,?,?) AND (end_seconds,end_nanos,end_frame)>(?,?,?) ORDER BY id"
        try database.rows(sql, values: rangeValues + [.text(binding.scope), .text(binding.name.precomposedStringWithCanonicalMapping)] + binding.end.sqlValues + binding.start.sqlValues) { candidate in
            let alias = try JSONDecoder().decode(StoredDNSRecord.self, from: candidate.bytes(0))
            guard let owner = alias.record.owner, !binding.chain.contains(owner) else { return }
            guard binding.chain.count < 64 else { throw CapturedDNSError.resourceLimit("CNAME chain exceeds 64 records") }
            let start = max(binding.start, alias.start)
            let end = min(binding.end, alias.end)
            guard start < end else { throw PacketStorageError.invalidValue("DNS interval candidate") }
            let supporting = Set(binding.supportingPackets + alias.supportingPackets).sorted { $0.frameNumber < $1.frameNumber }
            try insertStoredDNSBinding(database: database, binding: StoredDNSBinding(scope: binding.scope, name: owner, address: binding.address,
                start: start, end: end, chain: [owner] + binding.chain, supportingPackets: supporting))
        }
    }
    try database.execute("UPDATE dns_state SET indexed=1 WHERE id=1", values: [])
}

/// Reads structured direct observations and live DNS bindings for one selected frame.
/// Interval lookups preserve unknown/conflicting interface handling and never resolve names.
func storedDNSPacketNames(database: PacketDatabase, packet: PacketRecord) throws -> [CapturedHostnameAssociation] {
    var evidence: Set<CapturedHostnameAssociation> = []
    var messages: [CapturedDNSMessage] = []
    try database.rows("SELECT payload FROM dns_messages WHERE frame=? ORDER BY id", values: [.integer(try packetStorageInteger(packet.id.frameNumber))]) { row in
        let message = try JSONDecoder().decode(CapturedDNSMessage.self, from: row.bytes(0))
        guard message.packetID == packet.id else { throw PacketDomainError.artifactMismatch }
        messages.append(message)
    }
    if !messages.isEmpty {
        // Reuse the existing per-frame direct RR/question/provenance rendering. With a
        // single frame this visitor has no stream history to propagate or retain.
        try visitCapturedHostnameEvidence(messages: messages, forEachPacket: { try $0(packet) }, dnsEvidence: { _ in [] },
            maximumAssociations: Int.max, consume: { _, names in evidence.formUnion(names) })
    }
    guard let source = packet.sourceAddress, let destination = packet.destinationAddress, packet.interface.state != .conflict else {
        return sortedStoredDNSNames(evidence)
    }
    var ordinal: Int64?
    let position = StoredDNSPosition(timestamp: packet.timestamp, frame: packet.id.frameNumber)
    try database.rows("SELECT position FROM dns_positions WHERE (seconds,nanos,frame)<=(?,?,?) ORDER BY seconds DESC,nanos DESC,frame DESC LIMIT 1", values: position.sqlValues) {
        ordinal = try $0.integer(0)
    }
    guard let ordinal else { return sortedStoredDNSNames(evidence) }
    let point = storedDNSOrdinalCoordinates(ordinal)
    for (client, remote) in [(source, destination), (destination, source)] {
        let scope = try storedDNSScope(artifact: packet.id.artifactID, client: client, interface: packet.interface)
        let key = try storedDNSLookupKey(scope: scope, value: remote.rawValue)
        try database.rows("""
            SELECT payload FROM dns_bindings WHERE id IN (
              SELECT binding_id FROM dns_binding_ranges WHERE id IN (
                SELECT id FROM dns_binding_index WHERE min_hi<=? AND max_hi>=? AND min_lo<=? AND max_lo>=? AND min_key<=? AND max_key>=?
              )
            ) AND scope=? AND address=? AND (start_seconds,start_nanos,start_frame)<=(?,?,?) AND (end_seconds,end_nanos,end_frame)>(?,?,?)
            """, values: [.integer(point.hi), .integer(point.hi), .integer(point.lo), .integer(point.lo), .integer(key), .integer(key), .text(scope), .text(remote.rawValue)] + position.sqlValues + position.sqlValues) { row in
            let binding = try JSONDecoder().decode(StoredDNSBinding.self, from: row.bytes(0))
            evidence.insert(CapturedHostnameAssociation(name: binding.name, address: remote.rawValue, supportingPackets: binding.supportingPackets,
                validUntil: binding.end.timestamp, canonicalNameChain: binding.chain, provenance: .capturedDNSAnswer, isInferred: true,
                detail: "DNS answer-to-packet association is inferred within the same capture, receiver IP, and interface. Owner/RDATA and CNAME edges are paired. Validity ends at epoch \(binding.end.timestamp.originalText), frame position \(binding.end.frame), after intersecting TTL intervals with the next replacement or negative answer. Frame position 0 means the TTL time boundary; shared addresses can retain multiple candidate names."))
        }
    }
    return sortedStoredDNSNames(evidence)
}

/// Merges DNS evidence with stored direct names, without invoking lazy stream propagation.
/// Empty DNS streams cost no packet traversal. The caller owns the write transaction.
func appendStoredDNSNames(database: PacketDatabase, artifact: PacketArtifactID) throws {
    if try database.integer("SELECT COUNT(*) FROM dns_messages", values: []) == 0 { return }
    try claimStoredDNSArtifact(database: database, artifact: artifact)
    guard try database.integer("SELECT indexed FROM dns_state WHERE id=1", values: []) == 1 else {
        throw PacketStorageError.invalidValue("DNS bindings have not been finalized")
    }
    try database.rows("SELECT payload FROM packets ORDER BY seconds,nanos,frame", values: []) { row in
        let packet = try JSONDecoder().decode(PacketRecord.self, from: row.bytes(0))
        guard packet.id.artifactID == artifact else { throw PacketDomainError.artifactMismatch }
        let names = try storedDNSPacketNames(database: database, packet: packet)
        if !names.isEmpty { try storeFrameCapturedNames(database: database, id: packet.id, evidence: names) }
    }
}

private struct StoredDNSPosition: Codable, Comparable {
    let timestamp: PacketTimestamp
    let frame: UInt64

    var sqlValues: [PacketSQLValue] {
        [.integer(timestamp.epochSeconds), .integer(Int64(timestamp.nanoseconds)), .integer(Int64(frame))]
    }

    static func < (left: Self, right: Self) -> Bool {
        left.timestamp == right.timestamp ? left.frame < right.frame : left.timestamp < right.timestamp
    }
}

private struct StoredDNSRecord: Codable {
    let messageID: Int64
    let scope: String
    let record: CapturedDNSResourceRecord
    let start: StoredDNSPosition
    let end: StoredDNSPosition
    let supportingPackets: [PacketRecordID]
}

private struct StoredDNSBinding: Codable {
    let scope: String
    let name: String
    let address: String
    let start: StoredDNSPosition
    let end: StoredDNSPosition
    let chain: [String]
    let supportingPackets: [PacketRecordID]
}

private struct StoredDNSOrderKey: Codable {
    let seconds: Int64
    let nanos: UInt32
    let frame: UInt64
}

private struct StoredDNSBindingIdentity: Codable {
    let scope: String
    let name: String
    let address: String
    let start: StoredDNSOrderKey
    let end: StoredDNSOrderKey
    let chain: [String]
    let supportingPackets: [PacketRecordID]
}

private struct StoredDNSClientScope: Codable {
    let artifact: PacketArtifactID
    let client: PacketIPAddress
    let interface: PacketInterfaceMetadata
}

private struct StoredDNSLookupIdentity: Codable {
    let scope: String
    let value: String
}

struct StoredDNSBox: Equatable {
    let minHi: Int64
    let maxHi: Int64
    let minLo: Int64
    let maxLo: Int64

    var sqlValues: [PacketSQLValue] { [.integer(minHi), .integer(maxHi), .integer(minLo), .integer(maxLo)] }
    var overlapValues: [PacketSQLValue] { [.integer(maxHi), .integer(minHi), .integer(maxLo), .integer(minLo)] }
}

private func claimStoredDNSArtifact(database: PacketDatabase, artifact: PacketArtifactID) throws {
    let key = try storedDNSDigest(artifact)
    var stored: String?
    try database.rows("SELECT artifact FROM dns_state WHERE id=1", values: []) { stored = try $0.optionalText(0) }
    if let stored {
        guard stored == key else { throw PacketDomainError.artifactMismatch }
    } else {
        try database.execute("UPDATE dns_state SET artifact=? WHERE id=1", values: [.text(key)])
    }
}

private func storedDNSScope(artifact: PacketArtifactID, client: PacketIPAddress, interface: PacketInterfaceMetadata) throws -> String {
    try storedDNSDigest(StoredDNSClientScope(artifact: artifact, client: client, interface: interface))
}

private func storedDNSCanonicalJSON<Value: Encodable>(_ value: Value) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    guard let text = String(data: data, encoding: .utf8) else { throw PacketStorageError.invalidValue("DNS key UTF-8") }
    return Data(text.precomposedStringWithCanonicalMapping.utf8)
}

private func storedDNSDigest<Value: Encodable>(_ value: Value) throws -> String {
    try SHA256.hash(data: storedDNSCanonicalJSON(value)).map { String(format: "%02x", $0) }.joined()
}

private func storedDNSLookupKey(scope: String, value: String) throws -> Int64 {
    let digest = try SHA256.hash(data: storedDNSCanonicalJSON(StoredDNSLookupIdentity(scope: scope, value: value)))
    // Hash collisions only broaden the candidate set. Exact scope/value predicates follow.
    return digest.prefix(4).reduce(Int64(0)) { ($0 << 8) | Int64($1) } - 2_147_483_648
}

private func insertStoredDNSEvent(database: PacketDatabase, scope: String, owner: String, kind: Int64, position: StoredDNSPosition) throws {
    try database.execute("INSERT OR IGNORE INTO dns_events(scope,owner,kind,seconds,nanos,frame,stamp) VALUES(?,?,?,?,?,?,?)", values:
        [.text(scope), .text(owner.precomposedStringWithCanonicalMapping), .integer(kind)] + position.sqlValues + [.bytes(try JSONEncoder().encode(position.timestamp))])
}

private func nextStoredDNSRecord(database: PacketDatabase, after cursor: Int64) throws -> (id: Int64, record: StoredDNSRecord)? {
    var result: (id: Int64, record: StoredDNSRecord)?
    try database.rows("SELECT id,payload FROM dns_records WHERE id>? ORDER BY id LIMIT 1", values: [.integer(cursor)]) {
        result = (try $0.integer(0), try JSONDecoder().decode(StoredDNSRecord.self, from: $0.bytes(1)))
    }
    return result
}

private func nextStoredDNSBinding(database: PacketDatabase, after cursor: Int64) throws -> (id: Int64, binding: StoredDNSBinding)? {
    var result: (id: Int64, binding: StoredDNSBinding)?
    try database.rows("SELECT id,payload FROM dns_bindings WHERE id>? ORDER BY id LIMIT 1", values: [.integer(cursor)]) {
        result = (try $0.integer(0), try JSONDecoder().decode(StoredDNSBinding.self, from: $0.bytes(1)))
    }
    return result
}

private func storedDNSQuerySupport(database: PacketDatabase, item: StoredDNSRecord, artifact: PacketArtifactID) throws -> [PacketRecordID] {
    var message: CapturedDNSMessage?
    try database.rows("SELECT payload FROM dns_messages WHERE id=?", values: [.integer(item.messageID)]) {
        message = try JSONDecoder().decode(CapturedDNSMessage.self, from: $0.bytes(0))
    }
    guard let message, let packet = try storedPacket(database: database, artifact: artifact, id: message.packetID) else {
        throw PacketStorageError.invalidValue("DNS supporting packet")
    }
    guard let queryFrame = message.responseToFrame else { return [packet.id] }
    let queryID = PacketRecordID(artifactID: artifact, frameNumber: queryFrame)
    guard let queryPacket = try storedPacket(database: database, artifact: artifact, id: queryID),
          try database.integer("SELECT COUNT(*) FROM dns_messages WHERE frame=?", values: [.integer(try packetStorageInteger(queryFrame))]) == 1 else { return [packet.id] }
    var query: CapturedDNSMessage?
    try database.rows("SELECT payload FROM dns_messages WHERE frame=? ORDER BY id", values: [.integer(try packetStorageInteger(queryFrame))]) {
        query = try JSONDecoder().decode(CapturedDNSMessage.self, from: $0.bytes(0))
    }
    guard let query, !query.isResponse, query.transactionID == message.transactionID, query.questions == message.questions,
          queryPacket.sourceAddress == packet.destinationAddress, queryPacket.destinationAddress == packet.sourceAddress,
          queryPacket.sourcePort == packet.destinationPort, queryPacket.destinationPort == packet.sourcePort,
          queryPacket.transport == packet.transport, queryPacket.stream == packet.stream,
          queryPacket.interface == packet.interface, queryPacket.timestamp <= packet.timestamp else { return [packet.id] }
    return [packet.id, queryID]
}

private func storedDNSOrdinalCoordinates(_ ordinal: Int64) -> (hi: Int64, lo: Int64) {
    (ordinal >> 32, (ordinal & 0xffff_ffff) - 2_147_483_648)
}

private func storedDNSIntervalBoxes(database: PacketDatabase, start: StoredDNSPosition, end: StoredDNSPosition) throws -> [StoredDNSBox] {
    let first = try database.integer("SELECT position FROM dns_positions WHERE seconds=? AND nanos=? AND frame=?", values: start.sqlValues)
    let exclusive = try database.integer("SELECT position FROM dns_positions WHERE seconds=? AND nanos=? AND frame=?", values: end.sqlValues)
    guard first > 0, exclusive > first else { throw PacketStorageError.invalidValue("DNS interval ordering") }
    return storedDNSOrdinalBoxes(first: first, last: exclusive - 1)
}

/// Internal seam for exact interval splitting across the 32-bit coordinate boundary.
func storedDNSOrdinalBoxes(first: Int64, last: Int64) -> [StoredDNSBox] {
    let lower = storedDNSOrdinalCoordinates(first)
    let upper = storedDNSOrdinalCoordinates(last)
    if lower.hi == upper.hi { return [StoredDNSBox(minHi: lower.hi, maxHi: upper.hi, minLo: lower.lo, maxLo: upper.lo)] }
    var boxes = [StoredDNSBox(minHi: lower.hi, maxHi: lower.hi, minLo: lower.lo, maxLo: 2_147_483_647)]
    if upper.hi - lower.hi > 1 { boxes.append(StoredDNSBox(minHi: lower.hi + 1, maxHi: upper.hi - 1, minLo: -2_147_483_648, maxLo: 2_147_483_647)) }
    boxes.append(StoredDNSBox(minHi: upper.hi, maxHi: upper.hi, minLo: -2_147_483_648, maxLo: upper.lo))
    return boxes
}

private func insertStoredDNSBinding(database: PacketDatabase, binding: StoredDNSBinding) throws {
    let identity = StoredDNSBindingIdentity(scope: binding.scope, name: binding.name, address: binding.address,
        start: StoredDNSOrderKey(seconds: binding.start.timestamp.epochSeconds, nanos: binding.start.timestamp.nanoseconds, frame: binding.start.frame),
        end: StoredDNSOrderKey(seconds: binding.end.timestamp.epochSeconds, nanos: binding.end.timestamp.nanoseconds, frame: binding.end.frame),
        chain: binding.chain, supportingPackets: binding.supportingPackets)
    try database.execute("INSERT INTO dns_bindings(identity,scope,address,name,start_seconds,start_nanos,start_frame,end_seconds,end_nanos,end_frame,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(identity) DO NOTHING", values:
        [.text(try storedDNSDigest(identity)), .text(binding.scope), .text(binding.address), .text(binding.name.precomposedStringWithCanonicalMapping)]
            + binding.start.sqlValues + binding.end.sqlValues + [.bytes(try JSONEncoder().encode(binding))])
    guard try database.integer("SELECT changes()", values: []) != 0 else { return }
    let id = try database.integer("SELECT last_insert_rowid()", values: [])
    let key = try storedDNSLookupKey(scope: binding.scope, value: binding.address)
    for box in try storedDNSIntervalBoxes(database: database, start: binding.start, end: binding.end) {
        try database.execute("INSERT INTO dns_binding_ranges(binding_id) VALUES(?)", values: [.integer(id)])
        let rangeID = try database.integer("SELECT last_insert_rowid()", values: [])
        try database.execute("INSERT INTO dns_binding_index VALUES(?,?,?,?,?,?,?)", values: [.integer(rangeID)] + box.sqlValues + [.integer(key), .integer(key)])
    }
}

private func sortedStoredDNSNames(_ evidence: Set<CapturedHostnameAssociation>) -> [CapturedHostnameAssociation] {
    evidence.sorted { ($0.name, $0.provenance.rawValue, $0.isInferred ? 1 : 0, $0.detail) < ($1.name, $1.provenance.rawValue, $1.isInferred ? 1 : 0, $1.detail) }
}

private func storedDNSExpiryText(seconds: Int64, nanos: UInt32) -> String {
    if seconds < 0, nanos > 0 { return "-\(-(seconds + 1)).\(String(format: "%09u", 1_000_000_000 - nanos))" }
    return "\(seconds).\(String(format: "%09u", nanos))"
}

private func storedDNSIsMulticast(_ address: PacketIPAddress) -> Bool {
    if address.family == .ipv6 { return address.rawValue.lowercased().hasPrefix("ff") }
    guard let first = address.rawValue.split(separator: ".").first.flatMap({ UInt8($0) }) else { return true }
    return (224...239).contains(first) || address.rawValue == "255.255.255.255"
}
