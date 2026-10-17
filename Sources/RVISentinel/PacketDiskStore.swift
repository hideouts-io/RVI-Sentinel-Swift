import CryptoKit
import Foundation

/// The database contains derived records only. The original capture is never copied or changed.
struct PacketDiskStorage: Equatable, Sendable {
    let files: PacketStorageFiles
    let recordCount: Int
    let sessionCount: Int
}

/// One writer belongs to one analysis actor/task. Prepared statements and transactions keep
/// ingestion incremental; SQLite's page cache and on-disk sort replace whole-capture arrays.
final class PacketDiskWriter {
    let database: PacketDatabase
    let artifact: PacketCaptureArtifact
    private(set) var recordCount: Int = 0
    private var serializedBytes: Int = 0
    private let encoder: JSONEncoder

    init(files: PacketStorageFiles, artifact: PacketCaptureArtifact) throws {
        database = try PacketDatabase(files: files, access: .write)
        self.artifact = artifact
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try database.execute("BEGIN", values: [])
    }

    func consume(packet: DecodedPacket) throws {
        try append(record: decodePacketRecord(packet: packet, artifact: artifact))
    }

    func append(record: PacketRecord) throws {
        try Task.checkCancellation()
        guard record.id.artifactID == artifact.id else { throw PacketDomainError.artifactMismatch }
        let frame = try packetStorageInteger(record.id.frameNumber)
        let data = try encoder.encode(record)
        let key = packetSessionKey(record: record, source: artifact.source)
        let session = try key.map(packetSessionStorageID)
        let search = packetStorageSearch(packetSearchValues(record).joined(separator: "\u{1f}"))
        let memberSearch = packetStorageSearch((record.protocolStack + record.protocols.map(\.rawValue) + record.recordedNames.map(\.value)).joined(separator: "\u{1f}"))
        try database.execute("INSERT INTO packets(frame, seconds, nanos, payload, session, search, member_search, transport, direction) VALUES(?,?,?,?,?,?,?,?,?)", values: [
            .integer(frame), .integer(record.timestamp.epochSeconds), .integer(Int64(record.timestamp.nanoseconds)), .bytes(data),
            session.map(PacketSQLValue.text) ?? .null, .text(search), .text(memberSearch),
            record.transport.map { .text($0.rawValue) } ?? .null, .text(record.direction.direction.rawValue)
        ])
        try appendStoredPacketNames(database: database, record: record, session: session)
        for kind in Set(record.protocols) {
            try database.execute("INSERT INTO packet_protocols(frame, value) VALUES(?,?)", values: [.integer(frame), .text(kind.rawValue)])
        }
        for name in Set(record.interface.labels.map(\.name)) {
            try database.execute("INSERT INTO packet_interfaces(frame, value) VALUES(?,?)", values: [.integer(frame), .text(name.precomposedStringWithCanonicalMapping)])
        }
        for pid in Set((record.process.labels + record.effectiveProcess.labels).compactMap(\.processID)) {
            try database.execute("INSERT INTO packet_processes(frame, value) VALUES(?,?)", values: [.integer(frame), .integer(Int64(pid))])
        }
        if let key, let session { try appendSession(key: key, identifier: session, record: record) }
        let (nextBytes, byteOverflow) = serializedBytes.addingReportingOverflow(data.count)
        let (nextCount, countOverflow) = recordCount.addingReportingOverflow(1)
        guard !byteOverflow, !countOverflow else { throw PacketDomainError.byteCountOverflow }
        serializedBytes = nextBytes
        recordCount = nextCount
        if recordCount.isMultiple(of: 5_000) { try checkpoint() }
    }

    func checkpoint() throws {
        try database.execute("COMMIT", values: [])
        try database.execute("BEGIN", values: [])
    }

    func finish() throws -> PacketAnalysisResult {
        try database.execute("COMMIT", values: [])
        try database.execute("CREATE INDEX packet_order ON packets(seconds, nanos, frame)", values: [])
        try database.execute("CREATE INDEX packet_session_order ON packets(session, seconds, nanos, frame)", values: [])
        try database.execute("CREATE INDEX session_order ON sessions(first_seconds, first_nanos, first_frame)", values: [])
        let sessionCount = try database.integer("SELECT COUNT(*) FROM sessions", values: [])
        let ungrouped = try database.integer("SELECT COUNT(*) FROM packets WHERE session IS NULL", values: [])
        let coverage = PacketIndexCoverage(recordCount: recordCount, estimatedBytes: serializedBytes,
            maximumRecords: Int.max, maximumEstimatedBytes: Int.max, ungroupedPackets: Int(ungrouped))
        let storage = PacketDiskStorage(files: database.files, recordCount: recordCount, sessionCount: Int(sessionCount))
        // Small value-model results preserve the existing in-memory inspection/test contract.
        // Large results expose every record through the same paging functions and retain none here.
        var records: [PacketRecord] = []
        var sessions: [PacketSession] = []
        if recordCount <= 2_000 {
            try forEachRecord { records.append($0) }
            sessions = try makePacketSessions(records: records, artifact: artifact)
        }
        try database.close()
        return PacketAnalysisResult(artifact: artifact, records: records, sessions: sessions, coverage: coverage, diskStorage: storage)
    }

    func forEachRecord(_ consume: (PacketRecord) throws -> Void) throws {
        try database.rows("SELECT payload FROM packets ORDER BY seconds, nanos, frame", values: []) { row in
            try consume(JSONDecoder().decode(PacketRecord.self, from: row.bytes(0)))
        }
    }

    private func appendSession(key: PacketSessionKey, identifier: String, record: PacketRecord) throws {
        let labels = key.process.labels + key.effectiveProcess.labels
        let values = [key.transport.rawValue, key.firstEndpoint.address.rawValue, key.secondEndpoint.address.rawValue,
                      String(key.firstEndpoint.port), String(key.secondEndpoint.port)] + key.interface.labels.map(\.name)
            + labels.flatMap { [$0.name, $0.processID.map(String.init)].compactMap { $0 } }
        let stamp = try encoder.encode(record.timestamp)
        let earlier = "(excluded.first_seconds, excluded.first_nanos, excluded.first_frame) < (first_seconds, first_nanos, first_frame)"
        let later = "(excluded.last_seconds, excluded.last_nanos, excluded.last_frame) > (last_seconds, last_nanos, last_frame)"
        try database.execute("""
            INSERT INTO sessions(id, context, search, first_seconds, first_nanos, first_frame, first_stamp,
                                 last_seconds, last_nanos, last_frame, last_stamp, packet_count, wire_bytes)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET
              first_stamp=CASE WHEN \(earlier) THEN excluded.first_stamp ELSE first_stamp END,
              first_seconds=MIN(first_seconds,excluded.first_seconds),
              first_nanos=CASE WHEN \(earlier) THEN excluded.first_nanos ELSE first_nanos END,
              first_frame=CASE WHEN \(earlier) THEN excluded.first_frame ELSE first_frame END,
              last_stamp=CASE WHEN \(later) THEN excluded.last_stamp ELSE last_stamp END,
              last_seconds=MAX(last_seconds,excluded.last_seconds),
              last_nanos=CASE WHEN \(later) THEN excluded.last_nanos ELSE last_nanos END,
              last_frame=CASE WHEN \(later) THEN excluded.last_frame ELSE last_frame END,
              packet_count=packet_count+1, wire_bytes=wire_bytes+excluded.wire_bytes
            """, values: [
                .text(identifier), .bytes(try encoder.encode(key)), .text(packetStorageSearch(values.joined(separator: "\u{1f}"))),
                .integer(record.timestamp.epochSeconds), .integer(Int64(record.timestamp.nanoseconds)), .integer(try packetStorageInteger(record.id.frameNumber)), .bytes(stamp),
                .integer(record.timestamp.epochSeconds), .integer(Int64(record.timestamp.nanoseconds)), .integer(try packetStorageInteger(record.id.frameNumber)), .bytes(stamp), .integer(Int64(record.wireLength))
            ])
    }
}

func createPacketStorage(files: PacketStorageFiles) throws {
    try withPacketDatabase(files: files, access: .write) { database in
        let statements = [
            "CREATE TABLE packets(frame INTEGER PRIMARY KEY, seconds INTEGER NOT NULL, nanos INTEGER NOT NULL, payload BLOB NOT NULL, session TEXT, search TEXT NOT NULL, member_search TEXT NOT NULL, transport TEXT, direction TEXT NOT NULL)",
            "CREATE TABLE packet_protocols(frame INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(frame,value)) WITHOUT ROWID",
            "CREATE TABLE packet_interfaces(frame INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(frame,value)) WITHOUT ROWID",
            "CREATE TABLE packet_processes(frame INTEGER NOT NULL, value INTEGER NOT NULL, PRIMARY KEY(frame,value)) WITHOUT ROWID",
            "CREATE TABLE sessions(id TEXT PRIMARY KEY, context BLOB NOT NULL, search TEXT NOT NULL, first_seconds INTEGER NOT NULL, first_nanos INTEGER NOT NULL, first_frame INTEGER NOT NULL, first_stamp BLOB NOT NULL, last_seconds INTEGER NOT NULL, last_nanos INTEGER NOT NULL, last_frame INTEGER NOT NULL, last_stamp BLOB NOT NULL, packet_count INTEGER NOT NULL CHECK(typeof(packet_count)='integer'), wire_bytes INTEGER NOT NULL CHECK(typeof(wire_bytes)='integer'))",
            "CREATE TABLE apple_processes(frame INTEGER PRIMARY KEY, primary_pid INTEGER, primary_name TEXT, effective_pid INTEGER, effective_name TEXT)",
            "CREATE TABLE captured_names(frame INTEGER PRIMARY KEY, payload BLOB NOT NULL, search TEXT NOT NULL)"
        ]
        for sql in statements { try database.execute(sql, values: []) }
        try createStoredStreamNames(database: database)
        try createStoredDNSEvidence(database: database)
    }
}

func packetStorageInteger(_ value: UInt64) throws -> Int64 {
    guard let number = Int64(exactly: value) else { throw PacketStorageError.invalidValue("frame number") }
    return number
}

func packetSessionStorageID(_ key: PacketSessionKey) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(key)
    guard let json = String(data: data, encoding: .utf8) else { throw PacketStorageError.invalidValue("session encoding") }
    // Swift String equality is canonically equivalent. Normalize only the derived key,
    // never the stored evidence, so equal metadata cannot split one logical session.
    return SHA256.hash(data: Data(json.precomposedStringWithCanonicalMapping.utf8)).map { String(format: "%02x", $0) }.joined()
}

func packetStorageSearch(_ text: String) -> String {
    text.lowercased().precomposedStringWithCanonicalMapping
}

func storedAppleProcesses(database: PacketDatabase, frame: UInt64) throws -> ApplePCAPNGFrameProcesses? {
    var processes: ApplePCAPNGFrameProcesses?
    try database.rows("SELECT primary_pid,primary_name,effective_pid,effective_name FROM apple_processes WHERE frame=?", values: [.integer(try packetStorageInteger(frame))]) { row in
        let primary = try row.optionalInteger(0)
        let effective = try row.optionalInteger(2)
        let primaryName = try row.optionalText(1)
        let effectiveName = try row.optionalText(3)
        guard primary.map({ UInt32(exactly: $0) != nil }) ?? true, effective.map({ UInt32(exactly: $0) != nil }) ?? true else {
            throw PacketStorageError.invalidValue("process ID")
        }
        processes = ApplePCAPNGFrameProcesses(
            primary: primary.map { ApplePCAPNGProcess(pid: UInt32($0), name: primaryName) },
            effective: effective.map { ApplePCAPNGProcess(pid: UInt32($0), name: effectiveName) })
    }
    return processes
}

func storedPacket(database: PacketDatabase, artifact: PacketArtifactID, id: PacketRecordID) throws -> PacketRecord? {
    guard id.artifactID == artifact else { throw PacketDomainError.artifactMismatch }
    var packet: PacketRecord?
    try database.rows("SELECT payload FROM packets WHERE frame=?", values: [.integer(try packetStorageInteger(id.frameNumber))]) { row in
        packet = try JSONDecoder().decode(PacketRecord.self, from: row.bytes(0))
    }
    return packet
}

func storedFrameCapturedNames(database: PacketDatabase, id: PacketRecordID) throws -> [CapturedHostnameAssociation] {
    var names: [CapturedHostnameAssociation] = []
    try database.rows("SELECT payload FROM captured_names WHERE frame=?", values: [.integer(try packetStorageInteger(id.frameNumber))]) { row in
        names = try JSONDecoder().decode([CapturedHostnameAssociation].self, from: row.bytes(0))
    }
    return names
}
