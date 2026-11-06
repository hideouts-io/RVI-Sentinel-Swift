import Foundation

private struct PacketSQLPredicate {
    let clause: String
    let values: [PacketSQLValue]
}

func pageStoredPackets(storage: PacketDiskStorage, artifact: PacketArtifactID, query: PacketRecordQuery, page: PacketPageRequest) throws -> PacketPage {
    try validateStoredPage(page)
    return try withPacketDatabase(files: storage.files, access: .read) { database in
        try prepareSelectedPacketIDs(database: database, artifact: artifact, ids: query.recordIDs)
        let predicate = packetSQLPredicate(query)
        let count = predicate.clause.isEmpty ? storage.recordCount : Int(try database.integer("SELECT COUNT(*) FROM packets p \(predicate.clause)", values: predicate.values))
        var records: [PacketRecord] = []
        try database.rows("SELECT p.payload FROM packets p \(predicate.clause) ORDER BY p.seconds,p.nanos,p.frame LIMIT ? OFFSET ?", values: predicate.values + [.integer(Int64(page.limit)), .integer(Int64(page.offset))]) { row in
            records.append(try JSONDecoder().decode(PacketRecord.self, from: row.bytes(0)))
        }
        return PacketPage(records: records, matchingCount: count, nextOffset: storedNextOffset(page: page, count: count, returned: records.count))
    }
}

func pageStoredSessionMembers(storage: PacketDiskStorage, session: PacketSessionKey, page: PacketPageRequest) throws -> PacketPage {
    try validateStoredPage(page)
    let id = try packetSessionStorageID(session)
    return try withPacketDatabase(files: storage.files, access: .read) { database in
        let count = Int(try database.integer("SELECT COUNT(*) FROM packets WHERE session=?", values: [.text(id)]))
        var records: [PacketRecord] = []
        try database.rows("SELECT payload FROM packets WHERE session=? ORDER BY seconds,nanos,frame LIMIT ? OFFSET ?", values: [.text(id), .integer(Int64(page.limit)), .integer(Int64(page.offset))]) { row in
            records.append(try JSONDecoder().decode(PacketRecord.self, from: row.bytes(0)))
        }
        return PacketPage(records: records, matchingCount: count, nextOffset: storedNextOffset(page: page, count: count, returned: records.count))
    }
}

func pageStoredSessions(storage: PacketDiskStorage, artifact: PacketArtifactID, query: PacketRecordQuery, page: PacketPageRequest) throws -> PacketSessionPage {
    try validateStoredPage(page)
    return try withPacketDatabase(files: storage.files, access: .read) { database in
        try prepareSelectedPacketIDs(database: database, artifact: artifact, ids: query.recordIDs)
        let predicate = sessionSQLPredicate(query)
        let count = predicate.clause.isEmpty ? storage.sessionCount : Int(try database.integer("SELECT COUNT(*) FROM sessions s \(predicate.clause)", values: predicate.values))
        var sessions: [PacketSession] = []
        try database.rows("SELECT s.context,s.first_stamp,s.last_stamp,s.packet_count,s.wire_bytes FROM sessions s \(predicate.clause) ORDER BY s.first_seconds,s.first_nanos,s.first_frame LIMIT ? OFFSET ?", values: predicate.values + [.integer(Int64(page.limit)), .integer(Int64(page.offset))]) { row in
            let count = try row.integer(3)
            let bytes = try row.integer(4)
            guard count > 0, bytes >= 0 else { throw PacketStorageError.invalidValue("session accounting") }
            sessions.append(PacketSession(id: try JSONDecoder().decode(PacketSessionKey.self, from: row.bytes(0)),
                firstTimestamp: try JSONDecoder().decode(PacketTimestamp.self, from: row.bytes(1)),
                lastTimestamp: try JSONDecoder().decode(PacketTimestamp.self, from: row.bytes(2)),
                packetCount: Int(count), wireBytes: UInt64(bytes)))
        }
        return PacketSessionPage(sessions: sessions, matchingCount: count, nextOffset: storedNextOffset(page: page, count: count, returned: sessions.count))
    }
}

private func prepareSelectedPacketIDs(database: PacketDatabase, artifact: PacketArtifactID, ids: Set<PacketRecordID>?) throws {
    guard let ids else { return }
    try database.execute("CREATE TEMP TABLE selected_frames(frame INTEGER PRIMARY KEY)", values: [])
    for id in ids where id.artifactID == artifact {
        try database.execute("INSERT INTO selected_frames(frame) VALUES(?)", values: [.integer(try packetStorageInteger(id.frameNumber))])
    }
}

private func packetSQLPredicate(_ query: PacketRecordQuery) -> PacketSQLPredicate {
    var clauses: [String] = []
    var values: [PacketSQLValue] = []
    if query.recordIDs != nil { clauses.append("p.frame IN (SELECT frame FROM selected_frames)") }
    if let transport = query.transport { clauses.append("p.transport=?"); values.append(.text(transport.rawValue)) }
    if let direction = query.direction { clauses.append("p.direction=?"); values.append(.text(direction.rawValue)) }
    if let kind = query.protocolKind {
        clauses.append("EXISTS(SELECT 1 FROM packet_protocols t WHERE t.frame=p.frame AND t.value=?)")
        values.append(.text(kind.rawValue))
    }
    if let interface = query.interfaceName {
        clauses.append("EXISTS(SELECT 1 FROM packet_interfaces t WHERE t.frame=p.frame AND t.value=?)")
        values.append(.text(interface.precomposedStringWithCanonicalMapping))
    }
    if let pid = query.processID {
        clauses.append("EXISTS(SELECT 1 FROM packet_processes t WHERE t.frame=p.frame AND t.value=?)")
        values.append(.integer(Int64(pid)))
    }
    for token in packetStorageSearch(query.text).split(whereSeparator: \.isWhitespace) {
        clauses.append("(instr(p.search,?)>0 OR EXISTS(SELECT 1 FROM captured_names n WHERE n.frame=p.frame AND instr(n.search,?)>0) OR EXISTS(SELECT 1 FROM stream_name_keys k WHERE k.session=p.session AND (k.first_seconds,k.first_nanos,k.first_frame)<(p.seconds,p.nanos,p.frame) AND instr(k.search,?)>0))")
        values.append(contentsOf: [.text(String(token)), .text(String(token)), .text(String(token))])
    }
    return PacketSQLPredicate(clause: clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND "), values: values)
}

private func sessionSQLPredicate(_ query: PacketRecordQuery) -> PacketSQLPredicate {
    var clauses: [String] = []
    var values: [PacketSQLValue] = []
    if query.recordIDs != nil { clauses.append("EXISTS(SELECT 1 FROM packets p WHERE p.session=s.id AND p.frame IN (SELECT frame FROM selected_frames))") }
    if let transport = query.transport {
        clauses.append("EXISTS(SELECT 1 FROM packets p WHERE p.session=s.id AND p.transport=?)")
        values.append(.text(transport.rawValue))
    }
    if let direction = query.direction {
        clauses.append("EXISTS(SELECT 1 FROM packets p WHERE p.session=s.id AND p.direction=?)")
        values.append(.text(direction.rawValue))
    }
    if let kind = query.protocolKind {
        clauses.append("EXISTS(SELECT 1 FROM packets p JOIN packet_protocols t ON t.frame=p.frame WHERE p.session=s.id AND t.value=?)")
        values.append(.text(kind.rawValue))
    }
    if let interface = query.interfaceName {
        clauses.append("EXISTS(SELECT 1 FROM packets p JOIN packet_interfaces t ON t.frame=p.frame WHERE p.session=s.id AND t.value=?)")
        values.append(.text(interface.precomposedStringWithCanonicalMapping))
    }
    if let pid = query.processID {
        clauses.append("EXISTS(SELECT 1 FROM packets p JOIN packet_processes t ON t.frame=p.frame WHERE p.session=s.id AND t.value=?)")
        values.append(.integer(Int64(pid)))
    }
    for token in packetStorageSearch(query.text).split(whereSeparator: \.isWhitespace) {
        clauses.append("(instr(s.search,?)>0 OR EXISTS(SELECT 1 FROM packets p WHERE p.session=s.id AND (instr(p.member_search,?)>0 OR EXISTS(SELECT 1 FROM captured_names n WHERE n.frame=p.frame AND instr(n.search,?)>0))))")
        values.append(contentsOf: [.text(String(token)), .text(String(token)), .text(String(token))])
    }
    return PacketSQLPredicate(clause: clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND "), values: values)
}

private func validateStoredPage(_ page: PacketPageRequest) throws {
    guard page.offset >= 0, (1...1_000).contains(page.limit) else { throw PacketDomainError.invalidPage }
    try Task.checkCancellation()
}

private func storedNextOffset(page: PacketPageRequest, count: Int, returned: Int) -> Int? {
    let (next, overflow) = page.offset.addingReportingOverflow(returned)
    return !overflow && next < count ? next : nil
}
