import Foundation
import Testing
@testable import RVI_Sentinel

struct StoredDNSEvidenceTests {
    @Test func diskDNSMatchesLegacyTTLReplacementNegativeAndFrameOrdering() throws {
        let packets = [
            storedDNSQueryPacket(frame: 1, epoch: "10.000000001", client: "10.0.0.2", interface: "en0"),
            storedDNSAnswerPacket(frame: 2, epoch: "10.000000001", client: "10.0.0.2", interface: "en0"),
            storedDNSFlowPacket(frame: 3, epoch: "10.000000001", client: "10.0.0.2", remote: "192.0.2.10", interface: "en0"),
            storedDNSFlowPacket(frame: 4, epoch: "11", client: "10.0.0.3", remote: "192.0.2.10", interface: "en0"),
            storedDNSFlowPacket(frame: 5, epoch: "11", client: "10.0.0.2", remote: "192.0.2.10", interface: "en1"),
            storedDNSFlowPacket(frame: 6, epoch: "15.000000001", client: "10.0.0.2", remote: "192.0.2.10", interface: "en0"),
            storedDNSAnswerPacket(frame: 7, epoch: "16", client: "10.0.0.2", interface: "en0"),
            storedDNSFlowPacket(frame: 8, epoch: "17", client: "10.0.0.2", remote: "192.0.2.10", interface: "en0"),
            storedDNSFlowPacket(frame: 9, epoch: "17", client: "10.0.0.2", remote: "192.0.2.20", interface: "en0"),
            storedDNSAnswerPacket(frame: 10, epoch: "20", client: "10.0.0.2", interface: "en0"),
            storedDNSFlowPacket(frame: 11, epoch: "20", client: "10.0.0.2", remote: "192.0.2.20", interface: "en0"),
            storedDNSAnswerPacket(frame: 12, epoch: "21", client: "10.0.0.2", interface: "en0"),
            storedDNSFlowPacket(frame: 13, epoch: "22", client: "10.0.0.2", remote: "192.0.2.20", interface: "en0")
        ]
        try withStoredDNSFixture(packets: packets) { database, artifact, records in
            let questions = [storedDNSQuestion("alias.example", type: 1)]
            let response = storedDNSAnswer(packet: records[1], questions: questions, answers: [
                storedDNSAlias("alias.example", target: "target.example", ttl: 5),
                storedDNSAddress("target.example", address: "192.0.2.10", ttl: 60),
                storedDNSAddress("other.example", address: "192.0.2.20", ttl: 30),
                CapturedDNSResourceRecord(owner: "10.2.0.192.in-addr.arpa", recordType: 12, recordClass: 1, ttlSeconds: 30, value: .pointerName("ptr.example")),
                CapturedDNSResourceRecord(owner: "_svc._tcp.local", recordType: 33, recordClass: 1, ttlSeconds: 30, value: .service(target: "host.local", port: 1234, priority: 0, weight: 0))
            ], code: 0, query: 1)
            let messages = [
                storedDNSQuery(packet: records[0], questions: questions), response,
                storedDNSAnswer(packet: records[6], questions: [storedDNSQuestion("target.example", type: 1)], answers: [storedDNSAddress("target.example", address: "192.0.2.20", ttl: 60)], code: 0, query: nil),
                storedDNSAnswer(packet: records[9], questions: [storedDNSQuestion("target.example", type: 1)], answers: [], code: 3, query: nil),
                storedDNSAnswer(packet: records[11], questions: [storedDNSQuestion("other.example", type: 1)], answers: [], code: 0, query: nil)
            ]
            // Ingestion order is deliberately unrelated to packet time or frame order.
            for message in messages.reversed() { try storeDNSMessages(messages: [message], artifact: artifact.id, database: database) }
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            try expectStoredDNSParity(database: database, artifact: artifact.id, records: records, messages: messages)
            let first = try storedDNSPacketNames(database: database, packet: records[2]).filter(\.isInferred)
            #expect(Set(first.map(\.name)) == ["alias.example", "target.example"])
            #expect(first.allSatisfy { $0.supportingPackets.map(\.frameNumber) == [1, 2] })
            #expect(try storedDNSPacketNames(database: database, packet: records[3]).isEmpty)
            #expect(try storedDNSPacketNames(database: database, packet: records[4]).isEmpty)
            #expect(Set(try storedDNSPacketNames(database: database, packet: records[5]).map(\.name)) == ["target.example"])
            #expect(try storedDNSPacketNames(database: database, packet: records[7]).isEmpty)
            #expect(Set(try storedDNSPacketNames(database: database, packet: records[10]).map(\.name)) == ["other.example"])
            #expect(try storedDNSPacketNames(database: database, packet: records[12]).isEmpty)
        }
    }

    @Test func duplicateAnswersAndConvergingChainsDoNotDuplicateBindingsOrRanges() throws {
        try withStoredDNSFixture(packets: [
            storedDNSAnswerPacket(frame: 1, epoch: "1", client: "10.0.0.2", interface: nil),
            storedDNSFlowPacket(frame: 2, epoch: "2", client: "10.0.0.2", remote: "192.0.2.10", interface: nil)
        ]) { database, artifact, records in
            let address = storedDNSAddress("target.example", address: "192.0.2.10", ttl: 50)
            let alias = storedDNSAlias("alias.example", target: "target.example", ttl: 50)
            let answer = storedDNSAnswer(packet: records[0], questions: [storedDNSQuestion("target.example", type: 1)], answers: [
                address, address, alias, alias,
                storedDNSAlias("upper.example", target: "alias.example", ttl: 50),
                storedDNSAlias("upper.example", target: "target.example", ttl: 50)
            ], code: 0, query: nil)
            let messages = [answer, answer]
            try storeDNSMessages(messages: messages, artifact: artifact.id, database: database)
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            try expectStoredDNSParity(database: database, artifact: artifact.id, records: records, messages: messages)
            let expected = try resolveCapturedDNSNames(messages: messages, packets: records, maximumAssociations: Int.max)[records[1].id] ?? []
            #expect(try database.integer("SELECT COUNT(*) FROM dns_bindings", values: []) == Int64(expected.count))
            #expect(try database.integer("SELECT COUNT(*) FROM dns_binding_ranges", values: []) == Int64(expected.count))
            #expect(try database.integer("SELECT COUNT(*) FROM dns_binding_ranges r LEFT JOIN dns_bindings b ON b.id=r.binding_id WHERE b.id IS NULL", values: []) == 0)
        }
    }

    @Test func unicodeScopeOwnerAndReplacementKeysPreserveSwiftEquality() throws {
        try withStoredDNSFixture(packets: [
            storedDNSQueryPacket(frame: 1, epoch: "1", client: "10.0.0.2", interface: "réseau"),
            storedDNSAnswerPacket(frame: 2, epoch: "2", client: "10.0.0.2", interface: "re\u{301}seau"),
            storedDNSFlowPacket(frame: 3, epoch: "3", client: "10.0.0.2", remote: "192.0.2.10", interface: "réseau"),
            storedDNSAnswerPacket(frame: 4, epoch: "4", client: "10.0.0.2", interface: "réseau"),
            storedDNSFlowPacket(frame: 5, epoch: "5", client: "10.0.0.2", remote: "192.0.2.10", interface: "re\u{301}seau")
        ]) { database, artifact, records in
            let messages = [
                storedDNSQuery(packet: records[0], questions: [storedDNSQuestion("café.example", type: 1)]),
                storedDNSAnswer(packet: records[1], questions: [storedDNSQuestion("cafe\u{301}.example", type: 1)], answers: [storedDNSAddress("café.example", address: "192.0.2.10", ttl: 100)], code: 0, query: 1),
                storedDNSAnswer(packet: records[3], questions: [storedDNSQuestion("cafe\u{301}.example", type: 1)], answers: [], code: 3, query: nil)
            ]
            for message in messages { try storeDNSMessages(messages: [message], artifact: artifact.id, database: database) }
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            try expectStoredDNSParity(database: database, artifact: artifact.id, records: records, messages: messages)
            #expect(try storedDNSPacketNames(database: database, packet: records[2]).contains { $0.name == "café.example" && $0.supportingPackets.map(\.frameNumber) == [1, 2] })
            #expect(try storedDNSPacketNames(database: database, packet: records[4]).isEmpty)
        }
    }

    @Test func cyclesTerminateAtTheSame64NameBoundaryAsLegacy() throws {
        for length in [63, 64] {
            try withStoredDNSFixture(packets: [
                storedDNSAnswerPacket(frame: 1, epoch: "1", client: "10.0.0.2", interface: "en0"),
                storedDNSFlowPacket(frame: 2, epoch: "2", client: "10.0.0.2", remote: "192.0.2.10", interface: "en0")
            ]) { database, artifact, records in
                var answers = [storedDNSAddress("node0.example", address: "192.0.2.10", ttl: 100)]
                for index in 1...length { answers.append(storedDNSAlias("node\(index).example", target: "node\(index - 1).example", ttl: 100)) }
                answers.append(storedDNSAlias("node0.example", target: "node\(length).example", ttl: 100))
                let messages = [storedDNSAnswer(packet: records[0], questions: [], answers: answers, code: 0, query: nil)]
                try storeDNSMessages(messages: messages, artifact: artifact.id, database: database)
                if length == 64 {
                    #expect(throws: CapturedDNSError.self) { try indexStoredDNSBindings(database: database, artifact: artifact.id) }
                    #expect(throws: CapturedDNSError.self) { try resolveCapturedDNSNames(messages: messages, packets: records, maximumAssociations: Int.max) }
                } else {
                    try indexStoredDNSBindings(database: database, artifact: artifact.id)
                    try expectStoredDNSParity(database: database, artifact: artifact.id, records: records, messages: messages)
                    #expect(try storedDNSPacketNames(database: database, packet: records[1]).filter(\.isInferred).count == 64)
                }
            }
        }
    }

    @Test func historicalRefreshesUseIntervalCandidatesAndKeepOnlyRealBindings() throws {
        let count = 512
        var packets = (1...count).map { storedDNSAnswerPacket(frame: UInt64($0), epoch: String($0 * 3), client: "10.0.0.2", interface: "en0") }
        packets.append(storedDNSFlowPacket(frame: UInt64(count + 1), epoch: String(count * 3 + 1), client: "10.0.0.2", remote: "192.0.2.10", interface: "en0"))
        try withStoredDNSFixture(packets: packets) { database, artifact, records in
            for record in records.dropLast() {
                let message = storedDNSAnswer(packet: record, questions: [], answers: [
                    storedDNSAddress("target.example", address: "192.0.2.10", ttl: 2),
                    storedDNSAlias("alias.example", target: "target.example", ttl: 2)
                ], code: 0, query: nil)
                try storeDNSMessages(messages: [message], artifact: artifact.id, database: database)
            }
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            #expect(try database.integer("SELECT COUNT(*) FROM dns_bindings", values: []) == Int64(count * 2))
            let names = try storedDNSPacketNames(database: database, packet: #require(records.last))
            #expect(Set(names.map(\.name)) == ["alias.example", "target.example"])
            let ordinal = try database.integer("SELECT position FROM dns_positions WHERE seconds=? AND nanos=0 AND frame=?", values: [.integer(Int64(count * 3)), .integer(Int64(count))])
            let hi = ordinal >> 32
            let lo = (ordinal & 0xffff_ffff) - 2_147_483_648
            #expect(try database.integer("SELECT COUNT(*) FROM dns_alias_index WHERE min_hi<=? AND max_hi>=? AND min_lo<=? AND max_lo>=?", values: [.integer(hi), .integer(hi), .integer(lo), .integer(lo)]) == 1)
            var plan: [String] = []
            try database.rows("EXPLAIN QUERY PLAN SELECT id FROM dns_alias_index WHERE min_hi<=? AND max_hi>=? AND min_lo<=? AND max_lo>=?", values: [.integer(hi), .integer(hi), .integer(lo), .integer(lo)]) { plan.append(try $0.text(3)) }
            #expect(plan.contains { $0.contains("VIRTUAL TABLE INDEX") })
        }
    }

    @Test func exactOrdinalRangesCrossInt32AndInt64BoundariesInRealSQLite() throws {
        let files = try PacketStorageFiles()
        try withPacketDatabase(files: files, access: .write) { database in
            try database.execute("CREATE VIRTUAL TABLE ranges USING rtree_i32(id,min_hi,max_hi,min_lo,max_lo)", values: [])
            let intervals: [(Int64, Int64)] = [(1, 4), (4_294_967_294, 4_294_967_298), (1, 12_884_901_890), (Int64.max - 2, Int64.max)]
            for (first, last) in intervals {
                try database.execute("DELETE FROM ranges", values: [])
                let boxes = storedDNSOrdinalBoxes(first: first, last: last)
                #expect(boxes.count <= 3)
                for (index, box) in boxes.enumerated() {
                    try database.execute("INSERT INTO ranges VALUES(?,?,?,?,?)", values: [.integer(Int64(index + 1))] + box.sqlValues)
                }
                var points: Set<Int64> = [first - 1, first, last]
                if last < Int64.max { points.insert(last + 1) }
                if first < last { points.insert(first + 1); points.insert(last - 1) }
                for point in points {
                    let hi = point >> 32
                    let lo = (point & 0xffff_ffff) - 2_147_483_648
                    let matches = try database.integer("SELECT COUNT(*) FROM ranges WHERE min_hi<=? AND max_hi>=? AND min_lo<=? AND max_lo>=?", values: [.integer(hi), .integer(hi), .integer(lo), .integer(lo)])
                    #expect(matches == ((first...last).contains(point) ? 1 : 0))
                }
            }
        }
    }

    @Test func emptyDNSDoesNotTraversePacketsAndForeignArtifactsAreRejected() throws {
        let files = try PacketStorageFiles()
        let artifact = try storedDNSTestArtifact()
        try withPacketDatabase(files: files, access: .write) { database in
            // There is deliberately no packets table: the zero-DNS path must not visit it.
            try createStoredDNSEvidence(database: database)
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            try appendStoredDNSNames(database: database, artifact: artifact.id)
        }
        try withStoredDNSFixture(packets: [storedDNSAnswerPacket(frame: 1, epoch: "1", client: "10.0.0.2", interface: nil)]) { database, artifact, records in
            let message = storedDNSAnswer(packet: records[0], questions: [], answers: [], code: 0, query: nil)
            try storeDNSMessages(messages: [message], artifact: artifact.id, database: database)
            let foreign = try PacketArtifactID(sha256: String(repeating: "b", count: 64), sourceURL: artifact.id.sourceURL)
            #expect(throws: PacketDomainError.self) { try storeDNSMessages(messages: [message], artifact: foreign, database: database) }
            #expect(try database.integer("SELECT COUNT(*) FROM dns_messages", values: []) == 1)
            try indexStoredDNSBindings(database: database, artifact: artifact.id)
            #expect(throws: PacketStorageError.self) { try storeDNSMessages(messages: [message], artifact: artifact.id, database: database) }
        }
    }

    @Test func cancellationPropagatesThroughTheRealSQLiteIndexer() async throws {
        let task = Task {
            try withStoredDNSFixture(packets: [storedDNSAnswerPacket(frame: 1, epoch: "1", client: "10.0.0.2", interface: nil)]) { database, artifact, records in
                try storeDNSMessages(messages: [storedDNSAnswer(packet: records[0], questions: [], answers: [storedDNSAddress("target.example", address: "192.0.2.10", ttl: 10)], code: 0, query: nil)], artifact: artifact.id, database: database)
                withUnsafeCurrentTask { $0?.cancel() }
                try indexStoredDNSBindings(database: database, artifact: artifact.id)
            }
        }
        do { try await task.value; Issue.record("Cancelled DNS indexing must not report success.") }
        catch is CancellationError { }
    }
}

private func withStoredDNSFixture(packets: [DecodedPacket], operation: (PacketDatabase, PacketCaptureArtifact, [PacketRecord]) throws -> Void) throws {
    let artifact = try storedDNSTestArtifact()
    let files = try PacketStorageFiles()
    try createPacketStorage(files: files)
    let writer = try PacketDiskWriter(files: files, artifact: artifact)
    for packet in packets { try writer.consume(packet: packet) }
    _ = try writer.finish()
    let records = try packets.map { try decodePacketRecord(packet: $0, artifact: artifact) }
    try withPacketDatabase(files: files, access: .write) { database in
        try createStoredDNSEvidence(database: database)
        try operation(database, artifact, records)
    }
}

private func expectStoredDNSParity(database: PacketDatabase, artifact: PacketArtifactID, records: [PacketRecord], messages: [CapturedDNSMessage]) throws {
    let expected = try resolveCapturedHostnames(messages: messages, packets: records, maximumAssociations: Int.max)
    for packet in records { #expect(Set(try storedDNSPacketNames(database: database, packet: packet)) == Set(expected[packet.id] ?? [])) }
    let baseline = CapturedHostnameAssociation(name: "baseline.example", address: nil, supportingPackets: [try #require(records.first).id], validUntil: nil,
        canonicalNameChain: [], provenance: .tlsSNI, isInferred: false, detail: "Existing directly recorded synthetic name.")
    let first = try #require(records.first)
    try storeFrameCapturedNames(database: database, id: first.id, evidence: [baseline])
    try appendStoredDNSNames(database: database, artifact: artifact)
    for packet in records {
        let names = Set(try storedFrameCapturedNames(database: database, id: packet.id))
        let baselineNames: Set<CapturedHostnameAssociation> = packet.id == first.id ? [baseline] : []
        #expect(names == Set(expected[packet.id] ?? []).union(baselineNames))
    }
}

private func storedDNSTestArtifact() throws -> PacketCaptureArtifact {
    PacketCaptureArtifact(id: try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/generated-stored-dns.pcap")), source: .unknown, integrity: .verified)
}

private func storedDNSUDPFields(frame: UInt64, epoch: String, source: String, destination: String, sourcePort: UInt16, destinationPort: UInt16, interface: String?) -> DecodedPacket {
    var values: [TSharkField: [String]] = [
        .frameNumber: [String(frame)], .frameTimeEpoch: [epoch], .frameLength: ["128"], .frameCapturedLength: ["128"], .frameProtocols: ["ip:udp:dns"],
        .ipv4Source: [source], .ipv4Destination: [destination], .udpSourcePort: [String(sourcePort)], .udpDestinationPort: [String(destinationPort)], .udpStream: ["1"]
    ]
    if let interface { values[.frameInterfaceName] = [interface] }
    return DecodedPacket(values: values)
}

private func storedDNSQueryPacket(frame: UInt64, epoch: String, client: String, interface: String?) -> DecodedPacket {
    storedDNSUDPFields(frame: frame, epoch: epoch, source: client, destination: "10.0.0.53", sourcePort: 53000, destinationPort: 53, interface: interface)
}

private func storedDNSAnswerPacket(frame: UInt64, epoch: String, client: String, interface: String?) -> DecodedPacket {
    storedDNSUDPFields(frame: frame, epoch: epoch, source: "10.0.0.53", destination: client, sourcePort: 53, destinationPort: 53000, interface: interface)
}

private func storedDNSFlowPacket(frame: UInt64, epoch: String, client: String, remote: String, interface: String?) -> DecodedPacket {
    storedDNSUDPFields(frame: frame, epoch: epoch, source: client, destination: remote, sourcePort: 54000, destinationPort: 443, interface: interface)
}

private func storedDNSQuestion(_ name: String, type: UInt16) -> CapturedDNSQuestion { CapturedDNSQuestion(name: name, recordType: type, recordClass: 1) }
private func storedDNSAddress(_ owner: String, address: String, ttl: UInt32) -> CapturedDNSResourceRecord {
    CapturedDNSResourceRecord(owner: owner, recordType: 1, recordClass: 1, ttlSeconds: ttl, value: .ipv4(address))
}
private func storedDNSAlias(_ owner: String, target: String, ttl: UInt32) -> CapturedDNSResourceRecord {
    CapturedDNSResourceRecord(owner: owner, recordType: 5, recordClass: 1, ttlSeconds: ttl, value: .canonicalName(target))
}
private func storedDNSQuery(packet: PacketRecord, questions: [CapturedDNSQuestion]) -> CapturedDNSMessage {
    CapturedDNSMessage(packetID: packet.id, transactionID: 7, isResponse: false, isTruncated: false, responseCode: 0, questions: questions, responseToFrame: nil, answers: [], unsupportedRecordTypes: [])
}
private func storedDNSAnswer(packet: PacketRecord, questions: [CapturedDNSQuestion], answers: [CapturedDNSResourceRecord], code: UInt16, query: UInt64?) -> CapturedDNSMessage {
    CapturedDNSMessage(packetID: packet.id, transactionID: 7, isResponse: true, isTruncated: false, responseCode: code, questions: questions, responseToFrame: query, answers: answers, unsupportedRecordTypes: [])
}
