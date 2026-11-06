import Foundation
import SQLite3
import XCTest
@testable import RVI_Sentinel

final class PacketDiskStoreTests: XCTestCase {
    func testDiskIndexPagesAndFiltersEveryMemberWithoutRetainingLargeArrays() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in 1...2_005 { try writer.consume(packet: diskTestPacket(frame: UInt64(frame), epoch: String(frame))) }
        let result = try writer.finish()
        XCTAssertEqual(result.recordCount, 2_005)
        XCTAssertEqual(result.sessionCount, 1)
        XCTAssertTrue(result.records.isEmpty)
        XCTAssertTrue(result.sessions.isEmpty)
        let query = diskTestQuery(text: "MAILd 192.0.2.2")
        let first = try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(first.matchingCount, 2_005)
        XCTAssertEqual(first.records.first?.id.frameNumber, 1)
        XCTAssertEqual(first.nextOffset, 100)
        let last = try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 2_000, limit: 100))
        XCTAssertEqual(last.records.map(\.id.frameNumber), [2_001, 2_002, 2_003, 2_004, 2_005])
        XCTAssertNil(last.nextOffset)
        let sessions = try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        let session = try XCTUnwrap(sessions.sessions.first)
        XCTAssertEqual(session.packetCount, 2_005)
        XCTAssertEqual(session.wireBytes, 2_005 * 128)
        XCTAssertTrue(session.packetIDs.isEmpty)
        let members = try pagePacketSessionMembers(result: result, session: session.id, page: PacketPageRequest(offset: 2_000, limit: 100))
        XCTAssertEqual(members.matchingCount, 2_005)
        XCTAssertEqual(members.records, last.records)
        XCTAssertEqual(try pagePacketRecords(result: result, query: diskTestQuery(text: "' OR 1=1 --"), page: PacketPageRequest(offset: 0, limit: 100)).matchingCount, 0)
        let selected = Set(last.records.map(\.id))
        let focused = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: selected)
        XCTAssertEqual(try pagePacketRecords(result: result, query: focused, page: PacketPageRequest(offset: 0, limit: 100)).records, last.records)
        XCTAssertThrowsError(try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: -1, limit: 100)))
    }

    func testManySessionDiskQueryPerformance() throws {
        guard ProcessInfo.processInfo.environment["RVI_SENTINEL_RUN_PACKET_PERFORMANCE"] == "1" else {
            throw XCTSkip("Set RVI_SENTINEL_RUN_PACKET_PERFORMANCE=1 to measure generated many-session disk queries.")
        }
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in 1...5_000 {
            let stream = (frame - 1) / 10
            var values = diskTestPacket(frame: UInt64(frame), epoch: String(frame)).values
            values[.tcpStream] = [String(stream)]
            values[.tcpSourcePort] = [String(50_000 + stream)]
            if frame == 5_000 { values[.frameProtocols] = ["ip:tcp:rareprobe"] }
            try writer.consume(packet: DecodedPacket(values: values))
        }
        let result = try writer.finish()
        XCTAssertEqual(result.recordCount, 5_000)
        XCTAssertEqual(result.sessionCount, 500)
        XCTAssertTrue(result.records.isEmpty)
        XCTAssertTrue(result.sessions.isEmpty)

        let unfiltered = diskUnfilteredQuery()
        let first = try pagePacketSessions(result: result, query: unfiltered, names: [:], page: PacketPageRequest(offset: 0, limit: 1))
        let last = try pagePacketSessions(result: result, query: unfiltered, names: [:], page: PacketPageRequest(offset: 499, limit: 1))
        XCTAssertEqual(first.matchingCount, 500)
        XCTAssertEqual(first.sessions.first?.packetCount, 10)
        let firstSession = try XCTUnwrap(first.sessions.first)
        XCTAssertEqual(try pagePacketSessionMembers(result: result, session: firstSession.id, page: PacketPageRequest(offset: 0, limit: 10)).records.map(\.id.frameNumber), Array(UInt64(1)...10))
        let lastSession = try XCTUnwrap(last.sessions.first)
        XCTAssertEqual(last.matchingCount, 500)
        XCTAssertEqual(lastSession.packetCount, 10)
        let rare = diskTestQuery(text: "rareprobe")
        let packet = try pagePacketRecords(result: result, query: rare, page: PacketPageRequest(offset: 0, limit: 1))
        XCTAssertEqual(packet.matchingCount, 1)
        XCTAssertEqual(packet.records.first?.id.frameNumber, 5_000)
        let matchingSession = try pagePacketSessions(result: result, query: rare, names: [:], page: PacketPageRequest(offset: 0, limit: 1))
        XCTAssertEqual(matchingSession.matchingCount, 1)
        XCTAssertEqual(matchingSession.sessions.first?.id, lastSession.id)
        let members = try pagePacketSessionMembers(result: result, session: lastSession.id, page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(members.matchingCount, 10)
        XCTAssertEqual(members.records.map(\.id.frameNumber), Array(UInt64(4_991)...5_000))
        XCTAssertEqual(try pagePacketRecords(result: result, query: diskTestQuery(text: "absentprobe"), page: PacketPageRequest(offset: 0, limit: 1)).matchingCount, 0)
        XCTAssertEqual(try pagePacketSessions(result: result, query: diskTestQuery(text: "absentprobe"), names: [:], page: PacketPageRequest(offset: 0, limit: 1)).matchingCount, 0)

        let clock = ContinuousClock()
        var packetMilliseconds: [Double] = []
        var sessionMilliseconds: [Double] = []
        var memberMilliseconds: [Double] = []
        for _ in 0..<20 {
            let packetStart = clock.now
            let packetPage = try pagePacketRecords(result: result, query: rare, page: PacketPageRequest(offset: 0, limit: 1))
            packetMilliseconds.append(diskTestMilliseconds(packetStart.duration(to: clock.now)))
            XCTAssertEqual(packetPage.records.first?.id.frameNumber, 5_000)
            let sessionStart = clock.now
            let sessionPage = try pagePacketSessions(result: result, query: rare, names: [:], page: PacketPageRequest(offset: 0, limit: 1))
            sessionMilliseconds.append(diskTestMilliseconds(sessionStart.duration(to: clock.now)))
            XCTAssertEqual(sessionPage.sessions.first?.id, lastSession.id)
            let memberStart = clock.now
            let memberPage = try pagePacketSessionMembers(result: result, session: lastSession.id, page: PacketPageRequest(offset: 0, limit: 10))
            memberMilliseconds.append(diskTestMilliseconds(memberStart.duration(to: clock.now)))
            XCTAssertEqual(memberPage.records.count, 10)
        }
        let observation = DiskManySessionObservation(recordCount: result.recordCount, sessionCount: result.sessionCount,
            sampleCount: packetMilliseconds.count, packetFilterP95Milliseconds: diskTestP95(packetMilliseconds),
            sessionFilterP95Milliseconds: diskTestP95(sessionMilliseconds), sessionMembersP95Milliseconds: diskTestP95(memberMilliseconds))
        let encoded = try JSONEncoder().encode(observation)
        let attachment = XCTAttachment(data: encoded, uniformTypeIdentifier: "public.json")
        attachment.name = "Generated many-session disk query performance"
        attachment.lifetime = .keepAlways
        add(attachment)
        print(String(decoding: encoded, as: UTF8.self))
        XCTAssertLessThanOrEqual(observation.packetFilterP95Milliseconds, 300)
        XCTAssertLessThanOrEqual(observation.sessionFilterP95Milliseconds, 300)
        XCTAssertLessThanOrEqual(observation.sessionMembersP95Milliseconds, 300)
    }

    func testDiskOrderRetainsExactEpochsAndSessionExtremaFromOutOfOrderInput() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for (frame, epoch) in [(UInt64(1), "2.000000002"), (2, "1.999999999"), (3, "2.000000001")] {
            try writer.consume(packet: diskTestPacket(frame: frame, epoch: epoch))
        }
        let result = try writer.finish()
        let page = try pagePacketRecords(result: result, query: diskTestQuery(text: ""), page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(page.records.map(\.id.frameNumber), [2, 3, 1])
        XCTAssertEqual(page.records.map(\.timestamp.originalText), ["1.999999999", "2.000000001", "2.000000002"])
        let sessions = try pagePacketSessions(result: result, query: diskTestQuery(text: ""), names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(sessions.sessions.first?.firstTimestamp.originalText, "1.999999999")
        XCTAssertEqual(sessions.sessions.first?.lastTimestamp.originalText, "2.000000002")
        XCTAssertEqual(sessions.sessions.first?.packetCount, 3)
    }

    func testCanonicalUnicodeMetadataKeepsOneSessionAndEquivalentFilters() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in UInt64(1)...2 {
            var values = diskTestPacket(frame: frame, epoch: String(frame)).values
            values[.frameInterfaceName] = [frame == 1 ? "caf\u{e9}" : "cafe\u{301}"]
            values[.darwinProcessName] = [frame == 1 ? "m\u{e9}ta" : "me\u{301}ta"]
            try writer.consume(packet: DecodedPacket(values: values))
        }
        let result = try writer.finish()
        XCTAssertEqual(result.sessionCount, 1)
        let sessions = try pagePacketSessions(result: result, query: diskUnfilteredQuery(), names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        let session = try XCTUnwrap(sessions.sessions.first)
        XCTAssertEqual(session.packetCount, 2)
        XCTAssertEqual(try pagePacketSessionMembers(result: result, session: session.id, page: PacketPageRequest(offset: 0, limit: 100)).records.count, 2)
        let query = PacketRecordQuery(text: "M\u{c9}TA", transport: nil, protocolKind: nil, interfaceName: "cafe\u{301}", processID: nil, direction: nil, recordIDs: nil)
        let page = try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(page.matchingCount, 2)
        XCTAssertEqual(Array(try XCTUnwrap(page.records.last?.interface.name).utf8), Array("cafe\u{301}".utf8))
        let filteredSessions = try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(filteredSessions.matchingCount, 1)
        XCTAssertEqual(filteredSessions.sessions.first?.packetCount, 2)
    }

    func testStoredNameEvidenceRemainsSearchableAndDoesNotChangeRecordedFields() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in UInt64(1)...3 { try writer.consume(packet: diskTestPacket(frame: frame, epoch: String(frame))) }
        let result = try writer.finish()
        let storage = try XCTUnwrap(result.diskStorage)
        try indexStoredHostnameEvidence(storage: storage, artifact: artifact.id, messages: [])
        let page = try pagePacketRecords(result: result, query: diskTestQuery(text: "service.example"), page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(page.records.map(\.id.frameNumber), [1, 2, 3])
        let last = try XCTUnwrap(page.records.last)
        XCTAssertTrue(last.recordedNames.isEmpty)
        let evidence = try capturedPacketNames(result: result, packet: last.id, names: [:])
        XCTAssertTrue(evidence.contains { $0.name == "service.example" && $0.isInferred && $0.supportingPackets.map(\.frameNumber) == [1] })
        let sessions = try pagePacketSessions(result: result, query: diskTestQuery(text: "service.example"), names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(sessions.matchingCount, 1)
    }

    func testStreamNameHistoryStoresObservationsOnceAndQueriesPriorContext() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in UInt64(1)...500 {
            var values = diskTestPacket(frame: frame, epoch: String(frame)).values
            values[.http2Authority] = ["name-\(frame).example"]
            try writer.consume(packet: DecodedPacket(values: values))
        }
        let result = try writer.finish()
        try withPacketDatabase(files: files, access: .read) { database in
            XCTAssertEqual(try database.integer("SELECT COUNT(*) FROM stream_name_keys", values: []), 501)
            XCTAssertEqual(try database.integer("SELECT COUNT(*) FROM stream_name_observations", values: []), 501)
            XCTAssertEqual(try database.integer("SELECT COUNT(*) FROM captured_names", values: []), 500)
        }
        let id = PacketRecordID(artifactID: artifact.id, frameNumber: 500)
        let names = try capturedPacketNames(result: result, packet: id, names: [:])
        XCTAssertEqual(names.count, 501)
        XCTAssertTrue(names.contains { $0.name == "name-499.example" && $0.isInferred && $0.supportingPackets.map(\.frameNumber) == [499] })
        XCTAssertTrue(names.contains { $0.name == "name-500.example" && !$0.isInferred })
        let page = try pagePacketRecords(result: result, query: diskTestQuery(text: "name-499.example"), page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(page.records.map(\.id.frameNumber), [499, 500])
        let sessions = try pagePacketSessions(result: result, query: diskTestQuery(text: "name-499.example"), names: [:], page: PacketPageRequest(offset: 0, limit: 100))
        XCTAssertEqual(sessions.matchingCount, 1)
    }

    func testEquivalentStreamNamesUseLatestSupportingObservationWithoutRewritingIt() throws {
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        for frame in UInt64(1)...3 {
            var values = diskTestPacket(frame: frame, epoch: String(frame)).values
            values[.tlsSNI] = frame == 1 ? ["caf\u{e9}.example"] : frame == 2 ? ["cafe\u{301}.example"] : []
            try writer.consume(packet: DecodedPacket(values: values))
        }
        let result = try writer.finish()
        try withPacketDatabase(files: files, access: .read) { database in
            XCTAssertEqual(try database.integer("SELECT COUNT(*) FROM stream_name_keys", values: []), 1)
            XCTAssertEqual(try database.integer("SELECT COUNT(*) FROM stream_name_observations", values: []), 2)
        }
        let evidence = try capturedPacketNames(result: result, packet: PacketRecordID(artifactID: artifact.id, frameNumber: 3), names: [:])
        let latest = try XCTUnwrap(evidence.first)
        XCTAssertEqual(evidence.count, 1)
        XCTAssertEqual(latest.supportingPackets.map(\.frameNumber), [2])
        XCTAssertEqual(Array(latest.name.utf8), Array("cafe\u{301}.example".utf8))
        for spelling in ["caf\u{e9}.example", "cafe\u{301}.example"] {
            let page = try pagePacketRecords(result: result, query: diskTestQuery(text: spelling), page: PacketPageRequest(offset: 0, limit: 100))
            XCTAssertEqual(page.records.map(\.id.frameNumber), [1, 2, 3])
        }
    }

    func testPrivateStorePermissionsCleanupAndDiskFullFailure() throws {
        let releasedDirectory = try createAndReleaseDiskTestStore()
        XCTAssertFalse(FileManager.default.fileExists(atPath: releasedDirectory.path))
        let artifact = try diskTestArtifact()
        let files = try PacketStorageFiles()
        let attributes = try FileManager.default.attributesOfItem(atPath: files.directory.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: files.database.path)
        XCTAssertEqual((fileAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        try createPacketStorage(files: files)
        let writer = try PacketDiskWriter(files: files, artifact: artifact)
        let pages = try writer.database.integer("PRAGMA page_count", values: [])
        try writer.database.execute("PRAGMA max_page_count=\(pages + 1)", values: [])
        XCTAssertThrowsError(try {
            for frame in UInt64(1)...100 { try writer.consume(packet: diskTestPacket(frame: frame, epoch: String(frame))) }
        }()) { error in
            guard case let PacketStorageError.database(_, code) = error else { return XCTFail("Expected an explicit SQLite storage failure: \(error)") }
            XCTAssertEqual(code, SQLITE_FULL)
        }
    }

    func testSuppliedLargeCaptureKeepsEveryFrameQueryable() async throws {
        guard let path = ProcessInfo.processInfo.environment["RVI_SENTINEL_LARGE_CAPTURE"], !path.isEmpty else {
            throw XCTSkip("Set RVI_SENTINEL_LARGE_CAPTURE to an authorized local capture for large-file validation.")
        }
        let url = URL(fileURLWithPath: path)
        let digest = try hashCaptureBytes(url: url, maximumBytes: Int64.max, deadline: ContinuousClock().now + .seconds(120))
        let result = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: url, progress: { _ in })
        let packets = try XCTUnwrap(result.packetAnalysis)
        XCTAssertGreaterThan(packets.recordCount, 200_000)
        XCTAssertEqual(packets.recordCount, result.summary.packetCount)
        XCTAssertTrue(packets.records.isEmpty)
        XCTAssertTrue(packets.sessions.isEmpty)
        for offset in [0, packets.recordCount / 2, packets.recordCount - 1] {
            let page = try pagePacketRecords(result: packets, query: diskUnfilteredQuery(), page: PacketPageRequest(offset: offset, limit: 1))
            XCTAssertEqual(page.matchingCount, packets.recordCount)
            XCTAssertEqual(page.records.count, 1)
        }
        let page = try pagePacketSessions(result: packets, query: diskUnfilteredQuery(), names: [:], page: PacketPageRequest(offset: 0, limit: 1))
        let session = try XCTUnwrap(page.sessions.first)
        let members = try pagePacketSessionMembers(result: packets, session: session.id, page: PacketPageRequest(offset: max(0, session.packetCount - 1), limit: 1))
        XCTAssertEqual(members.matchingCount, session.packetCount)
        XCTAssertEqual(members.records.count, 1)
        XCTAssertEqual(result.summary.captureSHA256, digest)
        XCTAssertEqual(try hashCaptureBytes(url: url, maximumBytes: Int64.max, deadline: ContinuousClock().now + .seconds(120)), digest)
        XCTAssertFalse(result.coverage.activeResolutionEnabled)
        print("Large saved capture validated: \(packets.recordCount) frames, \(packets.sessionCount) sessions.")
    }
}

private func diskTestArtifact() throws -> PacketCaptureArtifact {
    PacketCaptureArtifact(id: try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/generated-disk-index.pcapng")), source: .unknown, integrity: .verified)
}

private func diskTestPacket(frame: UInt64, epoch: String) -> DecodedPacket {
    var values: [TSharkField: [String]] = [
        .frameNumber: [String(frame)], .frameTimeEpoch: [epoch], .frameLength: ["128"], .frameProtocols: ["ip:tcp"],
        .frameInterfaceName: ["fixture0"], .ipv4Source: ["192.0.2.1"], .ipv4Destination: ["192.0.2.2"],
        .tcpSourcePort: ["50000"], .tcpDestinationPort: ["443"], .tcpStream: ["1"],
        .darwinProcessID: ["343"], .darwinProcessName: ["maild"], .framePacketDirection: ["2"]
    ]
    if frame == 1 { values[.tlsSNI] = ["service.example"] }
    return DecodedPacket(values: values)
}

private func diskTestQuery(text: String) -> PacketRecordQuery {
    PacketRecordQuery(text: text, transport: .tcp, protocolKind: .tcp, interfaceName: "fixture0", processID: 343, direction: .outbound, recordIDs: nil)
}

private func diskUnfilteredQuery() -> PacketRecordQuery {
    PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: nil)
}

private func createAndReleaseDiskTestStore() throws -> URL {
    let files = try PacketStorageFiles()
    try createPacketStorage(files: files)
    return files.directory
}

private struct DiskManySessionObservation: Encodable {
    let recordCount: Int
    let sessionCount: Int
    let sampleCount: Int
    let packetFilterP95Milliseconds: Double
    let sessionFilterP95Milliseconds: Double
    let sessionMembersP95Milliseconds: Double
}

private func diskTestMilliseconds(_ duration: Duration) -> Double {
    Double(duration.components.seconds) * 1_000 + Double(duration.components.attoseconds) / 1_000_000_000_000_000
}

private func diskTestP95(_ values: [Double]) -> Double {
    let ordered = values.sorted()
    return ordered[Int(ceil(Double(ordered.count) * 0.95)) - 1]
}
