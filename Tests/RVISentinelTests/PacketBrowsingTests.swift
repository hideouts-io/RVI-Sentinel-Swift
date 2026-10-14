import XCTest
@testable import RVI_Sentinel

final class PacketBrowsingTests: XCTestCase {
    func testPacketFiltersCombineRecordedProcessDirectionAndEndpoint() throws {
        let result = try browsingPacketResult()
        let query = PacketRecordQuery(text: "maild 192.0.2.2", transport: .tcp, protocolKind: .tcp, interfaceName: "en2", processID: 343, direction: .outbound, recordIDs: nil)
        let page = try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(page.records.map { $0.id.frameNumber }, [1])
        XCTAssertEqual(page.matchingCount, 1)
        XCTAssertNil(page.nextOffset)
    }

    func testSessionPagingKeepsChronologicalGroupsAndNavigationMembership() throws {
        let result = try browsingPacketResult()
        let all = browsingQuery(text: "")
        let first = try pagePacketSessions(result: result, query: all, names: [:], page: PacketPageRequest(offset: 0, limit: 1))
        XCTAssertEqual(first.matchingCount, 3)
        XCTAssertEqual(first.nextOffset, 1)
        XCTAssertEqual(first.sessions.first?.packetCount, 2)
        let second = try pagePacketSessions(result: result, query: all, names: [:], page: PacketPageRequest(offset: 1, limit: 1))
        XCTAssertEqual(second.sessions.first?.transport, .udp)
        XCTAssertEqual(second.sessions.first?.stream, 7)
        XCTAssertEqual(second.nextOffset, 2)
        let last = try pagePacketSessions(result: result, query: all, names: [:], page: PacketPageRequest(offset: 2, limit: 10))
        XCTAssertEqual(last.sessions.first?.interface.name, "pdp_ip0")
        XCTAssertNil(last.nextOffset)
        let memberIDs = try XCTUnwrap(first.sessions.first?.packetIDs)
        let focused = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: Set(memberIDs))
        let records = try pagePacketRecords(result: result, query: focused, page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(records.records.map(\.id), memberIDs)
    }

    func testCapturedHostnameFilterRemainsArtifactAndPacketScoped() throws {
        let result = try browsingPacketResult()
        let record = try XCTUnwrap(result.records.first { $0.id.frameNumber == 3 })
        let association = CapturedHostnameAssociation(name: "service.example", address: "192.0.2.2", supportingPackets: [record.id], validUntil: try decodePacketTimestamp("60"), canonicalNameChain: ["service.example"], provenance: .capturedDNSAnswer, isInferred: true, detail: "Generated boundary association; DNS decoding is tested separately.")
        let names = [record.id: [association]]
        let query = browsingQuery(text: "service.example")
        let packetPage = try pagePacketRecords(result: result, query: query, names: names, page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(packetPage.records.map { $0.id.frameNumber }, [3])
        let sessionPage = try pagePacketSessions(result: result, query: query, names: names, page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(sessionPage.sessions.first?.stream, 7)
        XCTAssertEqual(sessionPage.matchingCount, 1)
        XCTAssertTrue(result.records.allSatisfy { !$0.recordedNames.contains(where: { $0.value == "service.example" }) })
        let foreignArtifact = try PacketArtifactID(sha256: String(repeating: "b", count: 64), sourceURL: result.artifact.id.sourceURL)
        let foreignID = PacketRecordID(artifactID: foreignArtifact, frameNumber: record.id.frameNumber)
        XCTAssertEqual(try pagePacketRecords(result: result, query: query, names: [foreignID: [association]], page: PacketPageRequest(offset: 0, limit: 10)).matchingCount, 0)
        XCTAssertEqual(try pagePacketSessions(result: result, query: query, names: [foreignID: [association]], page: PacketPageRequest(offset: 0, limit: 10)).matchingCount, 0)
    }

    func testSessionProcessAndFocusedRecordFiltersRespectEffectiveMetadata() throws {
        let result = try browsingPacketResult()
        let effective = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: 7, direction: nil, recordIDs: nil)
        let selected = try pagePacketSessions(result: result, query: effective, names: [:], page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(selected.matchingCount, 1)
        XCTAssertEqual(selected.sessions.first?.effectiveProcess.processID, 7)
        let frame = try XCTUnwrap(result.records.first { $0.id.frameNumber == 3 })
        let focused = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: [frame.id])
        let page = try pagePacketSessions(result: result, query: focused, names: [:], page: PacketPageRequest(offset: 0, limit: 10))
        XCTAssertEqual(page.matchingCount, 1)
        XCTAssertEqual(page.sessions.first?.stream, 7)
    }

    func testDirectPacketNameSearchAndInvalidPages() throws {
        let result = try browsingPacketResult()
        let query = browsingQuery(text: "mail.example")
        XCTAssertEqual(try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: 0, limit: 10)).matchingCount, 1)
        XCTAssertEqual(try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 0, limit: 10)).records.first?.id.frameNumber, 1)
        XCTAssertThrowsError(try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: -1, limit: 10)))
        XCTAssertThrowsError(try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: 0, limit: 1_001)))
        XCTAssertEqual(try pagePacketSessions(result: result, query: query, names: [:], page: PacketPageRequest(offset: Int.max, limit: 1)).sessions.count, 0)
    }
}

private func browsingQuery(text: String) -> PacketRecordQuery {
    PacketRecordQuery(text: text, transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: nil)
}

private func browsingPacketResult() throws -> PacketAnalysisResult {
    let id = try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/browsing-generated.pcapng"))
    let artifact = PacketCaptureArtifact(id: id, source: .unknown, integrity: .verified)
    var index = try PacketIndexAccumulator(artifact: artifact, limits: PacketIndexLimits(maximumRecords: 10, maximumEstimatedBytes: 100_000))
    for frame in UInt64(1)...4 {
        var values: [TSharkField: [String]] = [
            .frameNumber: [String(frame)], .frameTimeEpoch: [String(frame)], .frameLength: ["128"],
            .frameProtocols: ["ip:tcp"], .frameInterfaceName: ["en2"],
            .ipv4Source: ["192.0.2.1"], .ipv4Destination: ["192.0.2.2"],
            .tcpSourcePort: ["50000"], .tcpDestinationPort: ["443"], .tcpStream: ["3"],
            .darwinProcessID: ["343"], .darwinProcessName: ["maild"], .framePacketDirection: ["2"]
        ]
        if frame == 1 { values[.tlsSNI] = ["mail.example"] }
        if frame == 2 {
            values[.ipv4Source] = ["192.0.2.2"]
            values[.ipv4Destination] = ["192.0.2.1"]
            values[.tcpSourcePort] = ["443"]
            values[.tcpDestinationPort] = ["50000"]
            values[.framePacketDirection] = ["1"]
        }
        if frame == 3 {
            values[.frameProtocols] = ["ip:udp"]
            values[.tcpSourcePort] = nil
            values[.tcpDestinationPort] = nil
            values[.tcpStream] = nil
            values[.udpSourcePort] = ["50000"]
            values[.udpDestinationPort] = ["5353"]
            values[.udpStream] = ["7"]
            values[.darwinProcessID] = ["344"]
            values[.darwinProcessName] = ["mobile_assertion"]
        }
        if frame == 4 {
            values[.frameInterfaceName] = ["pdp_ip0"]
            values[.tcpStream] = ["11"]
            values[.darwinEffectiveProcessID] = ["7"]
            values[.darwinEffectiveProcessName] = ["networkd"]
        }
        try index.consume(packet: DecodedPacket(values: values))
    }
    return try index.result()
}
