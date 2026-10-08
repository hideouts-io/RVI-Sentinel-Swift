import XCTest
@testable import RVI_Sentinel

final class PacketFoundationTests: XCTestCase {
    func testTimestampPreservesNanosecondsAndNegativeEpochOrdering() throws {
        let near = try decodePacketTimestamp("1791428448.590385001")
        let later = try decodePacketTimestamp("1791428448.590385002")
        XCTAssertEqual(near.epochSeconds, 1_791_428_448)
        XCTAssertEqual(near.nanoseconds, 590_385_001)
        XCTAssertEqual(near.originalText, "1791428448.590385001")
        XCTAssertLessThan(near, later)
        let negative = try decodePacketTimestamp("-0.000000001")
        XCTAssertEqual(negative.epochSeconds, -1)
        XCTAssertEqual(negative.nanoseconds, 999_999_999)
        XCTAssertLessThan(negative, try decodePacketTimestamp("0.0"))
        XCTAssertEqual(try decodePacketTimestamp("-1.25").epochSeconds, -2)
        XCTAssertEqual(try decodePacketTimestamp("-1.25").nanoseconds, 750_000_000)
        XCTAssertEqual(try decodePacketTimestamp("1.0"), try decodePacketTimestamp("1.000"))
        for invalid in ["", ".1", "1.", "+1.0", "1.0000000001", "1e3", "1.nan", "-9223372036854775808.1", "1.٢"] {
            XCTAssertThrowsError(try decodePacketTimestamp(invalid), invalid)
        }
    }

    func testRecordedMetadataKeepsSourceConflictsAndDoesNotPromoteUnknownCapture() throws {
        let artifact = try foundationArtifact(source: .unknown, hashDigit: "a")
        var values = foundationPacketValues(frame: 1, timestamp: "1.0")
        values[.darwinProcessID] = ["343"]
        values[.darwinProcessName] = ["maild"]
        values[.pktapProcessID] = ["987"]
        values[.pktapProcessName] = ["mobile_assertion"]
        values[.darwinEffectiveProcessID] = ["0"]
        values[.framePacketDirection] = ["2"]
        values[.pktapFlags] = ["0x00000001"]
        let record = try decodePacketRecord(packet: DecodedPacket(values: values), artifact: artifact)
        XCTAssertEqual(artifact.source, .unknown)
        XCTAssertEqual(record.process.state, .conflict)
        XCTAssertNil(record.process.name)
        XCTAssertEqual(Set(record.process.labels.map(\.source)), [.applePCAPNG, .pktapHeader])
        XCTAssertEqual(record.effectiveProcess.state, .unknown)
        XCTAssertNil(record.effectiveProcess.processID)
        XCTAssertEqual(record.direction.state, .conflict)
        XCTAssertTrue(record.diagnostics.contains(.processMetadataConflict))
        XCTAssertNil(packetSessionKey(record: record, source: artifact.source))
        values[.pktapProcessID] = ["343"]
        values[.pktapProcessName] = ["maild"]
        values[.pktapFlags] = ["0x00000002"]
        let agreeing = try decodePacketRecord(packet: DecodedPacket(values: values), artifact: artifact)
        XCTAssertEqual(agreeing.process.state, .recorded)
        XCTAssertEqual(agreeing.process.name, "maild")
        XCTAssertEqual(agreeing.process.processID, 343)
        XCTAssertEqual(agreeing.direction.direction, .outbound)
    }

    func testMetadataFreePacketsAndDirectNamesRemainExplicit() throws {
        var values = foundationPacketValues(frame: 1, timestamp: "1")
        values[.frameInterfaceName] = nil
        values[.dnsQueryName] = ["_companion-link._tcp.local"]
        values[.certificateDNSName] = ["unpaired.example"]
        values[.tcpFlags] = ["0x0012"]
        values[.tcpSequenceRaw] = ["4294967295"]
        values[.tcpAcknowledgmentRaw] = ["7"]
        values[.frameCapturedLength] = ["48"]
        let record = try decodePacketRecord(packet: DecodedPacket(values: values), artifact: foundationArtifact(source: .userDeclaredRVI, hashDigit: "b"))
        XCTAssertEqual(record.process.state, .unknown)
        XCTAssertEqual(record.interface.state, .unknown)
        XCTAssertEqual(record.direction.direction, .unknown)
        XCTAssertEqual(record.tcp?.sequenceRaw, UInt32.max)
        XCTAssertEqual(record.tcp?.isSYN, true)
        XCTAssertEqual(record.tcp?.isACK, true)
        XCTAssertEqual(record.capturedLength, 48)
        XCTAssertEqual(record.recordedNames.map(\.field), [.dnsQueryName, .certificateDNSName])
        XCTAssertEqual(record.recordedNames.map(\.value), ["_companion-link._tcp.local", "unpaired.example"])
    }

    func testTypedFieldValidationAndLayerAmbiguity() throws {
        let artifact = try foundationArtifact(source: .userDeclaredRVI, hashDigit: "b")
        let invalidFields: [(TSharkField, String)] = [
            (.ipv4Source, "999.0.0.1"), (.tcpSourcePort, "65536"), (.tcpStream, "-1"), (.tcpStream, "4294967296"),
            (.tcpSequenceRaw, "4294967296"), (.tcpFlags, "0x10000"), (.frameLength, "-10"),
            (.frameCapturedLength, "129"), (.darwinProcessID, "2147483648")
        ]
        for (field, text) in invalidFields {
            var values = foundationPacketValues(frame: 1, timestamp: "1")
            values[field] = [text]
            XCTAssertThrowsError(try decodePacketRecord(packet: DecodedPacket(values: values), artifact: artifact), field.rawValue)
        }
        var values = foundationPacketValues(frame: 1, timestamp: "1")
        values[.ipv4Source] = ["192.0.2.1", "192.0.2.1"]
        let ambiguous = try decodePacketRecord(packet: DecodedPacket(values: values), artifact: artifact)
        XCTAssertTrue(ambiguous.diagnostics.contains(.ambiguousNetworkLayers))
        XCTAssertNil(ambiguous.sourceAddress)
        XCTAssertNil(packetSessionKey(record: ambiguous, source: artifact.source))
        XCTAssertEqual(try packetIPAddress("2001:0DB8:0:0:0:0:0:1").rawValue, "2001:db8::1")
    }

    func testSessionGroupingIsBidirectionalAndScopedByMetadataAndArtifact() throws {
        let artifact = try foundationArtifact(source: .liveDeviceRVI, hashDigit: "a")
        var accumulator = try PacketIndexAccumulator(artifact: artifact, limits: PacketIndexLimits(maximumRecords: 20, maximumEstimatedBytes: 100_000))
        var forward = foundationPacketValues(frame: 1, timestamp: "1.000000001")
        forward[.darwinProcessID] = ["343"]
        forward[.darwinProcessName] = ["maild"]
        try accumulator.consume(packet: DecodedPacket(values: forward))
        var reverse = foundationPacketValues(frame: 2, timestamp: "1.000000002")
        reverse[.ipv4Source] = forward[.ipv4Destination]
        reverse[.ipv4Destination] = forward[.ipv4Source]
        reverse[.tcpSourcePort] = forward[.tcpDestinationPort]
        reverse[.tcpDestinationPort] = forward[.tcpSourcePort]
        reverse[.darwinProcessID] = ["343"]
        reverse[.darwinProcessName] = ["maild"]
        try accumulator.consume(packet: DecodedPacket(values: reverse))
        var otherProcess = forward
        otherProcess[.frameNumber] = ["3"]
        otherProcess[.darwinProcessID] = ["344"]
        try accumulator.consume(packet: DecodedPacket(values: otherProcess))
        var otherInterface = forward
        otherInterface[.frameNumber] = ["4"]
        otherInterface[.frameInterfaceName] = ["pdp_ip0"]
        try accumulator.consume(packet: DecodedPacket(values: otherInterface))
        var otherEffective = forward
        otherEffective[.frameNumber] = ["5"]
        otherEffective[.darwinEffectiveProcessID] = ["8"]
        try accumulator.consume(packet: DecodedPacket(values: otherEffective))
        let result = try accumulator.result()
        XCTAssertEqual(result.sessions.count, 4)
        XCTAssertEqual(result.sessions.first?.packetCount, 2)
        XCTAssertEqual(result.sessions.first?.wireBytes, 256)
        XCTAssertEqual(result.coverage.ungroupedPackets, 0)
        let otherArtifact = try foundationArtifact(source: .liveDeviceRVI, hashDigit: "b")
        let foreign = try decodePacketRecord(packet: DecodedPacket(values: forward), artifact: otherArtifact)
        XCTAssertThrowsError(try accumulator.append(record: foreign)) { error in
            XCTAssertEqual(error as? PacketDomainError, .artifactMismatch)
        }
    }

    func testBoundedIndexAndChronologicalFilteredPaging() throws {
        let artifact = try foundationArtifact(source: .unknown, hashDigit: "a")
        var accumulator = try PacketIndexAccumulator(artifact: artifact, limits: PacketIndexLimits(maximumRecords: 2, maximumEstimatedBytes: 10_000))
        var values = foundationPacketValues(frame: 1, timestamp: "2.000000001")
        values[.darwinProcessName] = ["maild"]
        try accumulator.consume(packet: DecodedPacket(values: values))
        XCTAssertThrowsError(try accumulator.consume(packet: DecodedPacket(values: values)))
        values[.frameNumber] = ["2"]
        values[.frameTimeEpoch] = ["1.999999999"]
        try accumulator.consume(packet: DecodedPacket(values: values))
        values[.frameNumber] = ["3"]
        XCTAssertThrowsError(try accumulator.consume(packet: DecodedPacket(values: values))) { error in
            XCTAssertEqual(error as? PacketDomainError, .recordLimitExceeded(2))
        }
        let result = try accumulator.result()
        let query = PacketRecordQuery(text: "maild 192.0.2.2", transport: .tcp, protocolKind: .tcp, interfaceName: "en2", processID: nil, direction: nil, recordIDs: nil)
        let page = try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: 0, limit: 1))
        XCTAssertEqual(page.records.first?.id.frameNumber, 2)
        XCTAssertEqual(page.matchingCount, 2)
        XCTAssertEqual(page.nextOffset, 1)
        let focused = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: Set(page.records.map(\.id)))
        XCTAssertEqual(try pagePacketRecords(result: result, query: focused, page: PacketPageRequest(offset: 0, limit: 10)).matchingCount, 1)
        XCTAssertThrowsError(try pagePacketRecords(result: result, query: query, page: PacketPageRequest(offset: -1, limit: 1)))
        var tiny = try PacketIndexAccumulator(artifact: artifact, limits: PacketIndexLimits(maximumRecords: 10, maximumEstimatedBytes: 1))
        XCTAssertThrowsError(try tiny.consume(packet: DecodedPacket(values: values)))
        XCTAssertEqual(try tiny.result().coverage.recordCount, 0)
    }

    func testOlderAggregateResultsDecodeWithoutPacketIndex() throws {
        let original = makeSyntheticAnalysisResult(captureURL: URL(fileURLWithPath: "/tmp/old.pcap"), hash: String(repeating: "a", count: 64))
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NativeAnalysisResult.self, from: encoded)
        XCTAssertNil(decoded.packetAnalysis)
        XCTAssertEqual(decoded.summary, original.summary)
    }
}

private func foundationArtifact(source: PacketSourceProvenance, hashDigit: Character) throws -> PacketCaptureArtifact {
    PacketCaptureArtifact(id: try PacketArtifactID(sha256: String(repeating: String(hashDigit), count: 64), sourceURL: URL(fileURLWithPath: "/tmp/foundation.pcapng")), source: source, integrity: .verified)
}

private func foundationPacketValues(frame: UInt64, timestamp: String) -> [TSharkField: [String]] {
    [.frameNumber: [String(frame)], .frameTimeEpoch: [timestamp], .frameLength: ["128"],
     .frameProtocols: ["ip:tcp"], .frameInterfaceName: ["en2"], .ipv4Source: ["192.0.2.1"],
     .ipv4Destination: ["192.0.2.2"], .tcpSourcePort: ["61596"], .tcpDestinationPort: ["993"], .tcpStream: ["3"]]
}
