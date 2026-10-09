import Foundation
import XCTest
@testable import RVI_Sentinel

@MainActor
final class PacketEvidenceIntegrationTests: XCTestCase {
    /// Synthetic typed positions verify refresh ordering, independently of physical-device behavior.
    func testRepeatedDNSRefreshesRespectFrameOrderAtEqualTimestamps() throws {
        let artifact = PacketCaptureArtifact(
            id: try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/generated-refresh-order.pcap")),
            source: .unknown, integrity: .verified
        )
        var packets = [try evidenceDNSPositionPacket(artifact: artifact, frameNumber: 1, source: "10.0.0.2", destination: "192.0.2.10", sourcePort: 54000, destinationPort: 443)]
        var messages: [CapturedDNSMessage] = []
        for index in 0..<64 {
            let responseFrame = UInt64(index * 2 + 2)
            let address = index.isMultiple(of: 2) ? "192.0.2.10" : "192.0.2.20"
            let response = try evidenceDNSPositionPacket(artifact: artifact, frameNumber: responseFrame, source: "10.0.0.53", destination: "10.0.0.2", sourcePort: 53, destinationPort: 53000)
            packets.append(response)
            packets.append(try evidenceDNSPositionPacket(artifact: artifact, frameNumber: responseFrame + 1, source: "10.0.0.2", destination: address, sourcePort: 54000, destinationPort: 443))
            messages.append(CapturedDNSMessage(
                packetID: response.id, transactionID: UInt16(index), isResponse: true, isTruncated: false, responseCode: 0,
                questions: [CapturedDNSQuestion(name: "refresh.example", recordType: 1, recordClass: 1)], responseToFrame: nil,
                answers: [CapturedDNSResourceRecord(owner: "refresh.example", recordType: 1, recordClass: 1, ttlSeconds: 120, value: .ipv4(address))],
                unsupportedRecordTypes: []
            ))
        }
        let negative = try evidenceDNSPositionPacket(artifact: artifact, frameNumber: 130, source: "10.0.0.53", destination: "10.0.0.2", sourcePort: 53, destinationPort: 53000)
        packets.append(negative)
        packets.append(try evidenceDNSPositionPacket(artifact: artifact, frameNumber: 131, source: "10.0.0.2", destination: "192.0.2.20", sourcePort: 54000, destinationPort: 443))
        messages.append(CapturedDNSMessage(packetID: negative.id, transactionID: 100, isResponse: true, isTruncated: false, responseCode: 0, questions: [CapturedDNSQuestion(name: "refresh.example", recordType: 1, recordClass: 1)], responseToFrame: nil, answers: [], unsupportedRecordTypes: []))
        let links = try resolveCapturedDNSNames(messages: Array(messages.reversed()), packets: Array(packets.reversed()), maximumAssociations: 1_000)
        XCTAssertNil(links[packets[0].id], "A packet before the first same-time answer cannot use that answer.")
        for index in 0..<64 {
            let responseID = PacketRecordID(artifactID: artifact.id, frameNumber: UInt64(index * 2 + 2))
            let flowID = PacketRecordID(artifactID: artifact.id, frameNumber: responseID.frameNumber + 1)
            let evidence = try XCTUnwrap(links[flowID])
            XCTAssertEqual(evidence.count, 1)
            XCTAssertEqual(evidence[0].supportingPackets, [responseID], "A later same-time refresh must not invalidate an earlier frame.")
        }
        XCTAssertNil(links[PacketRecordID(artifactID: artifact.id, frameNumber: 131)], "A later NOERROR/NODATA answer ends the prior owner/type interval.")
    }

    func testRealTSharkKeepsDNSOwnersTTLAndClientScope() async throws {
        let tshark = try XCTUnwrap(resolveTShark(), "TShark is required for packet evidence integration.")
        let capture = try makePacketEvidenceCapture()
        let analysis = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture.url, progress: { _ in })
        let indexed = try XCTUnwrap(analysis.packetAnalysis)
        let messages = try await readCapturedDNSRecords(
            artifactID: indexed.artifact.id, tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard, timeout: .seconds(20)
        )
        let original = try XCTUnwrap(messages.first { $0.packetID.frameNumber == 2 })
        XCTAssertEqual(original.answers.count, 6)
        XCTAssertTrue(original.answers.contains { $0.owner == "target.example" && $0.value == .ipv4("192.0.2.10") && $0.ttlSeconds == 120 })
        XCTAssertTrue(original.answers.contains { $0.owner == "other.example" && $0.value == .ipv4("192.0.2.20") })
        XCTAssertTrue(original.answers.contains { $0.value == .pointerName("ptr.example") })
        XCTAssertTrue(original.answers.contains { $0.value == .service(target: "host.local", port: 1234, priority: 0, weight: 0) })
        let capturedNames = try resolveCapturedHostnames(messages: messages, packets: indexed.records, maximumAssociations: 1_000)
        let mdnsAnswerID = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 17)
        let mdnsQueryID = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 18)
        XCTAssertTrue((capturedNames[mdnsAnswerID] ?? []).contains { $0.name == "printer.local" && $0.provenance == .capturedMDNS && $0.address == "192.0.2.40" && !$0.isInferred })
        XCTAssertTrue((capturedNames[mdnsQueryID] ?? []).contains { $0.name == "printer.local" && $0.provenance == .capturedMDNS && $0.address == nil && !$0.isInferred })
        let links = try resolveCapturedDNSNames(messages: messages, packets: indexed.records, maximumAssociations: 100)
        func names(_ frame: UInt64) -> Set<String> {
            Set((links[PacketRecordID(artifactID: indexed.artifact.id, frameNumber: frame)] ?? []).map(\.name))
        }
        XCTAssertEqual(names(3), ["alias.example", "target.example"])
        XCTAssertEqual(names(4), ["alias.example", "target.example"])
        XCTAssertTrue(names(5).isEmpty, "A DNS answer to another client cannot label this packet.")
        XCTAssertEqual(names(6), ["target.example"], "CNAME expiry must use its shorter TTL.")
        XCTAssertTrue(names(8).isEmpty, "A replacement address invalidates the earlier binding.")
        XCTAssertEqual(names(10), ["other.example"], "NXDOMAIN invalidates its matching name while preserving independent owners on the shared address.")
        let flow = try XCTUnwrap(links[PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 3)])
        XCTAssertTrue(flow.allSatisfy { $0.isInferred && $0.supportingPackets.contains(where: { $0.frameNumber == 2 }) })
        XCTAssertTrue(flow.allSatisfy { $0.name != "ptr.example" && $0.name != "host.local" && $0.name != "other.example" })
        XCTAssertEqual(try sha256(url: capture.url), indexed.artifact.id.sha256)
    }

    func testRealTSharkOriginalBytesMatchSavedFrameAndMetadataStaysUnmapped() async throws {
        let tshark = try XCTUnwrap(resolveTShark(), "TShark is required for original-byte integration.")
        let capture = try makePacketEvidenceCapture()
        let analysis = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture.url, progress: { _ in })
        let indexed = try XCTUnwrap(analysis.packetAnalysis)
        let packet = try XCTUnwrap(indexed.records.first { $0.id.frameNumber == 2 })
        let evidence = try await inspectOriginalPacket(
            packet: packet, artifact: indexed.artifact,
            fields: [.ipv4Source, .ipv4Destination, .udpSourcePort, .darwinProcessName, .frameTimeEpoch],
            tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard
        )
        XCTAssertEqual(evidence.bytes, capture.frames[1])
        XCTAssertEqual(evidence.verifiedRanges.first { $0.field == .ipv4Source }?.offset, 26)
        XCTAssertEqual(evidence.verifiedRanges.first { $0.field == .ipv4Destination }?.length, 4)
        XCTAssertTrue(evidence.unmappedFields.contains(.darwinProcessName))
        XCTAssertTrue(evidence.unmappedFields.contains(.frameTimeEpoch))
        XCTAssertEqual(try sha256(url: capture.url), indexed.artifact.id.sha256)
    }

    func testRealTSharkHTTPNamesPropagateOnlyWithinExactEarlierStreamContext() async throws {
        _ = try XCTUnwrap(resolveTShark(), "TShark is required for HTTP stream evidence integration.")
        let capture = try makePacketEvidenceCapture()
        let analysis = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture.url, progress: { _ in })
        let indexed = try XCTUnwrap(analysis.packetAnalysis)
        let evidence = try resolveCapturedHostnames(messages: [], packets: indexed.records, maximumAssociations: 100)
        let request = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 11)
        let response = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 12)
        let unrelated = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 14)
        let reused = PacketRecordID(artifactID: indexed.artifact.id, frameNumber: 16)
        XCTAssertTrue((evidence[request] ?? []).contains { $0.name == "captured.example" && !$0.isInferred && $0.address == nil })
        XCTAssertTrue((evidence[response] ?? []).contains { $0.name == "captured.example" && $0.isInferred && $0.supportingPackets == [request] && $0.address == nil })
        XCTAssertFalse((evidence[unrelated] ?? []).contains { $0.name == "captured.example" })
        XCTAssertEqual(Set((evidence[reused] ?? []).filter { $0.provenance == .httpHost }.map(\.name)), ["captured.example", "second.example"])
        XCTAssertTrue((evidence[reused] ?? []).allSatisfy { $0.address == nil })
        let contextPacket = try XCTUnwrap(indexed.records.first { $0.id.frameNumber == 13 })
        let otherProcess = evidencePacketWithContext(
            record: contextPacket,
            process: PacketProcessMetadata(state: .recorded, labels: [PacketProcessLabel(source: .applePCAPNG, processID: 99, name: "different-process")]),
            interface: contextPacket.interface
        )
        let changedProcess = indexed.records.map { $0.id == contextPacket.id ? otherProcess : $0 }
        let processEvidence = try resolveCapturedHostnames(messages: [], packets: changedProcess, maximumAssociations: 100)
        XCTAssertFalse((processEvidence[contextPacket.id] ?? []).contains { $0.name == "captured.example" })
        let otherInterface = evidencePacketWithContext(
            record: contextPacket, process: contextPacket.process,
            interface: PacketInterfaceMetadata(state: .recorded, labels: [PacketInterfaceLabel(source: .applePCAPNG, name: "different-interface")])
        )
        let changedInterface = indexed.records.map { $0.id == contextPacket.id ? otherInterface : $0 }
        let interfaceEvidence = try resolveCapturedHostnames(messages: [], packets: changedInterface, maximumAssociations: 100)
        XCTAssertFalse((interfaceEvidence[contextPacket.id] ?? []).contains { $0.name == "captured.example" })
    }

    func testOriginalInspectionRejectsPendingChangedMissingAndWrongArtifacts() async throws {
        let tshark = try XCTUnwrap(resolveTShark(), "TShark is required for original-byte denial integration.")
        let capture = try makePacketEvidenceCapture()
        let analysis = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture.url, progress: { _ in })
        let indexed = try XCTUnwrap(analysis.packetAnalysis)
        let packet = try XCTUnwrap(indexed.records.first)
        let pending = PacketCaptureArtifact(id: indexed.artifact.id, source: .unknown, integrity: .pending)
        do {
            _ = try await inspectOriginalPacket(packet: packet, artifact: pending, fields: [], tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard)
            XCTFail("Pending integrity unexpectedly allowed byte inspection.")
        } catch let error as OriginalPacketError {
            guard case .unfinishedCapture = error else { return XCTFail(error.localizedDescription) }
        }
        let otherID = try PacketArtifactID(sha256: indexed.artifact.id.sha256, sourceURL: capture.url.deletingLastPathComponent().appendingPathComponent("other.pcap"))
        do {
            _ = try await inspectOriginalPacket(packet: packet, artifact: PacketCaptureArtifact(id: otherID, source: .unknown, integrity: .verified), fields: [], tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard)
            XCTFail("Wrong artifact unexpectedly allowed byte inspection.")
        } catch let error as OriginalPacketError {
            guard case .artifactMismatch = error else { return XCTFail(error.localizedDescription) }
        }
        let handle = try FileHandle(forWritingTo: capture.url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0]))
        try handle.close()
        do {
            _ = try await inspectOriginalPacket(packet: packet, artifact: indexed.artifact, fields: [], tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard)
            XCTFail("Changed original unexpectedly allowed byte inspection.")
        } catch let error as OriginalPacketError {
            guard case .changedCapture = error else { return XCTFail(error.localizedDescription) }
        }
        try FileManager.default.removeItem(at: capture.url)
        do {
            _ = try await inspectOriginalPacket(packet: packet, artifact: indexed.artifact, fields: [], tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard)
            XCTFail("Missing original unexpectedly allowed byte inspection.")
        } catch let error as OriginalPacketError {
            guard case .missingCapture = error else { return XCTFail(error.localizedDescription) }
        }
    }

    func testMalformedEvidenceCannotCreateByteHighlightsOrDNSLinks() throws {
        let id = try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/known-test.pcap"))
        let malformedDNS = Data("[{\"_source\":{\"layers\":{\"frame\":{\"frame.number\":\"2\"},\"dns\":{\"dns.id\":\"1\",\"dns.flags\":\"0x8180\",\"dns.flags_tree\":{\"dns.flags.response\":\"1\",\"dns.flags.truncated\":\"0\",\"dns.flags.rcode\":\"0\"},\"Answers\":{\"answer\":{\"dns.resp.name\":\"owner.example\",\"dns.resp.type\":[\"1\",\"28\"],\"dns.resp.class\":\"0x0001\",\"dns.resp.ttl\":\"10\",\"dns.a\":\"192.0.2.1\"}}}}}}]".utf8)
        XCTAssertThrowsError(try decodeCapturedDNSRecords(data: malformedDNS, artifactID: id, limits: .standard))
        let raw = Data("[{\"_source\":{\"layers\":{\"frame_raw\":[\"0001\",0,2,0,1,0],\"ip\":{\"ip.src_raw\":[\"0001\",3,2,0,32,0]}}}}]".utf8)
        XCTAssertThrowsError(try decodeOriginalPacketBytes(data: raw, packetID: PacketRecordID(artifactID: id, frameNumber: 1), capturedLength: 2, wireLength: 2, fields: [.ipv4Source], limits: .standard))
        XCTAssertThrowsError(try validateEvidenceJSONStructure(data: Data("[[[]]]".utf8), maximumBytes: 100, maximumDepth: 2))
        XCTAssertThrowsError(try currentDNSReverseName(address: "192.0.2.1;echo invalid"))
        XCTAssertEqual(try currentDNSReverseName(address: "192.0.2.1"), "1.2.0.192.in-addr.arpa")
        XCTAssertThrowsError(try parseCurrentPTRResponse(output: ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nunrelated.example. 5 IN PTR host.example.\n", queryName: "1.2.0.192.in-addr.arpa", maximumAnswers: 128))
    }

    private func makePacketEvidenceCapture() throws -> (url: URL, frames: [Data]) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-sentinel-packet-evidence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let question = evidenceDNSName("alias.example") + evidenceBigEndian(UInt16(1)) + evidenceBigEndian(UInt16(1))
        let query = evidenceDNSHeader(identifier: 7, flags: 0x0100, questions: 1, answers: 0) + question
        let answers = evidenceRR(owner: "alias.example", type: 5, ttl: 60, value: evidenceDNSName("target.example"))
            + evidenceRR(owner: "target.example", type: 1, ttl: 120, value: Data([192, 0, 2, 10]))
            + evidenceRR(owner: "other.example", type: 1, ttl: 120, value: Data([192, 0, 2, 20]))
            + evidenceRR(owner: "target.example", type: 28, ttl: 120, value: Data([0x20, 1, 0x0d, 0xb8] + Array(repeating: UInt8(0), count: 11) + [0x10]))
            + evidenceRR(owner: "10.2.0.192.in-addr.arpa", type: 12, ttl: 30, value: evidenceDNSName("ptr.example"))
            + evidenceRR(owner: "_svc._tcp.local", type: 33, ttl: 40, value: evidenceBigEndian(UInt16(0)) + evidenceBigEndian(UInt16(0)) + evidenceBigEndian(UInt16(1234)) + evidenceDNSName("host.local"))
        let response = evidenceDNSHeader(identifier: 7, flags: 0x8180, questions: 1, answers: 6) + question + answers
        let replacementQuestion = evidenceDNSName("target.example") + evidenceBigEndian(UInt16(1)) + evidenceBigEndian(UInt16(1))
        let replacement = evidenceDNSHeader(identifier: 8, flags: 0x8180, questions: 1, answers: 1) + replacementQuestion + evidenceRR(owner: "target.example", type: 1, ttl: 120, value: Data([192, 0, 2, 20]))
        let negative = evidenceDNSHeader(identifier: 9, flags: 0x8183, questions: 1, answers: 0) + replacementQuestion
        let client = Data([10, 0, 0, 2]), server = Data([10, 0, 0, 53]), peer = Data([192, 0, 2, 10])
        let httpPeer = Data([192, 0, 2, 30])
        let firstRequest = Data("GET / HTTP/1.1\r\nHost: captured.example\r\n\r\n".utf8)
        let secondRequest = Data("GET /next HTTP/1.1\r\nHost: second.example\r\n\r\n".utf8)
        let httpResponse = Data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)
        let mdnsQuestion = evidenceDNSName("printer.local") + evidenceBigEndian(UInt16(1)) + evidenceBigEndian(UInt16(1))
        let mdnsAnswers = evidenceRR(owner: "printer.local", type: 1, ttl: 120, value: Data([192, 0, 2, 40])) + evidenceRR(owner: "alias-printer.local", type: 5, ttl: 60, value: evidenceDNSName("printer.local"))
        let frames = [
            evidenceUDPPacket(payload: query, source: client, destination: server, sourcePort: 53000, destinationPort: 53),
            evidenceUDPPacket(payload: response, source: server, destination: client, sourcePort: 53, destinationPort: 53000),
            evidenceTCPPacket(source: client, destination: peer, sourcePort: 54000, destinationPort: 443),
            evidenceTCPPacket(source: peer, destination: client, sourcePort: 443, destinationPort: 54000),
            evidenceTCPPacket(source: Data([10, 0, 0, 3]), destination: peer, sourcePort: 54000, destinationPort: 443),
            evidenceTCPPacket(source: client, destination: peer, sourcePort: 54001, destinationPort: 443),
            evidenceUDPPacket(payload: replacement, source: server, destination: client, sourcePort: 53, destinationPort: 53001),
            evidenceTCPPacket(source: client, destination: peer, sourcePort: 54002, destinationPort: 443),
            evidenceUDPPacket(payload: negative, source: server, destination: client, sourcePort: 53, destinationPort: 53002),
            evidenceTCPPacket(source: client, destination: Data([192, 0, 2, 20]), sourcePort: 54003, destinationPort: 443),
            evidenceTCPDataPacket(source: client, destination: httpPeer, sourcePort: 55000, destinationPort: 80, payload: firstRequest, sequence: 1, acknowledgment: 1),
            evidenceTCPDataPacket(source: httpPeer, destination: client, sourcePort: 80, destinationPort: 55000, payload: httpResponse, sequence: 1, acknowledgment: UInt32(firstRequest.count + 1)),
            evidenceTCPAcknowledgmentPacket(source: client, destination: httpPeer, sourcePort: 55000, destinationPort: 80, sequence: UInt32(firstRequest.count + 1), acknowledgment: UInt32(httpResponse.count + 1)),
            evidenceTCPAcknowledgmentPacket(source: client, destination: httpPeer, sourcePort: 55001, destinationPort: 80, sequence: 1, acknowledgment: 1),
            evidenceTCPDataPacket(source: client, destination: httpPeer, sourcePort: 55000, destinationPort: 80, payload: secondRequest, sequence: UInt32(firstRequest.count + 1), acknowledgment: UInt32(httpResponse.count + 1)),
            evidenceTCPDataPacket(source: httpPeer, destination: client, sourcePort: 80, destinationPort: 55000, payload: httpResponse, sequence: UInt32(httpResponse.count + 1), acknowledgment: UInt32(firstRequest.count + secondRequest.count + 1)),
            evidenceUDPPacket(payload: evidenceDNSHeader(identifier: 0, flags: 0x8400, questions: 0, answers: 2) + mdnsAnswers, source: client, destination: Data([224, 0, 0, 251]), sourcePort: 5353, destinationPort: 5353),
            evidenceUDPPacket(payload: evidenceDNSHeader(identifier: 0, flags: 0, questions: 1, answers: 0) + mdnsQuestion, source: client, destination: Data([224, 0, 0, 251]), sourcePort: 5353, destinationPort: 5353)
        ]
        let seconds: [UInt32] = [0, 1, 2, 3, 4, 62, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81]
        var capture = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0])
        for (index, frame) in frames.enumerated() {
            capture.append(evidenceLittleEndian(UInt32(1_700_000_000) + seconds[index]))
            capture.append(evidenceLittleEndian(UInt32(123_456)))
            capture.append(evidenceLittleEndian(UInt32(frame.count)))
            capture.append(evidenceLittleEndian(UInt32(frame.count)))
            capture.append(frame)
        }
        let url = directory.appendingPathComponent("known-dns-and-tcp.pcap")
        try capture.write(to: url, options: .atomic)
        return (url, frames)
    }
}

private func evidenceDNSPositionPacket(artifact: PacketCaptureArtifact, frameNumber: UInt64, source: String, destination: String, sourcePort: UInt16, destinationPort: UInt16) throws -> PacketRecord {
    try decodePacketRecord(packet: DecodedPacket(values: [
        .frameNumber: [String(frameNumber)], .frameTimeEpoch: ["1700000000.123456789"], .frameLength: ["60"], .frameCapturedLength: ["60"], .frameProtocols: ["eth:ip:udp"],
        .ipv4Source: [source], .ipv4Destination: [destination], .udpSourcePort: [String(sourcePort)], .udpDestinationPort: [String(destinationPort)], .udpStream: ["0"]
    ]), artifact: artifact)
}

private func evidenceDNSHeader(identifier: UInt16, flags: UInt16, questions: UInt16, answers: UInt16) -> Data {
    evidenceBigEndian(identifier) + evidenceBigEndian(flags) + evidenceBigEndian(questions) + evidenceBigEndian(answers) + Data([0, 0, 0, 0])
}

private func evidenceDNSName(_ name: String) -> Data {
    var result = Data()
    for label in name.split(separator: ".") {
        result.append(UInt8(label.utf8.count))
        result.append(contentsOf: label.utf8)
    }
    result.append(0)
    return result
}

private func evidenceRR(owner: String, type: UInt16, ttl: UInt32, value: Data) -> Data {
    evidenceDNSName(owner) + evidenceBigEndian(type) + evidenceBigEndian(UInt16(1)) + evidenceBigEndian(ttl) + evidenceBigEndian(UInt16(value.count)) + value
}

private func evidenceUDPPacket(payload: Data, source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16) -> Data {
    let udp = evidenceBigEndian(sourcePort) + evidenceBigEndian(destinationPort) + evidenceBigEndian(UInt16(8 + payload.count)) + Data([0, 0]) + payload
    return evidenceIPv4Packet(transport: 17, payload: udp, source: source, destination: destination)
}

private func evidenceTCPPacket(source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16) -> Data {
    let tcp = evidenceBigEndian(sourcePort) + evidenceBigEndian(destinationPort) + Data([0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0, 0, 0, 0, 0])
    return evidenceIPv4Packet(transport: 6, payload: tcp, source: source, destination: destination)
}

private func evidenceTCPDataPacket(source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16, payload: Data, sequence: UInt32, acknowledgment: UInt32) -> Data {
    let header = evidenceBigEndian(sourcePort) + evidenceBigEndian(destinationPort) + evidenceBigEndian(sequence) + evidenceBigEndian(acknowledgment) + Data([0x50, 0x18, 0x10, 0, 0, 0, 0, 0])
    return evidenceIPv4Packet(transport: 6, payload: header + payload, source: source, destination: destination)
}

private func evidenceTCPAcknowledgmentPacket(source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16, sequence: UInt32, acknowledgment: UInt32) -> Data {
    let header = evidenceBigEndian(sourcePort) + evidenceBigEndian(destinationPort) + evidenceBigEndian(sequence) + evidenceBigEndian(acknowledgment) + Data([0x50, 0x10, 0x10, 0, 0, 0, 0, 0])
    return evidenceIPv4Packet(transport: 6, payload: header, source: source, destination: destination)
}

/// A typed context mutation checks propagation denial; it is not physical metadata validation.
private func evidencePacketWithContext(record: PacketRecord, process: PacketProcessMetadata, interface: PacketInterfaceMetadata) -> PacketRecord {
    PacketRecord(
        id: record.id, timestamp: record.timestamp, wireLength: record.wireLength, capturedLength: record.capturedLength,
        protocolStack: record.protocolStack, protocols: record.protocols, sourceAddress: record.sourceAddress, destinationAddress: record.destinationAddress,
        sourcePort: record.sourcePort, destinationPort: record.destinationPort, transport: record.transport, stream: record.stream, tcp: record.tcp,
        process: process, effectiveProcess: record.effectiveProcess, interface: interface, direction: record.direction,
        recordedNames: record.recordedNames, diagnostics: record.diagnostics
    )
}

private func evidenceIPv4Packet(transport: UInt8, payload: Data, source: Data, destination: Data) -> Data {
    let ethernet = Data([0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 8, 0])
    let ip = Data([0x45, 0]) + evidenceBigEndian(UInt16(20 + payload.count)) + Data([0, 1, 0, 0, 64, transport, 0, 0]) + source + destination
    return ethernet + ip + payload
}

private func evidenceBigEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

private func evidenceLittleEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.littleEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}
