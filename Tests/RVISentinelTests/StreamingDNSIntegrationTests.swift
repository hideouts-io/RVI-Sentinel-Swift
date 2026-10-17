import CryptoKit
import Foundation
import Testing
@testable import RVI_Sentinel

struct StreamingDNSIntegrationTests {
    @Test func realTSharkStreamPreservesStructuredDNSOwnership() async throws {
        let tshark = try #require(resolveTShark(), "TShark is required for streaming DNS integration.")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-streaming-dns-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record(error, "Could not remove the streaming DNS test directory.") }
        }
        let url = directory.appendingPathComponent("generated-dns.pcap")
        let bytes = streamingDNSTestCapture()
        try bytes.write(to: url, options: .atomic)
        let artifact = try PacketArtifactID(
            sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), sourceURL: url
        )
        let recorder = StreamingDNSRecorder()
        try await streamCapturedDNSRecords(
            artifactID: artifact, tsharkURL: tshark, decoder: BoundedDecoder(), timeout: .seconds(20),
            consume: { messages in await recorder.record(messages) }
        )
        let batches = await recorder.snapshot()
        #expect(batches.map { $0.map(\.packetID.frameNumber) } == [[1], [2], [3], [4]])
        let reference = try await readCapturedDNSRecords(
            artifactID: artifact, tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard, timeout: .seconds(20)
        )
        let streamed = batches.flatMap { $0 }
        #expect(streamed.count == reference.count)
        for (actual, expected) in zip(streamed, reference) {
            #expect(actual.packetID == expected.packetID)
            #expect(actual.transactionID == expected.transactionID)
            #expect(actual.isResponse == expected.isResponse)
            #expect(actual.isTruncated == expected.isTruncated)
            #expect(actual.responseCode == expected.responseCode)
            #expect(actual.questions == expected.questions)
            #expect(actual.responseToFrame == expected.responseToFrame)
            #expect(Set(actual.answers) == Set(expected.answers))
            #expect(actual.unsupportedRecordTypes == expected.unsupportedRecordTypes)
        }
        let answer = try #require(streamed.first { $0.packetID.frameNumber == 2 })
        #expect(answer.answers.count == 3)
        #expect(answer.answers.contains { $0.owner == "alias.example" && $0.value == .canonicalName("target.example") && $0.ttlSeconds == 60 })
        #expect(answer.answers.contains { $0.owner == "target.example" && $0.value == .ipv4("192.0.2.10") && $0.ttlSeconds == 120 })
        #expect(answer.answers.contains { $0.owner == "other.example" && $0.value == .ipv4("192.0.2.20") && $0.ttlSeconds == 30 })
        #expect(streamed.contains { $0.packetID.frameNumber == 3 && $0.answers.contains { $0.owner == "printer.local" && $0.value == .ipv4("192.0.2.40") } })
        #expect(streamed.contains { $0.packetID.frameNumber == 4 && $0.questions.contains { $0.name == "printer" } })
        #expect(try Data(contentsOf: url) == bytes)

        let decoder = BoundedDecoder()
        let stopped = StreamingDNSRecorder()
        do {
            try await streamCapturedDNSRecords(
                artifactID: artifact, tsharkURL: tshark, decoder: decoder, timeout: .seconds(20),
                consume: { messages in
                    await stopped.record(messages)
                    throw StreamingDNSTestError.consumerStopped
                }
            )
            Issue.record("The stream must propagate a consumer failure.")
        } catch StreamingDNSTestError.consumerStopped { }
        #expect(await stopped.snapshot().count == 1)
        let cancelled = StreamingDNSRecorder()
        let task = Task {
            try await streamCapturedDNSRecords(
                artifactID: artifact, tsharkURL: tshark, decoder: decoder, timeout: .seconds(20),
                consume: { messages in
                    await cancelled.record(messages)
                    withUnsafeCurrentTask { $0?.cancel() }
                }
            )
        }
        do {
            try await task.value
            Issue.record("The stream must honor cancellation during delivery.")
        } catch is CancellationError { }
        #expect(await cancelled.snapshot().count == 1)
        // Consumer failure and cancellation must release the owned decoder process for reuse.
        let restarted = StreamingDNSRecorder()
        try await streamCapturedDNSRecords(
            artifactID: artifact, tsharkURL: tshark, decoder: decoder, timeout: .seconds(20),
            consume: { messages in await restarted.record(messages) }
        )
        #expect(await restarted.snapshot().count == 4)

        // A valid capture with no DNS packets still emits and validates an empty JSON array.
        let emptyBytes = Data(bytes.prefix(24))
        try emptyBytes.write(to: url, options: .atomic)
        let emptyArtifact = try PacketArtifactID(
            sha256: SHA256.hash(data: emptyBytes).map { String(format: "%02x", $0) }.joined(), sourceURL: url
        )
        let empty = StreamingDNSRecorder()
        try await streamCapturedDNSRecords(
            artifactID: emptyArtifact, tsharkURL: tshark, decoder: decoder, timeout: .seconds(20),
            consume: { messages in await empty.record(messages) }
        )
        #expect(await empty.snapshot().isEmpty)
    }

    @Test func framesNestedObjectsAndEscapedDelimitersByteByByte() throws {
        let first = #"{"text":"escaped \\ \" } { [ ] é","nested":[{"values":[1,{"text":"ok"}]}]}"#
        let second = "{\r\n\t\"next\": []\r\n}"
        let objects = try streamingDNSObjects(json: " \r\n[\n\(first),\n\(second)\n]\t\n", maximumJSONBytes: 1_024, maximumDepth: 12)
        #expect(objects == [Data("[\(first)]".utf8), Data("[\(second)]".utf8)])
    }

    @Test func emitsCompletedPacketBeforeTheDocumentEnds() throws {
        var framer = try CapturedDNSJSONFramer(maximumJSONBytes: 16, maximumDepth: 4)
        var completed: [Data] = []
        for byte in "[{},".utf8 {
            if let object = try framer.append(byte: byte) { completed.append(object) }
        }
        #expect(completed == [Data("[{}]".utf8)])
        #expect(throws: CapturedDNSError.self) { try framer.finish() }
        for byte in "{}]".utf8 {
            if let object = try framer.append(byte: byte) { completed.append(object) }
        }
        try framer.finish()
        #expect(completed.count == 2)
    }

    @Test func framingHasNoTotalByteOrFrameCeiling() throws {
        var framer = try CapturedDNSJSONFramer(maximumJSONBytes: 4, maximumDepth: 2)
        _ = try framer.append(byte: 91)
        var completed = 0
        for index in 0..<200_001 {
            if index > 0 { _ = try framer.append(byte: 44) }
            for byte in "{}".utf8 {
                if let object = try framer.append(byte: byte) {
                    #expect(object == Data("[{}]".utf8))
                    completed += 1
                }
            }
        }
        _ = try framer.append(byte: 93)
        try framer.finish()
        #expect(completed == 200_001)
    }

    @Test func rejectsOversizedPacketsAndExcessiveNesting() throws {
        #expect(try streamingDNSObjects(json: "[{}]", maximumJSONBytes: 4, maximumDepth: 2) == [Data("[{}]".utf8)])
        for json in ["[{ } ]", "[{\n\"text\":\"\(String(repeating: "x", count: 64))\"\n}]"] {
            do {
                _ = try streamingDNSObjects(json: json, maximumJSONBytes: 4, maximumDepth: 8)
                Issue.record("An oversized packet must fail before it can be delivered.")
            } catch CapturedDNSError.resourceLimit { }
        }
        do {
            _ = try streamingDNSObjects(json: "[{\"values\":[[]]}]", maximumJSONBytes: 128, maximumDepth: 3)
            Issue.record("Nesting must include the enclosing document array in its budget.")
        } catch CapturedDNSError.resourceLimit { }
    }

    @Test func rejectsMalformedEnvelopeDelimitersAndTrailingContent() throws {
        for json in ["{}", "null", "[,{}]", "[{},]", "[{}{}]", "[[]]", "[0]", "[true]", "[{]}", "[{\"values\":[}]]", "[]{}", "[{}][]", "[{}]garbage", "[{\"text\":\"first\nsecond\"}]"] {
            #expect(throws: CapturedDNSError.self) {
                try streamingDNSObjects(json: json, maximumJSONBytes: 1_024, maximumDepth: 16)
            }
        }
        #expect(try streamingDNSObjects(json: " \n[] \r\n", maximumJSONBytes: 4, maximumDepth: 2).isEmpty)
    }

    @Test func rejectsTruncatedPacketsStringsAndArrayEndings() throws {
        for json in ["", " ", "[", "[{", "[{}", "[{},", "[{\"text\":\"unfinished", "[{\"text\":\"escape\\", "[{\"values\":["] {
            #expect(throws: CapturedDNSError.self) {
                try streamingDNSObjects(json: json, maximumJSONBytes: 1_024, maximumDepth: 16)
            }
        }
    }

    @Test func completedObjectsStillRequireTypedDNSValidation() throws {
        let artifact = try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/generated-dns.pcap"))
        let packet = #"{"_source":{"layers":{"frame":{"frame.number":"1"},"dns":{"dns.id":"7","dns.flags":"0x0100","dns.flags_tree":{"dns.flags.response":"0","dns.flags.truncated":"0"},"Queries":{"entry":{"dns.qry.name":"test.example","dns.qry.type":"1","dns.qry.class":"1"}}}}}}"#
        let valid = try streamingDNSObjects(json: "[\(packet)]", maximumJSONBytes: 2_048, maximumDepth: 16)
        #expect(try decodeCapturedDNSRecords(data: #require(valid.first), artifactID: artifact, limits: .standard).count == 1)
        let variants = [
            packet.replacingOccurrences(of: "\"dns.id\":\"7\"", with: "\"dns.id\":\"65536\""),
            packet.replacingOccurrences(of: "\"frame.number\":\"1\"", with: "\"frame.number\":\"0\""),
            packet.replacingOccurrences(of: "\"dns.flags.response\":\"0\"", with: "\"dns.flags.response\":\"1\""),
            packet.replacingOccurrences(of: "test.example", with: String(repeating: "x", count: 1_025)),
            packet.replacingOccurrences(of: "\"dns.id\":\"7\"", with: "\"dns.id\":")
        ]
        for json in variants {
            let objects = try streamingDNSObjects(json: "[\(json)]", maximumJSONBytes: 2_048, maximumDepth: 16)
            let object = try #require(objects.first)
            #expect(throws: (any Error).self) { try decodeCapturedDNSRecords(data: object, artifactID: artifact, limits: .standard) }
        }
    }
}

private actor StreamingDNSRecorder {
    private var batches: [[CapturedDNSMessage]] = []

    func record(_ messages: [CapturedDNSMessage]) { batches.append(messages) }
    func snapshot() -> [[CapturedDNSMessage]] { batches }
}

private enum StreamingDNSTestError: Error { case consumerStopped }

private func streamingDNSObjects(json: String, maximumJSONBytes: Int, maximumDepth: Int) throws -> [Data] {
    var framer = try CapturedDNSJSONFramer(maximumJSONBytes: maximumJSONBytes, maximumDepth: maximumDepth)
    var objects: [Data] = []
    for byte in json.utf8 {
        if let object = try framer.append(byte: byte) { objects.append(object) }
    }
    try framer.finish()
    return objects
}

/// Generated wire packets exercise the installed passive decoder without using private captures.
private func streamingDNSTestCapture() -> Data {
    let question = streamingDNSName("alias.example") + streamingDNSBigEndian(UInt16(1)) + streamingDNSBigEndian(UInt16(1))
    let query = Data([0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]) + question
    let answers = streamingDNSRecord(owner: "alias.example", type: 5, ttl: 60, value: streamingDNSName("target.example"))
        + streamingDNSRecord(owner: "target.example", type: 1, ttl: 120, value: Data([192, 0, 2, 10]))
        + streamingDNSRecord(owner: "other.example", type: 1, ttl: 30, value: Data([192, 0, 2, 20]))
    let response = Data([0, 7, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0]) + question + answers
    let mdns = Data([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0])
        + streamingDNSRecord(owner: "printer.local", type: 1, ttl: 120, value: Data([192, 0, 2, 40]))
    let llmnr = Data([0, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        + streamingDNSName("printer") + streamingDNSBigEndian(UInt16(1)) + streamingDNSBigEndian(UInt16(1))
    let frames = [
        streamingDNSUDPPacket(payload: query, source: Data([10, 0, 0, 2]), destination: Data([10, 0, 0, 53]), sourcePort: 53000, destinationPort: 53),
        streamingDNSUDPPacket(payload: response, source: Data([10, 0, 0, 53]), destination: Data([10, 0, 0, 2]), sourcePort: 53, destinationPort: 53000),
        streamingDNSUDPPacket(payload: mdns, source: Data([10, 0, 0, 2]), destination: Data([224, 0, 0, 251]), sourcePort: 5353, destinationPort: 5353),
        streamingDNSUDPPacket(payload: llmnr, source: Data([10, 0, 0, 2]), destination: Data([224, 0, 0, 252]), sourcePort: 53001, destinationPort: 5355),
        streamingDNSUDPPacket(payload: Data(), source: Data([10, 0, 0, 2]), destination: Data([10, 0, 0, 53]), sourcePort: 54000, destinationPort: 54001)
    ]
    var capture = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0])
    for (index, frame) in frames.enumerated() {
        capture.append(streamingDNSLittleEndian(UInt32(1_700_000_000 + index)))
        capture.append(streamingDNSLittleEndian(UInt32(123_456)))
        capture.append(streamingDNSLittleEndian(UInt32(frame.count)))
        capture.append(streamingDNSLittleEndian(UInt32(frame.count)))
        capture.append(frame)
    }
    return capture
}

private func streamingDNSName(_ name: String) -> Data {
    var encoded = Data()
    for label in name.split(separator: ".") {
        encoded.append(UInt8(label.utf8.count))
        encoded.append(contentsOf: label.utf8)
    }
    encoded.append(0)
    return encoded
}

private func streamingDNSRecord(owner: String, type: UInt16, ttl: UInt32, value: Data) -> Data {
    streamingDNSName(owner) + streamingDNSBigEndian(type) + streamingDNSBigEndian(UInt16(1))
        + streamingDNSBigEndian(ttl) + streamingDNSBigEndian(UInt16(value.count)) + value
}

private func streamingDNSUDPPacket(payload: Data, source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16) -> Data {
    let udp = streamingDNSBigEndian(sourcePort) + streamingDNSBigEndian(destinationPort)
        + streamingDNSBigEndian(UInt16(payload.count + 8)) + Data([0, 0]) + payload
    return Data([0x45, 0]) + streamingDNSBigEndian(UInt16(udp.count + 20))
        + Data([0, 1, 0, 0, 64, 17, 0, 0]) + source + destination + udp
}

private func streamingDNSBigEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

private func streamingDNSLittleEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.littleEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}
