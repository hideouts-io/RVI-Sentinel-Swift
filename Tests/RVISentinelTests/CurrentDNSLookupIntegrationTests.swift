import Foundation
import XCTest
@testable import RVI_Sentinel

private enum ControlledDNSExchangeEvent: Sendable {
    case query(ControlledDNSQuery)
    case result(CurrentPTRLookupResult)
}

private struct ControlledPTRCase {
    let address: String
    let reply: ControlledDNSReply
    let expectedStatus: CurrentPTRStatus
    let expectedName: String?
}

@MainActor
final class CurrentDNSLookupIntegrationTests: XCTestCase {
    /// Real dig/UDP transport with reserved fixture data; this does not verify native UI or physical traffic.
    func testRealDigAnswersAndNegativeResultsPreserveCapturedEvidence() async throws {
        try requireIsolatedDigConfiguration()
        let capture = try makeControlledCapture()
        let tshark = try XCTUnwrap(resolveTShark(), "TShark is required for captured-evidence preservation.")
        let before = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, progress: { _ in })
        let indexed = try XCTUnwrap(before.packetAnalysis)
        let packetID = try XCTUnwrap(indexed.records.first).id
        let messages = try await readCapturedDNSRecords(
            artifactID: indexed.artifact.id, tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard, timeout: .seconds(10)
        )
        let capturedNames = try resolveCapturedHostnames(messages: messages, packets: indexed.records, maximumAssociations: 100)
        XCTAssertTrue(capturedNames.values.joined().contains { $0.name == "captured.test" })
        let originalHash = try sha256(url: capture)
        let cases: [ControlledPTRCase] = [
            ControlledPTRCase(address: "192.0.2.1", reply: .pointer("current-v4.test"), expectedStatus: .answered, expectedName: "current-v4.test"),
            ControlledPTRCase(address: "2001:db8::1", reply: .pointer("current-v6.test"), expectedStatus: .answered, expectedName: "current-v6.test"),
            ControlledPTRCase(address: "192.0.2.2", reply: .noAnswer, expectedStatus: .noAnswer, expectedName: nil),
            ControlledPTRCase(address: "192.0.2.3", reply: .nameDoesNotExist, expectedStatus: .nameDoesNotExist, expectedName: nil)
        ]
        for item in cases {
            let resolver = try makeResolver()
            let startedAt = Date()
            let exchange = try await exchangeControlledPTR(
                address: item.address, packetID: packetID, resolver: resolver, reply: item.reply, decoder: BoundedDecoder()
            )
            let result = exchange.result
            XCTAssertEqual(result.address, item.address)
            XCTAssertEqual(result.packetID, packetID)
            XCTAssertEqual(result.queryName, try currentDNSReverseName(address: item.address))
            XCTAssertEqual(exchange.query.name, result.queryName)
            XCTAssertEqual(result.status, item.expectedStatus)
            XCTAssertEqual(result.provenance, .activeReverseLookup)
            XCTAssertGreaterThanOrEqual(result.requestedAt, startedAt)
            XCTAssertLessThanOrEqual(result.requestedAt, exchange.query.receivedAt)
            XCTAssertGreaterThanOrEqual(result.completedAt, exchange.query.receivedAt)
            XCTAssertLessThanOrEqual(result.completedAt, Date())
            if let name = item.expectedName {
                XCTAssertEqual(result.answers, [CurrentDNSAnswer(owner: result.queryName, ttlSeconds: 60, recordType: .pointer, value: name)])
            } else {
                XCTAssertTrue(result.answers.isEmpty)
            }
            XCTAssertEqual(try sha256(url: capture), originalHash)
        }
        let afterMessages = try await readCapturedDNSRecords(
            artifactID: indexed.artifact.id, tsharkURL: tshark, decoder: BoundedDecoder(), limits: .standard, timeout: .seconds(10)
        )
        let afterNames = try resolveCapturedHostnames(messages: afterMessages, packets: indexed.records, maximumAssociations: 100)
        XCTAssertEqual(afterNames, capturedNames)
        XCTAssertFalse(afterNames.values.joined().contains { $0.provenance == .activeReverseLookup || $0.name.hasPrefix("current-") })
        XCTAssertEqual(try sha256(url: capture), originalHash)
    }

    func testObservedQueryDeadlineAndCancellationReleaseDecoder() async throws {
        try requireIsolatedDigConfiguration()
        let capture = try makeControlledCapture()
        let originalHash = try sha256(url: capture)
        let packetID = PacketRecordID(artifactID: try PacketArtifactID(sha256: originalHash, sourceURL: capture), frameNumber: 1)
        let decoder = BoundedDecoder()
        let timedOutResolver = try makeResolver()
        do {
            try await withThrowingTaskGroup(of: ControlledDNSExchangeEvent.self) { group in
                group.addTask { .query(try await timedOutResolver.respondOnce(reply: .withhold)) }
                group.addTask {
                    .result(try await lookupCurrentPTR(
                        address: "192.0.2.4", packetID: packetID, resolver: .loopback(port: timedOutResolver.port),
                        decoder: decoder, timeout: .milliseconds(300), maximumOutputBytes: 32_768
                    ))
                }
                for try await _ in group {}
            }
            XCTFail("An unanswered observed query exceeded its deadline without failing.")
        } catch let error as BoundedDecoderError {
            guard case .deadlineExceeded = error else { throw error }
        }
        let timedOutQueries = await timedOutResolver.queries()
        XCTAssertEqual(timedOutQueries.count, 1)
        let cancelledResolver = try makeResolver()
        do {
            try await withThrowingTaskGroup(of: ControlledDNSExchangeEvent.self) { group in
                group.addTask {
                    let query = try await cancelledResolver.respondOnce(reply: .withhold)
                    await decoder.cancel()
                    return .query(query)
                }
                group.addTask {
                    .result(try await lookupCurrentPTR(
                        address: "192.0.2.5", packetID: packetID, resolver: .loopback(port: cancelledResolver.port),
                        decoder: decoder, timeout: .seconds(5), maximumOutputBytes: 32_768
                    ))
                }
                for try await _ in group {}
            }
            XCTFail("An explicitly cancelled observed query was reported as success.")
        } catch is CancellationError {}
        let cancelledQueries = await cancelledResolver.queries()
        let observed = try XCTUnwrap(cancelledQueries.first)
        XCTAssertLessThan(Date().timeIntervalSince(observed.receivedAt), 1)
        let reusedResolver = try makeResolver()
        let reused = try await exchangeControlledPTR(
            address: "192.0.2.6", packetID: packetID, resolver: reusedResolver, reply: .pointer("reused.test"), decoder: decoder
        )
        XCTAssertEqual(reused.result.status, .answered, "The same decoder must be reusable after timeout and cancellation cleanup.")
        XCTAssertEqual(try sha256(url: capture), originalHash)
    }

    func testRejectedInputsNeverSendDNSQuery() async throws {
        try requireIsolatedDigConfiguration()
        let resolver = try makeResolver()
        let capture = try makeControlledCapture()
        let originalHash = try sha256(url: capture)
        let packetID = PacketRecordID(artifactID: try PacketArtifactID(sha256: originalHash, sourceURL: capture), frameNumber: 1)
        for address in ["192.0.2.1;echo invalid", "2001:db8::1%en0", "192.0.2.1\u{0000}invalid", "2001:db8::1\u{0000}invalid", ""] {
            do {
                _ = try await lookupCurrentPTR(
                    address: address, packetID: packetID, resolver: .loopback(port: resolver.port),
                    decoder: BoundedDecoder(), timeout: .seconds(5), maximumOutputBytes: 32_768
                )
                XCTFail("An invalid address was accepted.")
            } catch let error as CurrentDNSLookupError {
                guard case .invalidAddress = error else { throw error }
            }
        }
        do {
            _ = try await lookupCurrentPTR(
                address: "192.0.2.1", packetID: packetID, resolver: .loopback(port: 0),
                decoder: BoundedDecoder(), timeout: .seconds(5), maximumOutputBytes: 32_768
            )
            XCTFail("An invalid resolver port was accepted.")
        } catch let error as CurrentDNSLookupError {
            guard case .invalidResolverPort = error else { throw error }
        }
        try await resolver.assertNoQueuedQuery()
        XCTAssertEqual(try sha256(url: capture), originalHash)
    }

    private func requireIsolatedDigConfiguration() throws {
        let configuration = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".digrc")
        guard !FileManager.default.fileExists(atPath: configuration.path) else {
            throw XCTSkip("Controlled dig transport is unverified: ~/.digrc exists and this Apple dig cannot disable it. No lookup was sent.")
        }
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: "/usr/bin/dig"), "The real system dig executable is required.")
    }

    private func makeResolver() throws -> CurrentDNSLoopbackResolver {
        let resolver = try CurrentDNSLoopbackResolver()
        addTeardownBlock { try await resolver.close() }
        return resolver
    }

    private func makeControlledCapture() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-sentinel-controlled-dns-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("generated.pcap")
        try generatedControlledDNSCapture().write(to: url)
        return url
    }
}

private func exchangeControlledPTR(
    address: String, packetID: PacketRecordID, resolver: CurrentDNSLoopbackResolver, reply: ControlledDNSReply, decoder: BoundedDecoder
) async throws -> (result: CurrentPTRLookupResult, query: ControlledDNSQuery) {
    try await withThrowingTaskGroup(of: ControlledDNSExchangeEvent.self) { group in
        group.addTask { .query(try await resolver.respondOnce(reply: reply)) }
        group.addTask {
            .result(try await lookupCurrentPTR(
                address: address, packetID: packetID, resolver: .loopback(port: resolver.port),
                decoder: decoder, timeout: .seconds(5), maximumOutputBytes: 32_768
            ))
        }
        var result: CurrentPTRLookupResult?
        var query: ControlledDNSQuery?
        for try await event in group {
            switch event {
            case let .result(value): result = value
            case let .query(value): query = value
            }
        }
        guard let result, let query else { throw ControlledDNSError.invalidQuery("incomplete controlled exchange") }
        return (result, query)
    }
}

/// Format-generated classic RAW PCAP containing one captured question/answer; these bytes are never transmitted.
private func generatedControlledDNSCapture() throws -> Data {
    let question = try controlledDNSWireName("captured.test") + Data([0, 1, 0, 1])
    let query = Data([0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]) + question
    let answer = Data([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1])
    let response = Data([0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]) + question + answer
    let frames = [
        try controlledDNSIPv4Packet(payload: query, source: Data([192, 0, 2, 50]), destination: Data([192, 0, 2, 53]), sourcePort: 54_000, destinationPort: 53),
        try controlledDNSIPv4Packet(payload: response, source: Data([192, 0, 2, 53]), destination: Data([192, 0, 2, 50]), sourcePort: 53, destinationPort: 54_000)
    ]
    var capture = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0])
    for (index, frame) in frames.enumerated() {
        for value in [UInt32(1_791_428_448), UInt32(index), UInt32(frame.count), UInt32(frame.count)] {
            var encoded = value.littleEndian
            capture.append(withUnsafeBytes(of: &encoded) { Data($0) })
        }
        capture.append(frame)
    }
    return capture
}

private func controlledDNSIPv4Packet(payload: Data, source: Data, destination: Data, sourcePort: UInt16, destinationPort: UInt16) throws -> Data {
    guard let length = UInt16(exactly: payload.count + 28), let udpLength = UInt16(exactly: payload.count + 8),
          source.count == 4, destination.count == 4 else { throw ControlledDNSError.invalidAnswer }
    var packet = Data([0x45, 0])
    packet.append(controlledDNSBigEndian(length))
    packet.append(Data([0, 1, 0, 0, 64, 17, 0, 0]))
    packet.append(source)
    packet.append(destination)
    packet.append(controlledDNSBigEndian(sourcePort))
    packet.append(controlledDNSBigEndian(destinationPort))
    packet.append(controlledDNSBigEndian(udpLength))
    packet.append(Data([0, 0]))
    packet.append(payload)
    return packet
}
