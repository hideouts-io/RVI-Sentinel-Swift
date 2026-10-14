import XCTest
@testable import RVI_Sentinel

final class AnalyzerPacketIntegrationTests: XCTestCase {
    func testRealDecoderPreservesGeneratedAppleProcessOptionsAndNanosecondTimes() async throws {
        guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-apple-options.pcapng")
        let bytes = try generatedAppleMetadataPacketCapture()
        try bytes.write(to: capture, options: .atomic)
        let before = try sha256(url: capture)
        let result = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, progress: { _ in })
        let packets = try XCTUnwrap(result.packetAnalysis)
        guard result.coverage.supportedFields.contains(.darwinProcessName) else {
            throw XCTSkip("Installed TShark lacks Apple process-option fields; generated metadata integration is unverified.")
        }
        XCTAssertEqual(result.summary.packetCount, 2)
        XCTAssertFalse(result.coverage.activeResolutionEnabled)
        XCTAssertEqual(packets.artifact.source, .unknown)
        XCTAssertEqual(packets.artifact.integrity, .verified)
        XCTAssertEqual(packets.artifact.id.sourceURL, capture)
        XCTAssertEqual(packets.artifact.id.sha256, before)
        XCTAssertEqual(packets.records.map { $0.id.frameNumber }, [1, 2])
        XCTAssertEqual(packets.records.map { $0.timestamp.nanoseconds }, [590_385_001, 590_385_002])
        XCTAssertEqual(packets.records.first?.timestamp.originalText, "1791428448.590385001")
        XCTAssertEqual(packets.records.first?.process.name, "maild")
        XCTAssertEqual(packets.records.first?.process.processID, 343)
        XCTAssertEqual(packets.records.first?.process.labels.first?.source, .applePCAPNG)
        XCTAssertEqual(packets.records.first?.effectiveProcess.state, .unknown)
        XCTAssertEqual(packets.records.first?.interface.name, "fixture0")
        XCTAssertEqual(packets.records.first?.direction.direction, .outbound)
        XCTAssertEqual(packets.sessions.count, 1)
        XCTAssertEqual(packets.sessions.first?.process.name, "maild")
        XCTAssertEqual(packets.sessions.first?.packetCount, 2)
        XCTAssertEqual(try sha256(url: capture), before)
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).count, 1)
    }

    func testRealDecoderKeepsClassicCaptureProcessUnknownAndNoActiveResolution() async throws {
        guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-classic.pcap")
        try generatedClassicPacketCapture(packetCount: 3).write(to: capture, options: .atomic)
        let digest = try sha256(url: capture)
        let result = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, source: .userDeclaredRVI, expectedCaptureSHA256: nil, progress: { _ in })
        let packets = try XCTUnwrap(result.packetAnalysis)
        XCTAssertEqual(result.summary.packetCount, 3)
        XCTAssertFalse(result.coverage.activeResolutionEnabled)
        XCTAssertEqual(packets.artifact.source, .userDeclaredRVI)
        XCTAssertTrue(packets.records.allSatisfy { $0.process.state == .unknown && $0.effectiveProcess.state == .unknown })
        XCTAssertEqual(packets.records.map { $0.id.frameNumber }, [1, 2, 3])
        XCTAssertEqual(packets.sessions.count, 1)
        XCTAssertEqual(packets.sessions.first?.packetCount, 3)
        XCTAssertEqual(packets.artifact.id.sha256, digest)
        XCTAssertEqual(try sha256(url: capture), digest)
    }

    /// Exercises the completion-digest contract with generated data; no device is captured.
    func testCompletedCaptureProvenanceRequiresMatchingDigest() async throws {
        guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-completion-contract.pcapng")
        try generatedAppleMetadataPacketCapture().write(to: capture, options: .atomic)
        let digest = try sha256(url: capture)
        for expected in [String?.none, String(repeating: "0", count: 64)] {
            do {
                _ = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, source: .liveDeviceRVI, expectedCaptureSHA256: expected, progress: { _ in })
                XCTFail("Unverified completion digest granted live-source provenance.")
            } catch let error as NativeAnalysisError {
                guard case .invalidCapture = error else { return XCTFail("Expected invalidCapture, received \(error.localizedDescription)") }
            }
        }
        let matched = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, source: .liveDeviceRVI, expectedCaptureSHA256: digest, progress: { _ in })
        XCTAssertEqual(matched.packetAnalysis?.artifact.source, .liveDeviceRVI)
        XCTAssertEqual(matched.packetAnalysis?.artifact.id.sha256, digest)
        XCTAssertEqual(try sha256(url: capture), digest)
    }
}
