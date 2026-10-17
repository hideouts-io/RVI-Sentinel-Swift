import XCTest
@testable import RVI_Sentinel

final class AnalyzerPacketIntegrationTests: XCTestCase {
    func testRealDecoderPreservesExplicitZeroProcessID() async throws {
        _ = try XCTUnwrap(resolveTShark(), "TShark is required for the recorded zero-PID integration case.")
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-zero-process-id.pcapng")
        var bytes = try generatedAppleMetadataPacketCapture()
        // Change only the synthetic Apple PIB's recorded PID, retaining its generated name.
        let processBlock = try XCTUnwrap(bytes.range(of: Data([0x01, 0x00, 0x00, 0x80])))
        let processIDRange = (processBlock.lowerBound + 8)..<(processBlock.lowerBound + 12)
        XCTAssertEqual(bytes.subdata(in: processIDRange), Data([0x57, 0x01, 0x00, 0x00]))
        bytes.replaceSubrange(processIDRange, with: Data([0x00, 0x00, 0x00, 0x00]))
        try bytes.write(to: capture, options: .atomic)
        let digest = try sha256(url: capture)
        let result = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, progress: { _ in })
        let packets = try XCTUnwrap(result.packetAnalysis)
        XCTAssertEqual(packets.records.count, 2)
        XCTAssertTrue(packets.records.allSatisfy { $0.process.state == .recorded && $0.process.processID == 0 && $0.process.name == "maild" })
        XCTAssertEqual(packets.sessions.first?.process.processID, 0)
        XCTAssertEqual(packets.artifact.source, .unknown)
        XCTAssertFalse(result.coverage.activeResolutionEnabled)
        XCTAssertEqual(try sha256(url: capture), digest)
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testOriginalPCAPNGMetadataReadsBigEndianSectionsAndResetsProcessIndices() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-big-endian-sections.pcapng")
        let section = generatedBigEndianProcessMetadataSection()
        let bytes = section + section
        try bytes.write(to: capture, options: .atomic)
        let metadata = try XCTUnwrap(readApplePCAPNGMetadata(url: capture, limits: .standard))
        XCTAssertEqual(metadata.frameCount, 2)
        for frame: UInt64 in [1, 2] {
            XCTAssertEqual(metadata.processes[frame]?.primary, ApplePCAPNGProcess(pid: 343, name: "fixture-main"))
            XCTAssertEqual(metadata.processes[frame]?.effective, ApplePCAPNGProcess(pid: 0, name: "fixture-kernel"))
        }
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testOriginalPCAPNGMetadataRejectsMalformedBlocksOptionsAndReferences() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let valid = try generatedAppleMetadataPacketCapture()
        let packet = try metadataFixtureBlockRange(bytes: valid, type: 6)
        let process = try metadataFixtureBlockRange(bytes: valid, type: 0x80000001)
        var variants: [Data] = [Data(valid.dropLast())]
        var trailer = valid
        trailer[packet.upperBound - 4] ^= 4
        variants.append(trailer)
        var byteOrder = valid
        byteOrder[8] = 0
        variants.append(byteOrder)
        var alignment = valid
        alignment[packet.lowerBound + 4] |= 1
        variants.append(alignment)
        var reference = valid
        let referenceOption = try XCTUnwrap(reference.range(of: Data([0x01, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]), in: packet))
        reference[referenceOption.lowerBound + 4] = 99
        variants.append(reference)
        var truncatedOption = valid
        truncatedOption[process.upperBound - 8] = 1
        truncatedOption[process.upperBound - 6] = 4
        variants.append(truncatedOption)
        // The second section's packet still references index zero after its PIB is removed.
        var missingSectionProcess = valid
        missingSectionProcess.removeSubrange(process)
        variants.append(valid + missingSectionProcess)
        for (index, bytes) in variants.enumerated() {
            let capture = directory.appendingPathComponent("malformed-original-\(index).pcapng")
            try bytes.write(to: capture, options: .atomic)
            XCTAssertThrowsError(try readApplePCAPNGMetadata(url: capture, limits: .standard)) { error in
                XCTAssertTrue(error is ApplePCAPNGMetadataError, "Malformed metadata must fail explicitly: \(error)")
            }
            XCTAssertThrowsError(try streamApplePCAPNGMetadata(url: capture, consume: { _, _ in })) { error in
                guard case ApplePCAPNGMetadataError.malformed = error else { return XCTFail("Streaming hid malformed metadata: \(error)") }
            }
            XCTAssertEqual(try Data(contentsOf: capture), bytes)
        }
    }

    func testOriginalPCAPNGMetadataAcceptsOptionsEndingExactlyAtBlockBoundary() async throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-options-without-end-marker.pcapng")
        var bytes = try generatedAppleMetadataPacketCapture()
        // Remove only opt_endofopt from each generated block and update its framing.
        var offset = 0
        while offset < bytes.count {
            let type = bytes.subdata(in: offset..<(offset + 4)).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
            let length = bytes.subdata(in: (offset + 4)..<(offset + 8)).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
            if [UInt32(1), 0x80000001, 6].contains(type) {
                let end = offset + Int(length)
                XCTAssertEqual(bytes.subdata(in: (end - 8)..<(end - 4)), Data([0, 0, 0, 0]))
                bytes.removeSubrange((end - 8)..<(end - 4))
                let shorter = metadataLittleEndian(length - 4)
                bytes.replaceSubrange((offset + 4)..<(offset + 8), with: shorter)
                bytes.replaceSubrange((end - 8)..<(end - 4), with: shorter)
                offset += Int(length - 4)
            } else { offset += Int(length) }
        }
        try bytes.write(to: capture, options: .atomic)
        let metadata = try XCTUnwrap(readApplePCAPNGMetadata(url: capture, limits: .standard))
        XCTAssertEqual(metadata.frameCount, 2)
        XCTAssertEqual(metadata.processes[1]?.primary, ApplePCAPNGProcess(pid: 343, name: "maild"))
        XCTAssertEqual(metadata.processes[2]?.primary, ApplePCAPNGProcess(pid: 343, name: "maild"))
        let result = try await TSharkAnalyzer(decoder: BoundedDecoder()).analyze(captureURL: capture, progress: { _ in })
        XCTAssertEqual(result.summary.packetCount, 2)
        XCTAssertTrue(try XCTUnwrap(result.packetAnalysis).records.allSatisfy { $0.process.processID == 343 })
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testOriginalPCAPNGMetadataRetainsPKTAPConflictAndRejectsDecoderDisagreement() throws {
        let process = ApplePCAPNGProcess(pid: 0, name: "fixture-kernel")
        let metadata = ApplePCAPNGMetadata(frameCount: 1, processes: [1: ApplePCAPNGFrameProcesses(primary: process, effective: nil)])
        let values: [TSharkField: [String]] = [.frameNumber: ["1"], .frameTimeEpoch: ["1700000000.0"], .frameLength: ["28"], .frameCapturedLength: ["28"], .frameProtocols: ["raw:ip:udp"], .pktapProcessID: ["343"], .pktapProcessName: ["fixture-other"]]
        let merged = try applyingApplePCAPNGProcesses(packet: DecodedPacket(values: values), metadata: metadata)
        XCTAssertEqual(try applyingApplePCAPNGProcesses(packet: DecodedPacket(values: values), processes: metadata.processes[1]).values, merged.values)
        let artifactID = try PacketArtifactID(sha256: String(repeating: "a", count: 64), sourceURL: URL(fileURLWithPath: "/tmp/generated-process-conflict.pcapng"))
        let record = try decodePacketRecord(packet: merged, artifact: PacketCaptureArtifact(id: artifactID, source: .unknown, integrity: .verified))
        XCTAssertEqual(record.process.state, .conflict)
        XCTAssertEqual(Set(record.process.labels.compactMap(\.processID)), [0, 343])
        XCTAssertEqual(Set(record.process.labels.map(\.source)), [.applePCAPNG, .pktapHeader])
        var conflicting = values
        conflicting[.darwinProcessID] = ["344"]
        XCTAssertThrowsError(try applyingApplePCAPNGProcesses(packet: DecodedPacket(values: conflicting), metadata: metadata)) { error in
            guard case ApplePCAPNGMetadataError.decoderConflict(frame: 1, field: .darwinProcessID) = error else { return XCTFail("Unexpected decoder disagreement: \(error)") }
        }
        XCTAssertThrowsError(try applyingApplePCAPNGProcesses(packet: DecodedPacket(values: conflicting), processes: metadata.processes[1])) { error in
            guard case ApplePCAPNGMetadataError.decoderConflict(frame: 1, field: .darwinProcessID) = error else { return XCTFail("Unexpected streaming decoder disagreement: \(error)") }
        }
    }

    func testOriginalPCAPNGMetadataCancellationAndFrameLimitFailExplicitly() async throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-metadata-limits.pcapng")
        let bytes = try generatedAppleMetadataPacketCapture()
        try bytes.write(to: capture, options: .atomic)
        let bounded = ApplePCAPNGMetadataLimits(maximumCaptureBytes: 1_048_576, maximumFrames: 1, maximumProcesses: 10, maximumOptionBytes: 1_024, maximumMetadataBytes: 1_024, timeout: .seconds(10))
        XCTAssertThrowsError(try readApplePCAPNGMetadata(url: capture, limits: bounded))
        let task = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try readApplePCAPNGMetadata(url: capture, limits: .standard)
        }
        do { _ = try await task.value; XCTFail("Cancelled metadata read succeeded.") }
        catch is CancellationError { }
        catch { XCTFail("Cancellation was converted to another result: \(error)") }
        let streaming = Task.detached {
            try streamApplePCAPNGMetadata(url: capture) { _, _ in
                withUnsafeCurrentTask { $0?.cancel() }
            }
        }
        do { _ = try await streaming.value; XCTFail("Streaming ignored cancellation after its first callback.") }
        catch is CancellationError { }
        catch { XCTFail("Streaming cancellation was converted to another result: \(error)") }
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testStreamingApplePCAPNGMetadataExceedsFrameAndRetainedMetadataLimits() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-large-metadata.pcapng")
        // These references exceed both the old 200,000-frame and 64-MiB metadata bounds.
        let repeatedFrames = 262_145
        let bytes = try generatedStreamingApplePCAPNGCapture(repeatedFrames: repeatedFrames)
        try bytes.write(to: capture, options: .atomic)
        var callbacks: UInt64 = 0
        var lastFrame: UInt64 = 0
        var lastProcesses: ApplePCAPNGFrameProcesses?
        let count = try streamApplePCAPNGMetadata(url: capture) { frame, processes in
            callbacks += 1
            // One packet without process options precedes the final big-endian section.
            let expectedFrame = callbacks <= UInt64(repeatedFrames) ? callbacks : callbacks + 1
            guard frame == expectedFrame else { throw PacketFixtureError.invalidBlock }
            if frame == 1 {
                XCTAssertEqual(processes.primary, ApplePCAPNGProcess(pid: 343, name: "maild"))
                XCTAssertNil(processes.effective)
            }
            lastFrame = frame
            lastProcesses = processes
        }
        XCTAssertEqual(count, UInt64(repeatedFrames + 2))
        XCTAssertEqual(callbacks, UInt64(repeatedFrames + 1))
        XCTAssertEqual(lastFrame, UInt64(repeatedFrames + 2))
        XCTAssertEqual(lastProcesses?.primary, ApplePCAPNGProcess(pid: 343, name: "fixture-main"))
        XCTAssertEqual(lastProcesses?.effective, ApplePCAPNGProcess(pid: 0, name: "fixture-kernel"))
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testStreamingApplePCAPNGMetadataPropagatesConsumerFailureAndValidatesTrailerBeforeCallback() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-stream-failure.pcapng")
        let bytes = try generatedAppleMetadataPacketCapture()
        try bytes.write(to: capture, options: .atomic)
        var callbacks = 0
        XCTAssertThrowsError(try streamApplePCAPNGMetadata(url: capture, consume: { _, _ in
            callbacks += 1
            throw PacketFixtureError.invalidCount
        })) { error in
            guard case PacketFixtureError.invalidCount = error else { return XCTFail("Consumer failure was replaced: \(error)") }
        }
        XCTAssertEqual(callbacks, 1)
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
        var malformed = bytes
        malformed[malformed.count - 4] ^= 4
        try malformed.write(to: capture, options: .atomic)
        var validatedFrames: [UInt64] = []
        XCTAssertThrowsError(try streamApplePCAPNGMetadata(url: capture, consume: { frame, _ in
            validatedFrames.append(frame)
        })) { error in
            guard case ApplePCAPNGMetadataError.malformed = error else { return XCTFail("Malformed trailer was hidden: \(error)") }
        }
        XCTAssertEqual(validatedFrames, [1])
        XCTAssertEqual(try Data(contentsOf: capture), malformed)
    }

    func testStreamedApplePCAPNGProcessesRequireOnePositiveDecimalFrameID() throws {
        let processes = ApplePCAPNGFrameProcesses(primary: ApplePCAPNGProcess(pid: 343, name: "fixture-main"), effective: ApplePCAPNGProcess(pid: 0, name: "fixture-kernel"))
        let invalid: [[String]] = [[], ["0"], ["-1"], ["+1"], [" 1"], ["1.0"], ["18446744073709551616"], ["1", "2"]]
        for frames in invalid {
            let packet = DecodedPacket(values: [.frameNumber: frames])
            XCTAssertThrowsError(try applyingApplePCAPNGProcesses(packet: packet, processes: nil))
            XCTAssertThrowsError(try applyingApplePCAPNGProcesses(packet: packet, processes: processes))
        }
        let packet = DecodedPacket(values: [.frameNumber: [String(UInt64.max)]])
        XCTAssertEqual(try applyingApplePCAPNGProcesses(packet: packet, processes: nil).values, packet.values)
        let merged = try applyingApplePCAPNGProcesses(packet: packet, processes: processes)
        XCTAssertEqual(merged.all(.darwinProcessID), ["343"])
        XCTAssertEqual(merged.all(.darwinEffectiveProcessID), ["0"])
        var conflicting = packet.values
        conflicting[.darwinEffectiveProcessName] = ["fixture-other"]
        XCTAssertThrowsError(try applyingApplePCAPNGProcesses(packet: DecodedPacket(values: conflicting), processes: processes)) { error in
            guard case ApplePCAPNGMetadataError.decoderConflict(frame: UInt64.max, field: .darwinEffectiveProcessName) = error else { return XCTFail("Effective process disagreement was hidden: \(error)") }
        }
    }

    func testStreamingApplePCAPNGMetadataSkipsClassicPCAPAndRejectsNonregularFiles() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-stream-classic.pcap")
        let bytes = try generatedClassicPacketCapture(packetCount: 1)
        try bytes.write(to: capture, options: .atomic)
        XCTAssertNil(try streamApplePCAPNGMetadata(url: capture, consume: { _, _ in
            XCTFail("Classic PCAP emitted PCAPNG process facts.")
        }))
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
        XCTAssertThrowsError(try streamApplePCAPNGMetadata(url: directory, consume: { _, _ in })) { error in
            guard case CaptureEvidenceError.nonregularFile = error else { return XCTFail("Nonregular input was not rejected: \(error)") }
        }
    }

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

private func metadataFixtureBlockRange(bytes: Data, type: UInt32) throws -> Range<Int> {
    var offset = 0
    while offset < bytes.count {
        guard bytes.count - offset >= 12 else { throw PacketFixtureError.invalidBlock }
        let blockType = bytes.subdata(in: offset..<(offset + 4)).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
        let length = bytes.subdata(in: (offset + 4)..<(offset + 8)).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
        guard length >= 12, Int(length) <= bytes.count - offset else { throw PacketFixtureError.invalidBlock }
        if blockType == type { return offset..<(offset + Int(length)) }
        offset += Int(length)
    }
    throw PacketFixtureError.invalidBlock
}

/// Compact zero-payload packets exercise large-file traversal without large fixture storage.
private func generatedStreamingApplePCAPNGCapture(repeatedFrames: Int) throws -> Data {
    guard repeatedFrames > 0 else { throw PacketFixtureError.invalidCount }
    let seed = try generatedAppleMetadataPacketCapture()
    let packetRange = try metadataFixtureBlockRange(bytes: seed, type: 6)
    var bytes = Data(seed.prefix(packetRange.lowerBound))
    let reference = metadataLittleEndian(UInt16(0x8001)) + metadataLittleEndian(UInt16(4)) + metadataLittleEndian(UInt32(0))
    let packet = metadataLittleEndian(UInt32(6)) + metadataLittleEndian(UInt32(40)) + Data(repeating: 0, count: 20) + reference + metadataLittleEndian(UInt32(40))
    for _ in 0..<repeatedFrames { bytes.append(packet) }
    bytes.append(metadataLittleEndian(UInt32(6)) + metadataLittleEndian(UInt32(32)) + Data(repeating: 0, count: 20) + metadataLittleEndian(UInt32(32)))
    bytes.append(generatedBigEndianProcessMetadataSection())
    return bytes
}

private func metadataBigEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

private func metadataLittleEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.littleEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

private func metadataBigEndianOption(code: UInt16, value: Data) -> Data {
    metadataBigEndian(code) + metadataBigEndian(UInt16(value.count)) + value + Data(repeating: 0, count: (4 - value.count % 4) % 4)
}

private func metadataBigEndianBlock(type: UInt32, body: Data) -> Data {
    let length = UInt32(body.count + 12)
    return metadataBigEndian(type) + metadataBigEndian(length) + body + metadataBigEndian(length)
}

/// Format-generated big-endian block headers with the independent little-endian Apple values.
private func generatedBigEndianProcessMetadataSection() -> Data {
    let end = metadataBigEndianOption(code: 0, value: Data())
    let section = metadataBigEndianBlock(type: 0x0a0d0d0a, body: metadataBigEndian(UInt32(0x1a2b3c4d)) + metadataBigEndian(UInt16(1)) + metadataBigEndian(UInt16(0)) + metadataBigEndian(UInt64.max))
    let interface = metadataBigEndianBlock(type: 1, body: metadataBigEndian(UInt16(101)) + metadataBigEndian(UInt16(0)) + metadataBigEndian(UInt32(65_535)) + end)
    let primary = metadataBigEndianBlock(type: 0x80000001, body: metadataLittleEndian(UInt32(343)) + metadataBigEndianOption(code: 2, value: Data("fixture-main".utf8)) + end)
    let effective = metadataBigEndianBlock(type: 0x80000001, body: metadataLittleEndian(UInt32(0)) + metadataBigEndianOption(code: 2, value: Data("fixture-kernel".utf8)) + end)
    let packet = generatedLoopbackUDPPacket()
    let fixed = metadataBigEndian(UInt32(0)) + metadataBigEndian(UInt32(0)) + metadataBigEndian(UInt32(1)) + metadataBigEndian(UInt32(packet.count)) + metadataBigEndian(UInt32(packet.count))
    let options = metadataBigEndianOption(code: 0x8001, value: metadataLittleEndian(UInt32(0))) + metadataBigEndianOption(code: 0x8003, value: metadataLittleEndian(UInt32(1))) + end
    return section + interface + primary + effective + metadataBigEndianBlock(type: 6, body: fixed + packet + options)
}
