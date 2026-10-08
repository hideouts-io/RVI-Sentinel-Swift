import Darwin
import XCTest
@testable import RVI_Sentinel

final class PacketPerformanceTests: XCTestCase {
    func testExplicitCancellationAfterFiveThousandDecodedPackets() async throws {
        try requirePacketPerformanceEnvironment()
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-explicit-cancellation.pcap")
        try generatedClassicPacketCapture(packetCount: 100_000).write(to: capture, options: .atomic)
        let digest = try sha256(url: capture)
        let pending = startPerformanceAnalysis(captureURL: capture)
        try await waitForPerformanceProgress(stream: pending.progress, minimumPackets: 5_000)
        let clock = ContinuousClock()
        let cancellationStart = clock.now
        await pending.analyzer.cancel()
        do {
            _ = try await pending.task.value
            XCTFail("Explicit cancellation unexpectedly returned an analysis result.")
        } catch is CancellationError {
            XCTAssertLessThanOrEqual(cancellationStart.duration(to: clock.now), .seconds(1))
        }
        XCTAssertEqual(try sha256(url: capture), digest)
    }

    func testCallerCancellationAfterFiveThousandDecodedPackets() async throws {
        try requirePacketPerformanceEnvironment()
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-caller-cancellation.pcap")
        try generatedClassicPacketCapture(packetCount: 100_000).write(to: capture, options: .atomic)
        let digest = try sha256(url: capture)
        let pending = startPerformanceAnalysis(captureURL: capture)
        try await waitForPerformanceProgress(stream: pending.progress, minimumPackets: 5_000)
        let clock = ContinuousClock()
        let cancellationStart = clock.now
        pending.task.cancel()
        do {
            _ = try await pending.task.value
            XCTFail("Caller cancellation unexpectedly returned an analysis result.")
        } catch is CancellationError {
            XCTAssertLessThanOrEqual(cancellationStart.duration(to: clock.now), .seconds(1))
        }
        XCTAssertEqual(try sha256(url: capture), digest)
    }

    /// Explicitly opt in with RVI_SENTINEL_RUN_PACKET_PERFORMANCE=1; inputs are generated.
    /// RSS is this test process's high-water mark, including prior tests and retained results;
    /// the separate decoder child's RSS is not included.
    func testRealTSharkAtFiftyAndOneHundredThousandPackets() async throws {
        guard ProcessInfo.processInfo.environment["RVI_SENTINEL_RUN_PACKET_PERFORMANCE"] == "1" else {
            throw XCTSkip("Set RVI_SENTINEL_RUN_PACKET_PERFORMANCE=1 to run the bounded large-capture integration benchmark.")
        }
        guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        for count in [50_000, 100_000] {
            let capture = directory.appendingPathComponent("generated-\(count).pcap")
            try generatedClassicPacketCapture(packetCount: count).write(to: capture, options: .atomic)
            let digest = try sha256(url: capture)
            let analyzer = TSharkAnalyzer(decoder: BoundedDecoder())
            let clock = ContinuousClock()
            let decodeStart = clock.now
            let result = try await analyzePerformanceCapture(analyzer: analyzer, captureURL: capture, deadline: .seconds(240))
            let decodeSeconds = packetDurationSeconds(decodeStart.duration(to: clock.now))
            let packets = try XCTUnwrap(result.packetAnalysis)
            XCTAssertEqual(result.summary.packetCount, count)
            XCTAssertEqual(packets.coverage.recordCount, count)
            XCTAssertEqual(packets.records.first?.id.frameNumber, 1)
            XCTAssertEqual(packets.records.last?.id.frameNumber, UInt64(count))
            XCTAssertEqual(packets.sessions.count, 1)
            XCTAssertEqual(packets.sessions.first?.packetCount, count)
            XCTAssertTrue(packets.records.allSatisfy { $0.process.state == .unknown })
            XCTAssertEqual(packets.artifact.source, .unknown)
            XCTAssertEqual(packets.artifact.integrity, .verified)
            XCTAssertFalse(result.coverage.activeResolutionEnabled)
            XCTAssertEqual(packets.artifact.id.sha256, digest)
            XCTAssertEqual(try sha256(url: capture), digest)

            var filterMilliseconds: [Double] = []
            var selectionMilliseconds: [Double] = []
            for index in 0..<20 {
                let search = ["127.0.0.1", "UDP", "53535", "absent-name"][index % 4]
                let query = PacketRecordQuery(text: search, transport: .udp, protocolKind: .udp, interfaceName: nil, processID: nil, direction: nil, recordIDs: nil)
                let filterStart = clock.now
                let page = try pagePacketRecords(result: packets, query: query, page: PacketPageRequest(offset: 0, limit: 100))
                filterMilliseconds.append(packetDurationSeconds(filterStart.duration(to: clock.now)) * 1_000)
                XCTAssertEqual(page.matchingCount, search == "absent-name" ? 0 : count)
                let chosen = packets.records[index * (count / 20)]
                let focused = PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: [chosen.id])
                let selectionStart = clock.now
                let selected = try pagePacketRecords(result: packets, query: focused, page: PacketPageRequest(offset: 0, limit: 1))
                selectionMilliseconds.append(packetDurationSeconds(selectionStart.duration(to: clock.now)) * 1_000)
                XCTAssertEqual(selected.records.first?.id, chosen.id)
            }
            let filterP95 = packetPercentile95(filterMilliseconds)
            let selectionP95 = packetPercentile95(selectionMilliseconds)
            var usage = rusage()
            guard getrusage(RUSAGE_SELF, &usage) == 0 else { throw PacketFixtureError.resourceUsageFailed(code: errno) }
            let observation = PacketPerformanceObservation(packetCount: count, decodeSeconds: decodeSeconds,
                filterP95Milliseconds: filterP95, selectionP95Milliseconds: selectionP95,
                processMaximumResidentBytes: Int64(usage.ru_maxrss), estimatedPacketBytes: packets.coverage.estimatedBytes,
                tsharkVersion: result.coverage.tsharkVersion, operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString)
            let encoded = try JSONEncoder().encode(observation)
            let attachment = XCTAttachment(data: encoded, uniformTypeIdentifier: "public.json")
            attachment.name = "Generated packet performance \(count)"
            attachment.lifetime = .keepAlways
            add(attachment)
            print(String(decoding: encoded, as: UTF8.self))
            XCTAssertLessThanOrEqual(filterP95, 300, "Generated-input filter p95 exceeded the proposed 300 ms target.")
            XCTAssertLessThanOrEqual(selectionP95, 300, "Generated-input selection p95 exceeded the proposed 300 ms target.")
            try FileManager.default.removeItem(at: capture)
        }
    }
}

private struct PendingPerformanceAnalysis {
    let analyzer: TSharkAnalyzer
    let task: Task<NativeAnalysisResult, Error>
    let progress: AsyncStream<AnalysisProgress>
}

private func startPerformanceAnalysis(captureURL: URL) -> PendingPerformanceAnalysis {
    let analyzer = TSharkAnalyzer(decoder: BoundedDecoder())
    let channel = AsyncStream<AnalysisProgress>.makeStream(bufferingPolicy: .bufferingNewest(8))
    let task = Task.detached {
        defer { channel.continuation.finish() }
        return try await analyzer.analyze(captureURL: captureURL, progress: { value in channel.continuation.yield(value) })
    }
    return PendingPerformanceAnalysis(analyzer: analyzer, task: task, progress: channel.stream)
}

private func waitForPerformanceProgress(stream: AsyncStream<AnalysisProgress>, minimumPackets: Int) async throws {
    for await value in stream where value.decodedPackets >= minimumPackets { return }
    throw PacketCancellationVerificationError.requiredProgressNotObserved
}

private func requirePacketPerformanceEnvironment() throws {
    guard ProcessInfo.processInfo.environment["RVI_SENTINEL_RUN_PACKET_PERFORMANCE"] == "1" else {
        throw XCTSkip("Set RVI_SENTINEL_RUN_PACKET_PERFORMANCE=1 to run the generated large-capture cancellation checks.")
    }
    guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
}

private enum PacketCancellationVerificationError: Error { case requiredProgressNotObserved }

private struct PacketPerformanceObservation: Encodable {
    let packetCount: Int
    let decodeSeconds: Double
    let filterP95Milliseconds: Double
    let selectionP95Milliseconds: Double
    let processMaximumResidentBytes: Int64
    let estimatedPacketBytes: Int
    let tsharkVersion: String
    let operatingSystem: String
}

private func analyzePerformanceCapture(analyzer: TSharkAnalyzer, captureURL: URL, deadline: Duration) async throws -> NativeAnalysisResult {
    try await withThrowingTaskGroup(of: NativeAnalysisResult.self) { group in
        group.addTask { try await analyzer.analyze(captureURL: captureURL, progress: { _ in }) }
        group.addTask {
            try await Task.sleep(for: deadline)
            await analyzer.cancel()
            throw PacketFixtureError.analysisTimedOut
        }
        defer { group.cancelAll() }
        guard let first = try await group.next() else { throw PacketFixtureError.analysisTimedOut }
        return first
    }
}

private func packetDurationSeconds(_ duration: Duration) -> Double {
    Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1_000_000_000_000_000_000
}

private func packetPercentile95(_ values: [Double]) -> Double {
    let ordered = values.sorted()
    return ordered[Int(ceil(Double(ordered.count) * 0.95)) - 1]
}
