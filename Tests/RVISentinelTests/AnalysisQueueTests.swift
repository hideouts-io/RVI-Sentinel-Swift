import Combine
import XCTest
@testable import RVI_Sentinel

final class AnalysisQueueTests: XCTestCase {
    @MainActor
    func testRealDecoderQueueRetainsBothResultsAndCorruptFileErrorThenRetriesIncomplete() async throws {
        _ = try XCTUnwrap(resolveTShark(), "TShark is required for capture queue integration.")
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let first = directory.appendingPathComponent("first.pcapng")
        let corrupt = directory.appendingPathComponent("corrupt.pcapng")
        let last = directory.appendingPathComponent("last.pcap")
        try generatedAppleMetadataPacketCapture().write(to: first)
        try Data("not a packet capture".utf8).write(to: corrupt)
        try generatedClassicPacketCapture(packetCount: 3).write(to: last)
        let captures = [first, corrupt, last]
        let originalHashes = try captures.map { try sha256(url: $0) }
        let state = AppState.live()
        state.prepareAnalysisQueue(captureURLs: captures)
        state.importedCaptureSource = .userDeclaredRVI
        let ids = state.analysisQueue.map(\.id)

        XCTAssertEqual(state.analysisQueue.map(\.status), [.queued, .queued, .queued])
        XCTAssertFalse(state.isAnalyzing)
        XCTAssertNil(state.analysisResult)
        await state.startAnalysis()

        XCTAssertFalse(state.isAnalyzing)
        XCTAssertEqual(state.analysisQueue.map(\.id), ids)
        XCTAssertEqual(state.analysisQueue.map(\.status), [.completed, .failed, .completed])
        XCTAssertEqual(state.analysisQueue.map(\.captureURL), captures)
        XCTAssertEqual(state.analysisQueue[0].result?.summary.packetCount, 2)
        XCTAssertNotNil(state.analysisQueue[1].error)
        XCTAssertNil(state.analysisQueue[1].result)
        XCTAssertEqual(state.analysisQueue[2].result?.summary.packetCount, 3)
        XCTAssertEqual(state.analysisQueue[0].progress.decodedPackets, 2)
        XCTAssertEqual(state.analysisQueue[2].progress.decodedPackets, 3)
        XCTAssertTrue(state.analysisQueue.allSatisfy { $0.source == .userDeclaredRVI })
        XCTAssertEqual(try captures.map { try sha256(url: $0) }, originalHashes)

        state.selectAnalysisResult(id: ids[2])
        XCTAssertEqual(state.analysisCaptureURL, last)
        XCTAssertEqual(state.analysisResult?.summary.packetCount, 3)
        XCTAssertEqual(state.analysisIntegrity, .verified)
        XCTAssertEqual(state.analysisResult?.coverage.activeResolutionEnabled, false)
        state.selectAnalysisResult(id: ids[0])
        XCTAssertEqual(state.analysisCaptureURL, first)
        XCTAssertEqual(state.analysisResult?.summary.packetCount, 2)
        XCTAssertEqual(state.analysisResult?.packetAnalysis?.artifact.source, .userDeclaredRVI)
        XCTAssertEqual(state.analysisResult?.coverage.activeResolutionEnabled, false)

        let firstResult = state.analysisQueue[0].result
        let lastResult = state.analysisQueue[2].result
        // Repair only the task-owned corrupt fixture, then explicitly retry the queue.
        try generatedClassicPacketCapture(packetCount: 4).write(to: corrupt, options: .atomic)
        let repairedHash = try sha256(url: corrupt)
        await state.startAnalysis()

        XCTAssertEqual(state.analysisQueue.map(\.id), ids)
        XCTAssertEqual(state.analysisQueue.map(\.status), [.completed, .completed, .completed])
        XCTAssertEqual(state.analysisQueue[0].result, firstResult)
        XCTAssertEqual(state.analysisQueue[2].result, lastResult)
        XCTAssertEqual(state.analysisQueue[1].result?.summary.packetCount, 4)
        XCTAssertNil(state.analysisQueue[1].error)
        XCTAssertEqual(state.analysisQueue[1].result?.summary.captureSHA256, repairedHash)
        XCTAssertEqual(try sha256(url: corrupt), repairedHash)
        XCTAssertEqual(try sha256(url: first), originalHashes[0])
        XCTAssertEqual(try sha256(url: last), originalHashes[2])
    }

    @MainActor
    func testCancellingRealDecoderKeepsCompletedResultStopsPendingAndAllowsNewQueue() async throws {
        _ = try XCTUnwrap(resolveTShark(), "TShark is required for queue cancellation integration.")
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let completed = directory.appendingPathComponent("completed.pcap")
        let active = directory.appendingPathComponent("active.pcap")
        let pending = directory.appendingPathComponent("pending.pcap")
        try generatedClassicPacketCapture(packetCount: 2).write(to: completed)
        try generatedClassicPacketCapture(packetCount: 50_000).write(to: active)
        try generatedClassicPacketCapture(packetCount: 3).write(to: pending)
        let captures = [completed, active, pending]
        let originalHashes = try captures.map { try sha256(url: $0) }
        let state = AppState.live()
        state.prepareAnalysisQueue(captureURLs: captures)
        let ids = state.analysisQueue.map(\.id)
        let analysis = Task { await state.startAnalysis() }
        do {
            try await waitForAnalysisQueueDecoderProgress(state: state, itemID: ids[1], minimumPackets: 5_000, timeout: .seconds(240))
        } catch {
            let diagnostics = analysisQueueDiagnostics(state: state)
            await state.cancelAnalysis()
            await analysis.value
            XCTFail("Expected actual decoder progress from the second queue entry before cancellation: \(error.localizedDescription)\nQueue before cleanup:\n\(diagnostics)")
            return
        }

        XCTAssertGreaterThanOrEqual(state.analysisQueue[1].progress.decodedPackets, 5_000)
        XCTAssertEqual(state.analysisQueue[0].status, .completed)
        XCTAssertEqual(state.analysisQueue[2].status, .queued)
        state.selectAnalysisResult(id: ids[0])
        XCTAssertEqual(state.analysisResult?.summary.packetCount, 2)
        state.prepareAnalysisQueue(captureURLs: [pending])
        XCTAssertNotNil(state.lastError)
        XCTAssertEqual(state.analysisQueue.map(\.id), ids)
        await state.startAnalysis()
        XCTAssertTrue(state.isAnalyzing)
        XCTAssertEqual(state.analysisQueue.map(\.id), ids)

        await state.cancelAnalysis()
        await analysis.value

        XCTAssertFalse(state.isAnalyzing)
        XCTAssertEqual(state.analysisQueue.map(\.status), [.completed, .cancelled, .cancelled])
        XCTAssertEqual(state.analysisResult?.summary.packetCount, 2)
        XCTAssertNil(state.analysisQueue[1].result)
        XCTAssertNil(state.analysisQueue[2].result)
        XCTAssertEqual(state.analysisQueue[2].progress.decodedPackets, 0)
        XCTAssertEqual(try captures.map { try sha256(url: $0) }, originalHashes)

        state.prepareAnalysisQueue(captureURLs: [pending])
        XCTAssertNil(state.lastError)
        XCTAssertNil(state.analysisResult)
        XCTAssertEqual(state.analysisQueue.map(\.status), [.queued])
        await state.startAnalysis()

        XCTAssertEqual(state.analysisQueue.map(\.status), [.completed])
        XCTAssertEqual(state.analysisResult?.summary.packetCount, 3)
        XCTAssertEqual(state.analysisResult?.coverage.activeResolutionEnabled, false)
        XCTAssertEqual(try captures.map { try sha256(url: $0) }, originalHashes)
    }
}

private enum AnalysisQueueProgressError: LocalizedError {
    case timedOut(Duration)
    case missingEntry(UUID)
    case entryEnded(AnalysisQueueStatus)
    case progressStreamEnded

    var errorDescription: String? {
        switch self {
        case let .timedOut(timeout): "No decoder progress rendezvous within the real integration timeout of \(timeout)."
        case let .missingEntry(id): "The expected queue entry \(id.uuidString) disappeared."
        case let .entryEnded(status): "The target entry became \(status.rawValue) before the decoder cancellation rendezvous."
        case .progressStreamEnded: "Queue progress observation ended before the decoder cancellation rendezvous."
        }
    }
}

/// Waits for decoded packets from one stable queue identity, rather than a startup status.
@MainActor
private func waitForAnalysisQueueDecoderProgress(state: AppState, itemID: UUID, minimumPackets: Int, timeout: Duration) async throws {
    let channel = AsyncStream<[AnalysisQueueItem]>.makeStream(bufferingPolicy: .bufferingNewest(8))
    let observation = state.$analysisQueue.sink { queue in channel.continuation.yield(queue) }
    defer {
        observation.cancel()
        channel.continuation.finish()
    }
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
            for await queue in channel.stream {
                try Task.checkCancellation()
                guard let item = queue.first(where: { $0.id == itemID }) else { throw AnalysisQueueProgressError.missingEntry(itemID) }
                switch item.status {
                case .queued: continue
                case .analyzing:
                    if item.progress.decodedPackets >= minimumPackets { return }
                case .completed, .failed, .cancelled:
                    throw AnalysisQueueProgressError.entryEnded(item.status)
                }
            }
            try Task.checkCancellation()
            throw AnalysisQueueProgressError.progressStreamEnded
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw AnalysisQueueProgressError.timedOut(timeout)
        }
        defer { group.cancelAll() }
        _ = try await group.next()
    }
    try Task.checkCancellation()
    guard let item = state.analysisQueue.first(where: { $0.id == itemID }) else { throw AnalysisQueueProgressError.missingEntry(itemID) }
    guard state.isAnalyzing, item.status == .analyzing else { throw AnalysisQueueProgressError.entryEnded(item.status) }
}

@MainActor
private func analysisQueueDiagnostics(state: AppState) -> String {
    let entries = state.analysisQueue.map { item in
        "\(item.captureURL.lastPathComponent) [\(item.id.uuidString)]: status=\(item.status.rawValue), decodedPackets=\(item.progress.decodedPackets), progress=\(item.progress.status), error=\(item.error ?? "none")"
    }
    return (["isAnalyzing=\(state.isAnalyzing), progress=\(state.analysisProgress.status), lastError=\(state.lastError ?? "none")"] + entries).joined(separator: "\n")
}
