import Darwin
import XCTest
@testable import RVI_Sentinel

final class CaptureEvidenceHashTests: XCTestCase {
    func testHashesKnownSavedBytesWithoutChangingOriginal() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("known.pcap")
        let data = Data("abc".utf8)
        try data.write(to: capture)
        let digest = try hashCaptureBytes(url: capture, maximumBytes: 3, deadline: ContinuousClock().now.advanced(by: .seconds(5)))
        XCTAssertEqual(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(try Data(contentsOf: capture), data)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).map { $0.resolvingSymlinksInPath() }, [capture.resolvingSymlinksInPath()])
    }

    func testRejectsLocalFIFOWithoutWaitingForWriter() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let fifo = directory.appendingPathComponent("unwritten.pcap")
        guard mkfifo(fifo.path, mode_t(0o600)) == 0 else { throw PacketFixtureError.resourceUsageFailed(code: errno) }
        let clock = ContinuousClock()
        let start = clock.now
        XCTAssertThrowsError(try hashCaptureBytes(url: fifo, maximumBytes: 10_000, deadline: start.advanced(by: .seconds(1)))) { error in
            guard case .nonregularFile = error as? CaptureEvidenceError else { return XCTFail("Expected nonregularFile, received \(error.localizedDescription)") }
        }
        XCTAssertLessThan(start.duration(to: clock.now), .seconds(1))
    }

    func testRejectsDirectoryAndMissingOriginalExplicitly() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let deadline = ContinuousClock().now.advanced(by: .seconds(5))
        XCTAssertThrowsError(try hashCaptureBytes(url: directory, maximumBytes: 10_000, deadline: deadline)) { error in
            guard case .nonregularFile = error as? CaptureEvidenceError else { return XCTFail("Expected nonregularFile, received \(error.localizedDescription)") }
        }
        let missing = directory.appendingPathComponent("absent.pcap")
        XCTAssertThrowsError(try hashCaptureBytes(url: missing, maximumBytes: 10_000, deadline: deadline)) { error in
            guard case let .openFailed(_, code) = error as? CaptureEvidenceError else { return XCTFail("Expected openFailed, received \(error.localizedDescription)") }
            XCTAssertEqual(code, ENOENT)
        }
    }

    func testRejectsSavedFileAboveExplicitSizeLimit() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("oversized.pcap")
        let bytes = Data(repeating: 7, count: 1_024)
        try bytes.write(to: capture)
        XCTAssertThrowsError(try hashCaptureBytes(url: capture, maximumBytes: 1_023, deadline: ContinuousClock().now.advanced(by: .seconds(5)))) { error in
            guard case let .sizeLimit(limit) = error as? CaptureEvidenceError else { return XCTFail("Expected sizeLimit, received \(error.localizedDescription)") }
            XCTAssertEqual(limit, 1_023)
        }
        XCTAssertEqual(try Data(contentsOf: capture), bytes)
    }

    func testExpiredDeadlineFailsBeforeReadingSavedBytes() throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("deadline.pcap")
        try Data([1, 2, 3]).write(to: capture)
        XCTAssertThrowsError(try hashCaptureBytes(url: capture, maximumBytes: 3, deadline: ContinuousClock().now.advanced(by: .seconds(-1)))) { error in
            guard case .deadlineExceeded = error as? CaptureEvidenceError else { return XCTFail("Expected deadlineExceeded, received \(error.localizedDescription)") }
        }
    }

    func testCancelledHashStopsBeforeOpeningOriginal() async throws {
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("cancelled.pcap")
        try Data([1, 2, 3]).write(to: capture)
        let task = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try hashCaptureBytes(url: capture, maximumBytes: 3, deadline: ContinuousClock().now.advanced(by: .seconds(5)))
        }
        do {
            _ = try await task.value
            XCTFail("A cancelled hash unexpectedly returned a digest.")
        } catch is CancellationError {
            XCTAssertEqual(try Data(contentsOf: capture), Data([1, 2, 3]))
        }
    }
}
