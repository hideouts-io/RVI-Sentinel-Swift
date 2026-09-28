import Foundation
import XCTest
@testable import RVI_Sentinel

final class BaselineStoreTests: XCTestCase {
    func testComparisonIsReadOnlyUntilExplicitUpdateAndUpdateCreatesBackup() throws {
        let directory = try createTemporaryTestDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let baselineURL = directory.appendingPathComponent("investigation-baseline.json")
        let store = BaselineStore()
        let createdAt = Date(timeIntervalSince1970: 1_720_000_000)
        let document = try store.create(url: baselineURL, scopeName: "Synthetic investigation", createdAt: createdAt)
        let originalData = try Data(contentsOf: baselineURL)
        let result = makeSyntheticAnalysisResult(
            captureURL: URL(fileURLWithPath: "/private/authorized/capture.pcap"),
            hash: String(repeating: "a", count: 64)
        )

        let comparison = compareBaseline(document: document, result: result, comparedAt: createdAt)

        XCTAssertEqual(comparison.count(state: .new), 4)
        XCTAssertEqual(try Data(contentsOf: baselineURL), originalData)

        let update = try store.update(url: baselineURL, result: result, reviewedAt: createdAt.addingTimeInterval(30))

        XCTAssertTrue(FileManager.default.fileExists(atPath: update.backupURL.path))
        XCTAssertEqual(update.document.capturesReviewed, 1)
        XCTAssertEqual(update.document.observations.count, 4)
        let knownComparison = compareBaseline(document: update.document, result: result, comparedAt: createdAt.addingTimeInterval(60))
        XCTAssertEqual(knownComparison.count(state: .known), 4)
        XCTAssertEqual(knownComparison.count(state: .new), 0)
    }

    func testResetKeepsRecoverableBackup() throws {
        let directory = try createTemporaryTestDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let baselineURL = directory.appendingPathComponent("device-baseline.json")
        let store = BaselineStore()
        let createdAt = Date(timeIntervalSince1970: 1_720_000_000)
        _ = try store.create(url: baselineURL, scopeName: "Synthetic device", createdAt: createdAt)
        let result = makeSyntheticAnalysisResult(
            captureURL: URL(fileURLWithPath: "/private/authorized/capture.pcap"),
            hash: String(repeating: "b", count: 64)
        )
        _ = try store.update(url: baselineURL, result: result, reviewedAt: createdAt.addingTimeInterval(30))

        let reset = try store.reset(url: baselineURL, resetAt: createdAt.addingTimeInterval(60))

        XCTAssertTrue(FileManager.default.fileExists(atPath: reset.backupURL.path))
        XCTAssertEqual(reset.document.capturesReviewed, 0)
        XCTAssertTrue(reset.document.observations.isEmpty)
        XCTAssertEqual(try store.load(url: baselineURL), reset.document)
    }
}
