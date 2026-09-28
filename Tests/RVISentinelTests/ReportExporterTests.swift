import Foundation
import XCTest
@testable import RVI_Sentinel

final class ReportExporterTests: XCTestCase {
    func testJSONExportIsLocalTypedAndExcludesPrivateSourcePath() throws {
        let directory = try createTemporaryTestDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let generatedAt = Date(timeIntervalSince1970: 1_720_000_000)
        let result = makeSyntheticAnalysisResult(
            captureURL: URL(fileURLWithPath: "/Users/private/Investigation/capture.pcap"),
            hash: String(repeating: "c", count: 64)
        )

        let receipt = try ReportExporter().export(result: result, format: .json, directory: directory, generatedAt: generatedAt)
        let data = try Data(contentsOf: receipt.outputURL)
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(AnalysisExportDocument.self, from: data)

        XCTAssertEqual(document.capture.sourceFilename, "capture.pcap")
        XCTAssertFalse(text.contains("/Users/private"))
        XCTAssertEqual(receipt.sha256, try sha256(url: receipt.outputURL))
        XCTAssertEqual(receipt.fileCount, 1)
    }

    func testCSVBundleContainsInventoriesAndHashManifest() throws {
        let directory = try createTemporaryTestDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let generatedAt = Date(timeIntervalSince1970: 1_720_000_000)
        let result = makeSyntheticAnalysisResult(
            captureURL: URL(fileURLWithPath: "/private/authorized/capture.pcap"),
            hash: String(repeating: "d", count: 64)
        )

        let receipt = try ReportExporter().export(result: result, format: .csv, directory: directory, generatedAt: generatedAt)
        let manifestURL = receipt.outputURL.appendingPathComponent("manifest.json")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(ExportManifest.self, from: Data(contentsOf: manifestURL))

        XCTAssertEqual(Set(manifest.files.map(\.filename)), ["coverage.csv", "endpoints.csv", "hostnames.csv", "ports.csv", "protocols.csv"])
        XCTAssertEqual(receipt.fileCount, 6)
        XCTAssertEqual(receipt.sha256, try sha256(url: manifestURL))
        XCTAssertTrue(manifest.files.allSatisfy { !$0.sha256.isEmpty })
    }

    func testHTMLReportEscapesCapturedValues() {
        XCTAssertEqual(htmlEscape("<script>alert('x')</script>"), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")
    }
}
