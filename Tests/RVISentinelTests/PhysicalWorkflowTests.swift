import Foundation
import XCTest
@testable import RVI_Sentinel

final class PhysicalWorkflowTests: XCTestCase {
    func testPhysicalCaptureAnalysisBaselineExportsAndDiagnostics() async throws {
        guard let capturePath = ProcessInfo.processInfo.environment["RVI_SENTINEL_PHYSICAL_CAPTURE"], !capturePath.isEmpty else {
            throw XCTSkip("Set RVI_SENTINEL_PHYSICAL_CAPTURE to an authorized local PCAP, PCAPNG, or CAP file.")
        }
        let captureURL = URL(fileURLWithPath: capturePath)
        let workingDirectory = try createTemporaryTestDirectory()
        addTeardownBlock {
            try FileManager.default.removeItem(at: workingDirectory)
        }

        let analyzer = TSharkAnalyzer(decoder: BoundedDecoder())
        let result = try await analyzer.analyze(captureURL: captureURL) { _ in }

        XCTAssertGreaterThan(result.summary.packetCount, 0)
        XCTAssertFalse(result.endpoints.isEmpty)
        XCTAssertFalse(result.protocols.isEmpty)
        XCTAssertFalse(result.summary.captureSHA256.isEmpty)
        XCTAssertTrue(result.coverage.activeResolutionEnabled)
        let observedIOSInterfaces: [NetworkInterfaceInfo] = captureReportedIOSInterfaces(names: result.summary.interfaces)
        XCTAssertFalse(observedIOSInterfaces.isEmpty)
        XCTAssertTrue(observedIOSInterfaces.allSatisfy { $0.owner == .ios && $0.isUp })
        XCTAssertFalse(observedIOSInterfaces.contains { isTemporaryRVIInterface(name: $0.name) })

        let baselineStore = BaselineStore()
        let baselineURL = workingDirectory.appendingPathComponent("physical-device-baseline.json")
        let createdAt = Date(timeIntervalSince1970: 1_800_000_000)
        let baseline = try baselineStore.create(url: baselineURL, scopeName: "Physical device validation", createdAt: createdAt)
        let baselineBeforeComparison = try Data(contentsOf: baselineURL)
        let initialComparison = compareBaseline(document: baseline, result: result, comparedAt: createdAt)

        XCTAssertGreaterThan(initialComparison.count(state: .new), 0)
        XCTAssertEqual(try Data(contentsOf: baselineURL), baselineBeforeComparison)

        let update = try baselineStore.update(url: baselineURL, result: result, reviewedAt: createdAt.addingTimeInterval(30))
        let reviewedComparison = compareBaseline(document: update.document, result: result, comparedAt: createdAt.addingTimeInterval(60))

        XCTAssertTrue(FileManager.default.fileExists(atPath: update.backupURL.path))
        XCTAssertEqual(update.document.capturesReviewed, 1)
        XCTAssertGreaterThan(reviewedComparison.count(state: .known), 0)
        XCTAssertEqual(reviewedComparison.count(state: .new), 0)

        let exporter = ReportExporter()
        for format in ReportExportFormat.allCases {
            let receipt = try exporter.export(result: result, format: format, directory: workingDirectory, generatedAt: createdAt)
            XCTAssertTrue(FileManager.default.fileExists(atPath: receipt.outputURL.path))
            XCTAssertEqual(receipt.sha256.count, 64)
            XCTAssertEqual(receipt.fileCount, format == .csv ? 7 : 1)
        }

        let endpointValues = result.endpoints.map(\.address)
        let hostnameValues = result.hostnames.map(\.hostname)
        let sensitiveValues = [capturePath, captureURL.lastPathComponent] + endpointValues + hostnameValues
        let diagnostics = makeRedactedDiagnostics(input: DiagnosticsInput(
            generatedAt: createdAt,
            application: DiagnosticApplication(name: "RVI-Sentinel", version: "test", build: "test", operatingSystem: "macOS", architecture: currentArchitectureName()),
            devices: [],
            setupChecks: [],
            interfaces: try InterfaceInventoryService().inventory(),
            capturePhase: .completed,
            captureRunning: false,
            validatedCaptureAvailable: true,
            analysisRunning: false,
            analysisResultAvailable: true,
            baselineSelected: true,
            localExportCount: ReportExportFormat.allCases.count,
            recentError: "Validated local capture at \(capturePath); first endpoint \(endpointValues.first ?? "not observed").",
            sensitiveValues: sensitiveValues
        ))
        let encodedDiagnostics = try encodeRedactedDiagnostics(diagnostics)

        for sensitiveValue in sensitiveValues where !sensitiveValue.isEmpty {
            XCTAssertFalse(encodedDiagnostics.contains(sensitiveValue))
        }
        XCTAssertTrue(diagnostics.workflow.validatedCaptureAvailable)
        XCTAssertTrue(diagnostics.workflow.analysisResultAvailable)
        XCTAssertTrue(diagnostics.workflow.baselineSelected)
        XCTAssertEqual(diagnostics.workflow.localExportCount, ReportExportFormat.allCases.count)
    }
}
