import UniformTypeIdentifiers
import XCTest
@testable import RVI_Sentinel

final class AppStateTests: XCTestCase {
    func testCurrentTestHostIsRecognizedAsXCTest() {
        XCTAssertTrue(isXCTestProcess(environment: ProcessInfo.processInfo.environment))
    }

    func testNormalLaunchEnvironmentDoesNotBypassSingleInstanceProtection() {
        XCTAssertFalse(isXCTestProcess(environment: ["PATH": "/usr/bin:/bin"]))
        XCTAssertFalse(isXCTestProcess(environment: [
            "XCTestConfigurationFilePath": "   ",
            "XCInjectBundleInto": ""
        ]))
    }

    func testSupportedXCTestMarkersBypassSingleInstanceProtection() {
        XCTAssertTrue(isXCTestProcess(environment: ["XCTestConfigurationFilePath": "/tmp/session.xctestconfiguration"]))
        XCTAssertTrue(isXCTestProcess(environment: ["XCInjectBundleInto": "unused"]))
    }

    @MainActor
    func testRunningAnalysisRejectsDuplicateAndCapturePreparationWithoutClearingBusyState() async throws {
        guard resolveTShark() != nil else { throw XCTSkip("TShark is not installed on this host.") }
        let directory = try createTemporaryTestDirectory()
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("generated-busy.pcap")
        try generatedClassicPacketCapture(packetCount: 50_000).write(to: capture)
        let originalHash = try sha256(url: capture)
        let state = AppState.live()
        state.analysisCaptureURL = capture
        let analysis = Task { await state.startAnalysis() }
        let deadline = ContinuousClock().now + .seconds(5)
        while !state.isAnalyzing && ContinuousClock().now < deadline { await Task.yield() }
        XCTAssertTrue(state.isAnalyzing)
        await state.startAnalysis()
        XCTAssertTrue(state.isAnalyzing)
        XCTAssertEqual(state.analysisCaptureURL, capture)
        XCTAssertNotNil(state.lastError)
        state.prepareCompletedCaptureForAnalysis()
        XCTAssertTrue(state.isAnalyzing)
        XCTAssertEqual(state.analysisCaptureURL, capture)
        await state.cancelAnalysis()
        await analysis.value
        XCTAssertFalse(state.isAnalyzing)
        XCTAssertNil(state.analysisResult)
        XCTAssertEqual(try sha256(url: capture), originalHash)
    }

    func testPacketCaptureContentTypesIncludeEverySupportedExtension() {
        let contentTypes = packetCaptureContentTypes()

        XCTAssertEqual(contentTypes.count, supportedPacketCaptureExtensions.count)
        XCTAssertTrue(contentTypes.allSatisfy { $0.conforms(to: .data) })
        XCTAssertEqual(Set(contentTypes.compactMap(\.preferredFilenameExtension)), Set(supportedPacketCaptureExtensions))
    }
}
