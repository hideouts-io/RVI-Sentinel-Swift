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

    func testPacketCaptureContentTypesIncludeEverySupportedExtension() {
        let contentTypes = packetCaptureContentTypes()

        XCTAssertEqual(contentTypes.count, supportedPacketCaptureExtensions.count)
        XCTAssertTrue(contentTypes.allSatisfy { $0.conforms(to: .data) })
        XCTAssertEqual(Set(contentTypes.compactMap(\.preferredFilenameExtension)), Set(supportedPacketCaptureExtensions))
    }
}
