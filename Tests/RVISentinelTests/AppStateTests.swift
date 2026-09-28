import UniformTypeIdentifiers
import XCTest
@testable import RVI_Sentinel

final class AppStateTests: XCTestCase {
    func testPacketCaptureContentTypesIncludeEverySupportedExtension() {
        let contentTypes = packetCaptureContentTypes()

        XCTAssertEqual(contentTypes.count, supportedPacketCaptureExtensions.count)
        XCTAssertTrue(contentTypes.allSatisfy { $0.conforms(to: .data) })
        XCTAssertEqual(Set(contentTypes.compactMap(\.preferredFilenameExtension)), Set(supportedPacketCaptureExtensions))
    }
}
