import XCTest
@testable import RVI_Sentinel

final class InterfaceInventoryTests: XCTestCase {
    func testClassifiesKnownHostAndRVIInterfaces() {
        XCTAssertEqual(classifyInterface(name: "rvi0").owner, .remoteVirtualInterface)
        XCTAssertEqual(classifyInterface(name: "utun4").owner, .vpn)
        XCTAssertEqual(classifyInterface(name: "lo0").friendlyType, "Loopback")
        XCTAssertEqual(classifyInterface(name: "awdl0").associatedService, "AirDrop, AirPlay, and peer services")
        XCTAssertEqual(classifyInterface(name: "en0").owner, .mac)
        XCTAssertEqual(classifyInterface(name: "pdp_ip0").owner, .unknown)
    }

    func testLiveInventoryUsesUniqueNames() throws {
        let interfaces = try InterfaceInventoryService().inventory()
        XCTAssertFalse(interfaces.isEmpty)
        XCTAssertEqual(Set(interfaces.map(\.name)).count, interfaces.count)
        XCTAssertTrue(interfaces.allSatisfy { !$0.evidenceSource.isEmpty })
    }
}
