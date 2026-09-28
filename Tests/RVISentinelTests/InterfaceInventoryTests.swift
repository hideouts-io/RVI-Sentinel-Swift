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

    func testCaptureReportedIOSInterfacesContainOnlyObservedDeviceLabels() {
        let interfaces: [NetworkInterfaceInfo] = captureReportedIOSInterfaces(
            names: ["rvi0", "pdp_ip0", "utun6", "en2", "pdp_ip0"]
        )

        XCTAssertEqual(interfaces.map(\.name), ["en2", "pdp_ip0", "utun6"])
        XCTAssertTrue(interfaces.allSatisfy(\.isUp))
        XCTAssertTrue(interfaces.allSatisfy { $0.owner == .ios })
        XCTAssertTrue(interfaces.allSatisfy { $0.ipv4Addresses.isEmpty && $0.ipv6Addresses.isEmpty })
        XCTAssertTrue(interfaces.allSatisfy { $0.evidenceSource == "Packet metadata field frame.interface_name" })
    }
}
