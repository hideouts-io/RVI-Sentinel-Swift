import XCTest
@testable import RVI_Sentinel

final class DeviceDiscoveryTests: XCTestCase {
    func testParsesReadyPhysicalDeviceAndExcludesSimulator() throws {
        let payload = """
        {
          "info": {"outcome": "success"},
          "result": {
            "devices": [
              {
                "visibilityClass": "default",
                "deviceProperties": {
                  "name": "Research iPhone",
                  "osVersionNumber": "26.3.1",
                  "bootState": "booted"
                },
                "hardwareProperties": {
                  "reality": "physical",
                  "platform": "iOS",
                  "udid": "SYNTHETIC-PHYSICAL-DEVICE",
                  "marketingName": "iPhone 17 Pro",
                  "productType": "iPhone18,1"
                },
                "connectionProperties": {
                  "pairingState": "paired",
                  "transportType": "wired"
                }
              },
              {
                "visibilityClass": "default",
                "deviceProperties": {
                  "name": "Simulator",
                  "osVersionNumber": "26.3.1",
                  "bootState": "booted"
                },
                "hardwareProperties": {
                  "reality": "simulated",
                  "platform": "iOS",
                  "udid": "SIMULATOR-ID",
                  "marketingName": "iPhone Simulator",
                  "productType": "iPhone18,1"
                },
                "connectionProperties": {
                  "pairingState": "paired",
                  "transportType": "wired"
                }
              }
            ]
          }
        }
        """

        let devices = try parseDeviceControlOutput(data: Data(payload.utf8))

        XCTAssertEqual(devices.count, 1)
        XCTAssertEqual(devices[0].name, "Research iPhone")
        XCTAssertEqual(devices[0].readiness, .ready)
        XCTAssertEqual(devices[0].status, "Ready — paired over USB")
    }

    func testReadinessExplainsEveryFailedRequirement() {
        let description = readinessDescription(
            bootState: "unknown",
            pairingState: "unpaired",
            transport: "network",
            visibility: "paired"
        )

        XCTAssertTrue(description.contains("not paired"))
        XCTAssertTrue(description.contains("not connected by USB"))
        XCTAssertTrue(description.contains("not booted"))
        XCTAssertTrue(description.contains("not currently available"))
    }
}
