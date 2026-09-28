import XCTest
@testable import RVI_Sentinel

final class EvidenceModelTests: XCTestCase {
    func testHostnameIdentityRetainsProvenance() {
        let timestamp = Date(timeIntervalSince1970: 1_720_000_000)
        let dns = HostnameEvidence(
            hostname: "example.test",
            address: "192.0.2.1",
            provenance: .capturedDNSAnswer,
            firstSeen: timestamp,
            lastSeen: timestamp,
            confidence: .direct,
            isPostCaptureEnrichment: false
        )
        let sni = HostnameEvidence(
            hostname: "example.test",
            address: "192.0.2.1",
            provenance: .tlsSNI,
            firstSeen: timestamp,
            lastSeen: timestamp,
            confidence: .direct,
            isPostCaptureEnrichment: false
        )

        XCTAssertNotEqual(dns.id, sni.id)
    }

    func testUnavailableProcessAttributionDoesNotGuess() {
        let attribution = ProcessAttribution.unavailable(sourceHost: "Connected iPhone")

        XCTAssertEqual(attribution.processName, "Process not observable from this capture")
        XCTAssertEqual(attribution.confidence, .unavailable)
        XCTAssertNil(attribution.processIdentifier)
    }

    func testDeviceChecksSeparateUSBFromTrust() {
        let device = DeviceInfo(
            name: "Research iPhone",
            identifier: "private-identifier",
            model: "iPhone",
            operatingSystem: "iOS",
            transport: "wired",
            pairingState: "unpaired",
            bootState: "booted",
            readiness: .unavailable,
            status: "Not ready — not paired"
        )

        let checks = deviceChecks(devices: [device])
        XCTAssertEqual(checks.first { $0.identifier == .usb }?.state, .passed)
        XCTAssertEqual(checks.first { $0.identifier == .trust }?.state, .failed)
    }
}
