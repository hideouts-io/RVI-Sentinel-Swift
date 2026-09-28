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

    func testEndpointHostnameLabelsPreserveNameAndProvenance() {
        let timestamp = Date(timeIntervalSince1970: 1_720_000_000)
        let hostnames: [HostnameEvidence] = [
            HostnameEvidence(
                hostname: "resolved.example",
                address: "192.0.2.1",
                provenance: .activeReverseLookup,
                firstSeen: timestamp,
                lastSeen: timestamp,
                confidence: .low,
                isPostCaptureEnrichment: true
            ),
            HostnameEvidence(
                hostname: "captured.example",
                address: "192.0.2.1",
                provenance: .tlsSNI,
                firstSeen: timestamp,
                lastSeen: timestamp,
                confidence: .direct,
                isPostCaptureEnrichment: false
            )
        ]

        XCTAssertEqual(endpointHostnameLabel(address: "192.0.2.1", hostnames: hostnames), "captured.example, resolved.example")
        XCTAssertEqual(endpointHostnameProvenanceLabel(address: "192.0.2.1", hostnames: hostnames), "Active reverse lookup, TLS SNI")
        XCTAssertEqual(endpointHostnameLabel(address: "2001:db8::1", hostnames: hostnames), "Not resolved")
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
        XCTAssertTrue(checks.first { $0.identifier == .trust }?.detail.contains("not paired") == true)
        XCTAssertTrue(checks.first { $0.identifier == .trust }?.correctiveAction.contains("Trust") == true)
    }

    func testDeviceChecksDistinguishDisconnectedFromUntrusted() {
        let checks = deviceChecks(devices: [])

        XCTAssertEqual(checks.first { $0.identifier == .device }?.detail, "No physical iPhone or iPad is visible.")
        XCTAssertTrue(checks.first { $0.identifier == .trust }?.detail.contains("no physical device is visible over USB") == true)
    }

    func testFailedSetupCheckExplainsSafeRetryAndEvidencePreservation() {
        let check = SetupCheck(
            identifier: .trust,
            title: "Device readiness and trust",
            state: .failed,
            detail: "The device is not paired.",
            correctiveAction: "Trust the Mac.",
            evidenceSource: "Synthetic fixture"
        )

        XCTAssertTrue(check.recoveryGuidance.retry.contains("run the checks again"))
        XCTAssertTrue(check.recoveryGuidance.evidenceImpact.contains("does not modify captures, baselines, or exports"))
    }
}
