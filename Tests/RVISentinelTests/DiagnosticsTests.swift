import Foundation
import XCTest
@testable import RVI_Sentinel

final class DiagnosticsTests: XCTestCase {
    func testRedactedDiagnosticsExcludeIdentityPathsAndNetworkEvidence() throws {
        let syntheticIdentifier = "AAAAAAAA" + "-" + String(repeating: "B", count: 16)
        let device = DeviceInfo(
            name: "Private Owner iPhone",
            identifier: syntheticIdentifier,
            model: "iPhone Pro",
            operatingSystem: "iOS 26",
            transport: "wired",
            pairingState: "paired",
            bootState: "booted",
            readiness: .ready,
            status: "Ready"
        )
        let check = SetupCheck(
            identifier: .device,
            title: "Connected device",
            state: .failed,
            detail: "Private Owner iPhone at /Users/private/Research/capture.pcap contacted 192.0.2.44 and phone.example.com with 00:11:22:33:44:55; identifier \(syntheticIdentifier)",
            correctiveAction: "Reconnect Private Owner iPhone",
            evidenceSource: "/Users/private/Library/device.log"
        )
        let input = DiagnosticsInput(
            generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            application: DiagnosticApplication(name: "RVI-Sentinel", version: "1", build: "1", operatingSystem: "macOS", architecture: "arm64"),
            devices: [device],
            setupChecks: [check],
            interfaces: [],
            capturePhase: .failed,
            captureRunning: false,
            validatedCaptureAvailable: false,
            analysisRunning: false,
            analysisResultAvailable: false,
            baselineSelected: false,
            localExportCount: 0,
            recentError: check.detail,
            sensitiveValues: [device.name, device.identifier, "/Users/private/Research/capture.pcap"]
        )

        let encoded = try encodeRedactedDiagnostics(makeRedactedDiagnostics(input: input))

        XCTAssertFalse(encoded.contains(device.name))
        XCTAssertFalse(encoded.contains(device.identifier))
        XCTAssertFalse(encoded.contains("/Users/private"))
        XCTAssertFalse(encoded.contains("192.0.2.44"))
        XCTAssertFalse(encoded.contains("phone.example.com"))
        XCTAssertFalse(encoded.contains("00:11:22:33:44:55"))
        XCTAssertTrue(encoded.contains("<REDACTED>"))
        XCTAssertTrue(encoded.contains("<IP_ADDRESS>"))
        XCTAssertTrue(encoded.contains("<HOSTNAME>"))
        XCTAssertTrue(encoded.contains("<MAC_ADDRESS>"))
    }

    func testDiagnosticsContainCountsAndInterfaceClassificationWithoutAddresses() {
        let interface = NetworkInterfaceInfo(
            name: "en0",
            friendlyType: "Ethernet or Wi-Fi",
            isUp: true,
            ipv4Addresses: ["192.0.2.10"],
            ipv6Addresses: ["2001:db8::10"],
            macAddress: "00:11:22:33:44:55",
            mtu: nil,
            flags: ["UP"],
            linkType: "Ethernet-style link",
            associatedService: "Wi-Fi",
            owner: .mac,
            isSelectable: true,
            evidenceSource: "macOS getifaddrs"
        )
        let input = DiagnosticsInput(
            generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            application: DiagnosticApplication(name: "RVI-Sentinel", version: "1", build: "1", operatingSystem: "macOS", architecture: "arm64"),
            devices: [],
            setupChecks: [],
            interfaces: [interface],
            capturePhase: .idle,
            captureRunning: false,
            validatedCaptureAvailable: false,
            analysisRunning: false,
            analysisResultAvailable: false,
            baselineSelected: false,
            localExportCount: 0,
            recentError: nil,
            sensitiveValues: []
        )

        let diagnostics = makeRedactedDiagnostics(input: input)

        XCTAssertEqual(diagnostics.interfaces, [DiagnosticInterface(name: "en0", friendlyType: "Ethernet or Wi-Fi", isUp: true, owner: .mac, evidenceSource: "macOS getifaddrs")])
        XCTAssertFalse(String(describing: diagnostics).contains("192.0.2.10"))
        XCTAssertFalse(String(describing: diagnostics).contains("2001:db8::10"))
        XCTAssertFalse(String(describing: diagnostics).contains("00:11:22:33:44:55"))
    }
}
