import XCTest
@testable import RVI_Sentinel

final class CaptureCoordinatorTests: XCTestCase {
    private let readyDevice = DeviceInfo(
        name: "Research iPhone",
        identifier: "SYNTHETIC-PHYSICAL-DEVICE",
        model: "iPhone 17 Pro",
        operatingSystem: "iOS 26.3.1",
        transport: "wired",
        pairingState: "paired",
        bootState: "booted",
        readiness: .ready,
        status: "Ready — paired over USB"
    )

    func testAuthorizedPlanUsesPacketPreflightBoundedTimerAndSIGINT() throws {
        let root = URL(fileURLWithPath: "/tmp/RVI Sentinel Tests")
        let configuration = CaptureConfiguration(
            device: readyDevice,
            durationSeconds: 30,
            format: .pcapng,
            outputURL: root.appendingPathComponent("Authorized Capture.pcapng")
        )

        let plan = try makeAuthorizedCapturePlan(
            configuration: configuration,
            interfaceName: "rvi0",
            temporaryDirectory: root,
            captureUser: "researcher"
        )

        XCTAssertTrue(plan.shellCommand.contains("'-c' '1'"))
        XCTAssertTrue(plan.shellCommand.contains("capture_deadline=$((capture_started_at + 30))"))
        XCTAssertTrue(plan.shellCommand.contains("/bin/kill -INT"))
        XCTAssertFalse(plan.shellCommand.contains("/bin/kill -TERM"))
        XCTAssertTrue(plan.shellCommand.contains("'/tmp/RVI Sentinel Tests/Authorized Capture.pcapng'"))
    }

    func testRejectsUnsafeRVIName() {
        let configuration = CaptureConfiguration(
            device: readyDevice,
            durationSeconds: 30,
            format: .pcapng,
            outputURL: URL(fileURLWithPath: "/tmp/capture.pcapng")
        )

        XCTAssertThrowsError(try makeAuthorizedCapturePlan(
            configuration: configuration,
            interfaceName: "en0; reboot",
            temporaryDirectory: URL(fileURLWithPath: "/tmp/test"),
            captureUser: "researcher"
        ))
    }

    func testCaptureHeadersAreFormatSpecific() {
        XCTAssertTrue(captureHeaderMatches(header: Data([0x0a, 0x0d, 0x0d, 0x0a]), format: .pcapng))
        XCTAssertFalse(captureHeaderMatches(header: Data([0x0a, 0x0d, 0x0d, 0x0a]), format: .pcap))
        XCTAssertTrue(captureHeaderMatches(header: Data([0xd4, 0xc3, 0xb2, 0xa1]), format: .pcap))
    }

    func testParsesMachineReadableCapinfosStatistics() throws {
        let statistics = try parseCapinfosTabOutput(
            output: "/tmp/capture.pcapng\t128\t4096\t30.250000000\n",
            fallbackSize: 4_000
        )

        XCTAssertEqual(statistics.packetCount, 128)
        XCTAssertEqual(statistics.fileSize, 4_096)
        XCTAssertEqual(statistics.actualDuration, 30.25)
    }

    func testShellQuotePreservesLiteralInput() {
        XCTAssertEqual(shellQuote("A path/with spaces"), "'A path/with spaces'")
        XCTAssertEqual(shellQuote("owner's file"), "'owner'\"'\"'s file'")
    }
}
