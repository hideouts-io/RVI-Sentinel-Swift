import XCTest
@testable import RVI_Sentinel

final class PacketAnalysisTests: XCTestCase {
    func testParsesQuotedTSVAndRetainsOccurrences() throws {
        let fields: [TSharkField] = [.frameNumber, .dnsQueryName, .tlsSNI]
        let packet = try decodePacketRow(
            row: "\"1\"\t\"one.example\u{1e}two.example\"\t\"api.example\"",
            fields: fields
        )

        XCTAssertEqual(packet.first(.frameNumber), "1")
        XCTAssertEqual(packet.all(.dnsQueryName), ["one.example", "two.example"])
        XCTAssertEqual(packet.first(.tlsSNI), "api.example")
    }

    func testAccumulatorPreservesHostnameProvenanceAndUnknownProcessBoundary() throws {
        let fields: [TSharkField] = [
            .frameNumber, .frameTimeEpoch, .frameLength, .frameProtocols,
            .ipv4Source, .ipv4Destination, .tcpSourcePort, .tcpDestinationPort,
            .dnsResponseName, .dnsA, .tlsSNI
        ]
        let row = [
            "1", "1720000000.0", "128", "eth:ip:tcp:tls:dns",
            "10.0.0.2", "192.0.2.10", "53111", "443",
            "service.example", "192.0.2.10", "service.example"
        ].map { "\"\($0)\"" }.joined(separator: "\t")
        var accumulator = AnalysisAccumulator()
        try accumulator.consume(packet: decodePacketRow(row: row, fields: fields))
        let result = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic.pcapng"),
            hash: String(repeating: "0", count: 64),
            coverage: AnalysisCoverage(tsharkVersion: "Synthetic", supportedFields: fields, unsupportedFields: [], activeResolutionEnabled: false, limitations: [])
        )

        XCTAssertEqual(result.summary.packetCount, 1)
        XCTAssertEqual(result.hostnames.count, 2)
        XCTAssertEqual(Set(result.hostnames.map(\.provenance)), [.capturedDNSAnswer, .tlsSNI])
        XCTAssertTrue(result.endpoints.allSatisfy { $0.processAttribution.confidence == .unavailable })
        XCTAssertEqual(result.ports.first { $0.port == 443 }?.standardService, "HTTPS")
        XCTAssertTrue(result.protocolDetails.contains { detail in
            detail.field == .tlsSNI && detail.value == "service.example" && detail.protocolKind == .tls
        })
    }

    func testProtocolDetailsPreserveTypedFieldEvidenceAndCounts() throws {
        var accumulator = AnalysisAccumulator()
        let packet = DecodedPacket(values: [
            .frameTimeEpoch: ["1700000000.0"],
            .frameLength: ["120"],
            .frameProtocols: ["eth:ip:tcp:tls"],
            .tcpFlags: ["0x0018"],
            .tcpRTT: ["0.042"],
            .tlsVersion: ["0x0304"],
            .tlsCipherSuite: ["0x1301"],
            .tlsALPN: ["h2"]
        ])
        try accumulator.consume(packet: packet)
        try accumulator.consume(packet: packet)

        let result = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic.pcap"),
            hash: String(repeating: "a", count: 64),
            coverage: AnalysisCoverage(
                tsharkVersion: "synthetic",
                supportedFields: TSharkField.allCases,
                unsupportedFields: [],
                activeResolutionEnabled: false,
                limitations: []
            )
        )

        XCTAssertEqual(result.protocolDetails.first { $0.field == .tlsVersion }?.occurrenceCount, 2)
        XCTAssertEqual(result.protocolDetails.first { $0.field == .tcpRTT }?.protocolKind, .tcp)
        XCTAssertEqual(result.protocolDetails.first { $0.field == .tlsALPN }?.label, "ALPN")
        XCTAssertTrue(result.protocolDetails.allSatisfy { !$0.evidenceBoundary.isEmpty })
    }

    func testProtocolDetailCardinalityIsBoundedAndOmissionsAreExplicit() throws {
        var accumulator = AnalysisAccumulator()
        for sequence in 0..<(protocolDetailMaximumDistinctValuesPerField + 4) {
            try accumulator.consume(packet: DecodedPacket(values: [
                .frameTimeEpoch: [String(1_700_000_000 + sequence)],
                .frameLength: ["80"],
                .frameProtocols: ["ip:tcp"],
                .tcpSequence: [String(sequence)]
            ]))
        }

        let result = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic.pcap"),
            hash: String(repeating: "b", count: 64),
            coverage: AnalysisCoverage(tsharkVersion: "synthetic", supportedFields: [.tcpSequence], unsupportedFields: [], activeResolutionEnabled: false, limitations: [])
        )
        let sequenceRows = result.protocolDetails.filter { $0.field == .tcpSequence }

        XCTAssertEqual(sequenceRows.count, protocolDetailMaximumDistinctValuesPerField + 1)
        XCTAssertEqual(sequenceRows.first { $0.value.contains("omitted") }?.occurrenceCount, 4)
    }

    func testCapturedHostnameProvenanceRequiresDirectDecodedEvidence() throws {
        var accumulator = AnalysisAccumulator()
        let packets: [DecodedPacket] = [
            DecodedPacket(values: [
                .frameTimeEpoch: ["1700000000.0"], .frameLength: ["100"], .frameProtocols: ["eth:ip:udp:mdns"],
                .dnsQueryName: ["printer.local"]
            ]),
            DecodedPacket(values: [
                .frameTimeEpoch: ["1700000001.0"], .frameLength: ["110"], .frameProtocols: ["eth:ip:udp:mdns"],
                .dnsQueryName: ["_airplay._tcp.local"]
            ]),
            DecodedPacket(values: [
                .frameTimeEpoch: ["1700000002.0"], .frameLength: ["120"], .frameProtocols: ["eth:ip:tcp:tls"],
                .ipv4Destination: ["192.0.2.20"], .certificateDNSName: ["certificate.example"]
            ]),
            DecodedPacket(values: [
                .frameTimeEpoch: ["1700000003.0"], .frameLength: ["130"], .frameProtocols: ["eth:ip:udp:quic:tls"],
                .ipv4Destination: ["192.0.2.30"], .tlsSNI: ["quic.example"]
            ]),
            DecodedPacket(values: [
                .frameTimeEpoch: ["1700000004.0"], .frameLength: ["140"], .frameProtocols: ["eth:ip:udp:quic:http3"],
                .ipv4Destination: ["192.0.2.40"], .http3Authority: ["http3.example"]
            ])
        ]
        for packet in packets { try accumulator.consume(packet: packet) }

        let result = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic-provenance.pcapng"),
            hash: String(repeating: "d", count: 64),
            coverage: AnalysisCoverage(tsharkVersion: "synthetic", supportedFields: TSharkField.allCases, unsupportedFields: [], activeResolutionEnabled: false, limitations: [])
        )
        let provenanceByHostname = Dictionary(uniqueKeysWithValues: result.hostnames.map { ($0.hostname, $0.provenance) })

        XCTAssertEqual(provenanceByHostname["printer.local"], .capturedMDNS)
        XCTAssertEqual(provenanceByHostname["_airplay._tcp.local"], .capturedDNSSD)
        XCTAssertEqual(provenanceByHostname["certificate.example"], .certificate)
        XCTAssertEqual(provenanceByHostname["quic.example"], .quicHandshake)
        XCTAssertEqual(provenanceByHostname["http3.example"], .http3Authority)
        XCTAssertTrue(result.hostnames.allSatisfy { $0.confidence == .direct && !$0.isPostCaptureEnrichment })
    }

    func testPriorityProtocolFamiliesPreserveTypedDecodedEvidence() throws {
        let fixtures: [(stack: String, field: TSharkField, value: String, expected: ProtocolKind)] = [
            ("eth:ipv6:icmpv6", .icmpv6NeighborSolicitationTarget, "2001:db8::10", .icmpv6),
            ("eth:ipv6:udp:dhcpv6", .dhcpv6MessageType, "1", .dhcpv6),
            ("eth:ip:udp:stun", .stunMappedAddress, "192.0.2.50", .stun),
            ("eth:ip:udp:turnchannel", .turnChannelNumber, "16384", .turn),
            ("eth:ip:udp:rtp", .rtpSSRC, "1234", .rtp),
            ("eth:ip:udp:rtcp", .rtcpType, "200", .rtcp),
            ("eth:ip:tcp:smb2", .smbCommand, "5", .smb),
            ("eth:ip:udp:ntp", .ntpStratum, "2", .ntp),
            ("eth:ip:esp", .espSPI, "0x01020304", .esp),
            ("eth:ip:udp:wg", .wireGuardMessageType, "1", .wireGuard)
        ]
        var accumulator = AnalysisAccumulator()
        for (index, fixture) in fixtures.enumerated() {
            try accumulator.consume(packet: DecodedPacket(values: [
                .frameTimeEpoch: [String(1_700_001_000 + index)],
                .frameLength: ["128"],
                .frameProtocols: [fixture.stack],
                fixture.field: [fixture.value]
            ]))
        }
        let result = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic-protocols.pcapng"),
            hash: String(repeating: "e", count: 64),
            coverage: AnalysisCoverage(tsharkVersion: "synthetic", supportedFields: TSharkField.allCases, unsupportedFields: [], activeResolutionEnabled: false, limitations: [])
        )

        for fixture in fixtures {
            XCTAssertTrue(result.protocolDetails.contains { $0.protocolKind == fixture.expected && $0.field == fixture.field && $0.value == fixture.value })
        }
    }

    func testCatalogFiltersOnlyFieldRecords() {
        let output = "P\tParent\nF\tFrame Number\tframe.number\tFT_UINT32\tframe\nF\tDNS Query\tdns.qry.name\tFT_STRING\tdns\n"
        let catalog = parseTSharkFieldCatalog(output)

        XCTAssertEqual(catalog, ["frame.number", "dns.qry.name"])
    }

    func testTSharkArgumentsEnableIPv4AndIPv6ResolutionAndPreserveFieldOrder() {
        let arguments = tsharkArguments(
            captureURL: URL(fileURLWithPath: "/tmp/authorized.pcapng"),
            fields: [.frameNumber, .dnsQueryName]
        )

        XCTAssertEqual(Array(arguments.prefix(2)), ["-N", "nN"])
        XCTAssertEqual(Array(arguments.suffix(4)), ["-e", "frame.number", "-e", "dns.qry.name"])
    }

    func testActiveResolutionIsPostCaptureEnrichmentWithAddressProvenance() throws {
        let fields: [TSharkField] = [
            .frameTimeEpoch, .frameLength, .frameProtocols,
            .ipv4Source, .ipv4SourceHost, .ipv6Destination, .ipv6DestinationHost
        ]
        let row: String = [
            "1720000000.0", "128", "ip:ipv6:udp",
            "192.0.2.10", "source.example", "2001:db8::10", "destination.example"
        ].map { "\"\($0)\"" }.joined(separator: "\t")
        var accumulator = AnalysisAccumulator()
        try accumulator.consume(packet: decodePacketRow(row: row, fields: fields))
        let result: NativeAnalysisResult = accumulator.result(
            captureURL: URL(fileURLWithPath: "/tmp/synthetic.pcapng"),
            hash: String(repeating: "c", count: 64),
            coverage: AnalysisCoverage(tsharkVersion: "synthetic", supportedFields: fields, unsupportedFields: [], activeResolutionEnabled: true, limitations: [])
        )

        XCTAssertEqual(Set(result.hostnames.map(\.hostname)), ["source.example", "destination.example"])
        XCTAssertEqual(Set(result.hostnames.compactMap(\.address)), ["192.0.2.10", "2001:db8::10"])
        XCTAssertTrue(result.hostnames.allSatisfy { $0.provenance == .activeReverseLookup })
        XCTAssertTrue(result.hostnames.allSatisfy(\.isPostCaptureEnrichment))
        XCTAssertTrue(result.hostnames.allSatisfy { $0.confidence == .low })
    }

    func testAddressClassification() {
        XCTAssertEqual(classifyIPAddress("10.0.0.1"), "Private")
        XCTAssertEqual(classifyIPAddress("100.64.0.1"), "Carrier-grade NAT")
        XCTAssertEqual(classifyIPAddress("169.254.1.1"), "Link-local")
        XCTAssertEqual(classifyIPAddress("192.0.2.1"), "Documentation")
        XCTAssertEqual(classifyIPAddress("::1"), "Loopback")
        XCTAssertEqual(classifyIPAddress("fe80::1"), "Link-local")
    }

    func testRealTSharkAnalysisCompletesForSyntheticCapture() async throws {
        guard resolveTShark() != nil else {
            throw XCTSkip("TShark is not installed on this test host.")
        }
        let captureURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rvi-sentinel-analysis-\(UUID().uuidString).pcap")
        try syntheticUDPPacketCapture().write(to: captureURL, options: .atomic)
        addTeardownBlock {
            try FileManager.default.removeItem(at: captureURL)
        }

        let result = try await TSharkAnalyzer(processRunner: ProcessRunner()).analyze(
            captureURL: captureURL,
            progress: { _ in }
        )

        XCTAssertEqual(result.summary.packetCount, 1)
        XCTAssertEqual(Set(result.endpoints.map(\.address)), ["127.0.0.1"])
        XCTAssertNotNil(result.protocols.first { $0.protocolKind == .udp })
        XCTAssertTrue(result.coverage.activeResolutionEnabled)
    }

    func testRealTSharkRejectsCorruptCaptureWithDecoderDetail() async throws {
        guard resolveTShark() != nil else {
            throw XCTSkip("TShark is not installed on this test host.")
        }
        let captureURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rvi-sentinel-corrupt-\(UUID().uuidString).pcap")
        try Data("not a packet capture".utf8).write(to: captureURL, options: .atomic)
        addTeardownBlock {
            try FileManager.default.removeItem(at: captureURL)
        }

        do {
            _ = try await TSharkAnalyzer(processRunner: ProcessRunner()).analyze(
                captureURL: captureURL,
                progress: { _ in }
            )
            XCTFail("Corrupt capture analysis unexpectedly succeeded.")
        } catch let error as NativeAnalysisError {
            guard case let .decodingFailed(detail) = error else {
                return XCTFail("Expected a decoding failure, received: \(error.localizedDescription)")
            }
            XCTAssertTrue(detail.contains("tshark exit"))
            XCTAssertTrue(detail.localizedCaseInsensitiveContains("capture file"))
        }
    }
}

private func syntheticUDPPacketCapture() -> Data {
    Data([
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2a, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x00, 0x35, 0x14, 0xe9, 0x00, 0x08, 0x00, 0x00
    ])
}
