import Foundation
@testable import RVI_Sentinel

func makeSyntheticAnalysisResult(captureURL: URL, hash: String) -> NativeAnalysisResult {
    let first = Date(timeIntervalSince1970: 1_720_000_000)
    let last = first.addingTimeInterval(3)
    let unavailable = ProcessAttribution.unavailable(sourceHost: "iPhone or iPad")
    return NativeAnalysisResult(
        summary: AnalysisSummary(
            captureURL: captureURL,
            captureSHA256: hash,
            packetCount: 4,
            byteCount: 512,
            firstPacket: first,
            lastPacket: last,
            interfaces: ["rvi0"]
        ),
        endpoints: [
            EndpointObservation(
                address: "192.0.2.10",
                version: "IPv4",
                classification: "Documentation",
                firstSeen: first,
                lastSeen: last,
                sourcePackets: 2,
                destinationPackets: 2,
                sourceBytes: 256,
                destinationBytes: 256,
                protocols: [.ipv4, .tcp, .tls],
                ports: ["TCP/443"],
                processAttribution: unavailable
            )
        ],
        hostnames: [
            HostnameEvidence(
                hostname: "service.example",
                address: "192.0.2.10",
                provenance: .tlsSNI,
                firstSeen: first,
                lastSeen: last,
                confidence: .direct,
                isPostCaptureEnrichment: false
            )
        ],
        protocols: [
            ProtocolObservation(protocolKind: .tls, packetCount: 4, byteCount: 512, identification: "captured ClientHello SNI")
        ],
        protocolDetails: [
            ProtocolDetailObservation(
                protocolKind: .tls,
                category: "Handshake",
                label: "TLS version",
                field: .tlsVersion,
                value: "0x0304",
                occurrenceCount: 1,
                evidenceBoundary: "Handshake or tunnel metadata is visible; encrypted application payloads remain protected."
            )
        ],
        ports: [
            PortObservation(
                transport: "TCP",
                port: 443,
                packetCount: 4,
                standardService: "HTTPS",
                explanation: "Commonly used for encrypted web traffic.",
                evidenceBoundary: "Port numbers alone do not prove the application protocol."
            )
        ],
        coverage: AnalysisCoverage(
            tsharkVersion: "TShark synthetic",
            supportedFields: [.frameNumber, .frameTimeEpoch, .frameLength, .frameProtocols, .tlsSNI],
            unsupportedFields: [.certificateSubject],
            activeResolutionEnabled: false,
            limitations: ["Encrypted payloads remain unavailable."]
        )
    )
}

func createTemporaryTestDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-sentinel-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    return url
}
