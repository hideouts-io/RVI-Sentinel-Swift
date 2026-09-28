import Foundation

enum ReportExportFormat: String, CaseIterable, Identifiable, Sendable {
    case json = "JSON"
    case csv = "CSV bundle"
    case html = "HTML"

    var id: String { rawValue }
}

struct ExportCaptureProvenance: Codable, Equatable, Sendable {
    let sourceFilename: String
    let sha256: String
    let packetCount: Int
    let byteCount: Int64
    let firstPacket: Date?
    let lastPacket: Date?
    let interfaces: [String]
}

struct AnalysisExportDocument: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let generatedAt: Date
    let capture: ExportCaptureProvenance
    let endpoints: [EndpointObservation]
    let hostnames: [HostnameEvidence]
    let protocols: [ProtocolObservation]
    let ports: [PortObservation]
    let coverage: AnalysisCoverage
    let evidenceBoundary: String
}

struct ExportManifestEntry: Codable, Equatable, Identifiable, Sendable {
    let filename: String
    let sha256: String

    var id: String { filename }
}

struct ExportManifest: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let generatedAt: Date
    let captureSHA256: String
    let files: [ExportManifestEntry]
}

struct ExportReceipt: Equatable, Identifiable, Sendable {
    let format: ReportExportFormat
    let outputURL: URL
    let sha256: String
    let createdAt: Date
    let fileCount: Int

    var id: String { "\(format.rawValue)|\(outputURL.path)|\(sha256)" }
}

enum ReportExporterError: LocalizedError {
    case destinationIsNotDirectory(String)
    case destinationExists(String)
    case partialExport(path: String, reason: String)

    var errorDescription: String? {
        switch self {
        case let .destinationIsNotDirectory(path):
            "The export destination is not a directory: \(path)"
        case let .destinationExists(path):
            "The export destination already exists and will not be overwritten: \(path)"
        case let .partialExport(path, reason):
            "Export stopped after creating \(path): \(reason)"
        }
    }
}

func makeExportDocument(result: NativeAnalysisResult, generatedAt: Date) -> AnalysisExportDocument {
    AnalysisExportDocument(
        schemaVersion: 1,
        generatedAt: generatedAt,
        capture: ExportCaptureProvenance(
            sourceFilename: result.summary.captureURL.lastPathComponent,
            sha256: result.summary.captureSHA256,
            packetCount: result.summary.packetCount,
            byteCount: result.summary.byteCount,
            firstPacket: result.summary.firstPacket,
            lastPacket: result.summary.lastPacket,
            interfaces: result.summary.interfaces
        ),
        endpoints: result.endpoints,
        hostnames: result.hostnames,
        protocols: result.protocols,
        ports: result.ports,
        coverage: result.coverage,
        evidenceBoundary: "A new observation is a change to investigate, not proof of malicious activity. Ordinary PCAP/RVI traffic does not prove an iOS process or internal iOS interface."
    )
}
