import Foundation

struct ReportExporter: Sendable {
    func export(
        result: NativeAnalysisResult,
        format: ReportExportFormat,
        directory: URL,
        generatedAt: Date
    ) throws -> ExportReceipt {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ReportExporterError.destinationIsNotDirectory(directory.path)
        }
        let document = makeExportDocument(result: result, generatedAt: generatedAt)
        switch format {
        case .json:
            return try exportJSON(document: document, directory: directory, generatedAt: generatedAt)
        case .csv:
            return try exportCSVBundle(document: document, directory: directory, generatedAt: generatedAt)
        case .html:
            return try exportHTML(document: document, directory: directory, generatedAt: generatedAt)
        }
    }

    private func exportJSON(document: AnalysisExportDocument, directory: URL, generatedAt: Date) throws -> ExportReceipt {
        let url = exportURL(document: document, directory: directory, generatedAt: generatedAt, extensionName: "json")
        let encoder = reportJSONEncoder()
        try writeNew(data: encoder.encode(document), url: url)
        return ExportReceipt(format: .json, outputURL: url, sha256: try sha256(url: url), createdAt: generatedAt, fileCount: 1)
    }

    private func exportHTML(document: AnalysisExportDocument, directory: URL, generatedAt: Date) throws -> ExportReceipt {
        let url = exportURL(document: document, directory: directory, generatedAt: generatedAt, extensionName: "html")
        guard let data = htmlReport(document: document).data(using: .utf8) else {
            throw ReportExporterError.partialExport(path: url.path, reason: "The HTML report could not be encoded as UTF-8.")
        }
        try writeNew(data: data, url: url)
        return ExportReceipt(format: .html, outputURL: url, sha256: try sha256(url: url), createdAt: generatedAt, fileCount: 1)
    }

    private func exportCSVBundle(document: AnalysisExportDocument, directory: URL, generatedAt: Date) throws -> ExportReceipt {
        let base = exportBaseName(document: document, generatedAt: generatedAt)
        let bundleURL = directory.appendingPathComponent("\(base)-csv", isDirectory: true)
        guard !FileManager.default.fileExists(atPath: bundleURL.path) else {
            throw ReportExporterError.destinationExists(bundleURL.path)
        }
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: false)
        do {
            let files: [(String, String)] = [
                ("endpoints.csv", endpointsCSV(document.endpoints)),
                ("hostnames.csv", hostnamesCSV(document.hostnames)),
                ("protocols.csv", protocolsCSV(document.protocols)),
                ("protocol-details.csv", protocolDetailsCSV(document.protocolDetails)),
                ("ports.csv", portsCSV(document.ports)),
                ("coverage.csv", coverageCSV(document.coverage))
            ]
            var entries: [ExportManifestEntry] = []
            for (filename, text) in files {
                let url = bundleURL.appendingPathComponent(filename)
                guard let data = text.data(using: .utf8) else {
                    throw ReportExporterError.partialExport(path: url.path, reason: "The CSV data could not be encoded as UTF-8.")
                }
                try writeNew(data: data, url: url)
                entries.append(ExportManifestEntry(filename: filename, sha256: try sha256(url: url)))
            }
            let manifest = ExportManifest(
                schemaVersion: 1,
                generatedAt: generatedAt,
                captureSHA256: document.capture.sha256,
                files: entries
            )
            let manifestURL = bundleURL.appendingPathComponent("manifest.json")
            try writeNew(data: reportJSONEncoder().encode(manifest), url: manifestURL)
            return ExportReceipt(
                format: .csv,
                outputURL: bundleURL,
                sha256: try sha256(url: manifestURL),
                createdAt: generatedAt,
                fileCount: files.count + 1
            )
        } catch let error as ReportExporterError {
            throw error
        } catch {
            throw ReportExporterError.partialExport(path: bundleURL.path, reason: error.localizedDescription)
        }
    }
}

func reportJSONEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    return encoder
}

func exportBaseName(document: AnalysisExportDocument, generatedAt: Date) -> String {
    let sourceStem = URL(fileURLWithPath: document.capture.sourceFilename).deletingPathExtension().lastPathComponent
    let safeStem = sourceStem.unicodeScalars.map { scalar -> Character in
        CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == "_" ? Character(String(scalar)) : "-"
    }
    let normalized = String(safeStem).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    let stem = normalized.isEmpty ? "capture" : normalized
    return "RVI-Sentinel-\(stem)-\(filenameTimestamp(date: generatedAt))-\(UUID().uuidString.prefix(8))"
}

func exportURL(document: AnalysisExportDocument, directory: URL, generatedAt: Date, extensionName: String) -> URL {
    directory.appendingPathComponent(exportBaseName(document: document, generatedAt: generatedAt)).appendingPathExtension(extensionName)
}

func writeNew(data: Data, url: URL) throws {
    guard !FileManager.default.fileExists(atPath: url.path) else {
        throw ReportExporterError.destinationExists(url.path)
    }
    try data.write(to: url, options: .atomic)
}

func csvRow(_ values: [String]) -> String {
    values.map { value in
        "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
    }.joined(separator: ",")
}

func endpointsCSV(_ endpoints: [EndpointObservation]) -> String {
    let header = csvRow(["address", "version", "classification", "first_seen", "last_seen", "source_packets", "destination_packets", "source_bytes", "destination_bytes", "protocols", "ports", "process_attribution"])
    let rows = endpoints.map { endpoint in
        csvRow([
            endpoint.address,
            endpoint.version,
            endpoint.classification,
            endpoint.firstSeen.ISO8601Format(),
            endpoint.lastSeen.ISO8601Format(),
            String(endpoint.sourcePackets),
            String(endpoint.destinationPackets),
            String(endpoint.sourceBytes),
            String(endpoint.destinationBytes),
            endpoint.protocols.map(\.rawValue).joined(separator: "; "),
            endpoint.ports.joined(separator: "; "),
            endpoint.processAttribution.processName
        ])
    }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func hostnamesCSV(_ hostnames: [HostnameEvidence]) -> String {
    let header = csvRow(["hostname", "address", "provenance", "first_seen", "last_seen", "confidence", "post_capture_enrichment"])
    let rows = hostnames.map { hostname in
        csvRow([
            hostname.hostname,
            hostname.address ?? "",
            hostname.provenance.rawValue,
            hostname.firstSeen.ISO8601Format(),
            hostname.lastSeen.ISO8601Format(),
            hostname.confidence.rawValue,
            String(hostname.isPostCaptureEnrichment)
        ])
    }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func protocolsCSV(_ protocols: [ProtocolObservation]) -> String {
    let header = csvRow(["protocol", "packets", "bytes", "identification_evidence"])
    let rows = protocols.map { observation in
        csvRow([observation.protocolKind.rawValue, String(observation.packetCount), String(observation.byteCount), observation.identification])
    }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func protocolDetailsCSV(_ details: [ProtocolDetailObservation]) -> String {
    let header = csvRow(["protocol", "category", "label", "tshark_field", "observed_value", "occurrence_count", "evidence_boundary"])
    let rows = details.map { detail in
        csvRow([
            detail.protocolKind.rawValue,
            detail.category,
            detail.label,
            detail.field.rawValue,
            detail.value,
            String(detail.occurrenceCount),
            detail.evidenceBoundary
        ])
    }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func portsCSV(_ ports: [PortObservation]) -> String {
    let header = csvRow(["transport", "port", "observed_packets", "standard_service", "usual_purpose", "evidence_boundary"])
    let rows = ports.map { port in
        csvRow([port.transport, String(port.port), String(port.packetCount), port.standardService, port.explanation, port.evidenceBoundary])
    }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func coverageCSV(_ coverage: AnalysisCoverage) -> String {
    let header = csvRow(["category", "value"])
    let rows = [
        csvRow(["tshark_version", coverage.tsharkVersion]),
        csvRow(["active_resolution", String(coverage.activeResolutionEnabled)]),
        csvRow(["supported_fields", coverage.supportedFields.map(\.rawValue).joined(separator: "; ")]),
        csvRow(["unsupported_fields", coverage.unsupportedFields.map(\.rawValue).joined(separator: "; ")]),
        csvRow(["limitations", coverage.limitations.joined(separator: "; ")])
    ]
    return ([header] + rows).joined(separator: "\n") + "\n"
}

func htmlReport(document: AnalysisExportDocument) -> String {
    let endpoints = document.endpoints.map { endpoint in
        "<tr><td>\(htmlEscape(endpoint.address))</td><td>\(htmlEscape(endpoint.classification))</td><td>\(endpoint.sourcePackets)</td><td>\(endpoint.destinationPackets)</td><td>\(htmlEscape(endpoint.protocols.map(\.rawValue).joined(separator: ", ")))</td><td>\(htmlEscape(endpoint.processAttribution.processName))</td></tr>"
    }.joined(separator: "\n")
    let hostnames = document.hostnames.map { hostname in
        "<tr><td>\(htmlEscape(hostname.hostname))</td><td>\(htmlEscape(hostname.address ?? "Not established"))</td><td>\(htmlEscape(hostname.provenance.rawValue))</td><td>\(htmlEscape(hostname.confidence.rawValue))</td></tr>"
    }.joined(separator: "\n")
    let protocols = document.protocols.map { observation in
        "<tr><td>\(htmlEscape(observation.protocolKind.rawValue))</td><td>\(observation.packetCount)</td><td>\(observation.byteCount)</td><td>\(htmlEscape(observation.identification))</td></tr>"
    }.joined(separator: "\n")
    let ports = document.ports.map { port in
        "<tr><td>\(htmlEscape(port.transport))</td><td>\(port.port)</td><td>\(htmlEscape(port.standardService))</td><td>\(htmlEscape(port.explanation))</td><td>\(htmlEscape(port.evidenceBoundary))</td></tr>"
    }.joined(separator: "\n")
    let protocolDetails = document.protocolDetails.map { detail in
        "<tr><td>\(htmlEscape(detail.protocolKind.rawValue))</td><td>\(htmlEscape(detail.category))</td><td>\(htmlEscape(detail.label))</td><td class=\"mono\">\(htmlEscape(detail.value))</td><td>\(detail.occurrenceCount)</td><td class=\"mono\">\(htmlEscape(detail.field.rawValue))</td><td>\(htmlEscape(detail.evidenceBoundary))</td></tr>"
    }.joined(separator: "\n")
    let limitations = document.coverage.limitations.map { "<li>\(htmlEscape($0))</li>" }.joined(separator: "\n")
    return """
    <!doctype html>
    <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RVI-Sentinel report</title>
    <style>body{font:15px -apple-system,BlinkMacSystemFont,sans-serif;margin:2rem;color:#172033}h1,h2{color:#0b3d91}.card{padding:1rem;border:1px solid #ccd5e0;border-radius:12px;margin:1rem 0}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #d8dee8;padding:.55rem;text-align:left;vertical-align:top}th{background:#eef3f9}.mono{font-family:ui-monospace,SFMono-Regular,monospace;word-break:break-all}.notice{border-left:5px solid #cc8400;background:#fff7df;padding:1rem}</style></head>
    <body><h1>RVI-Sentinel analysis</h1>
    <div class="card"><strong>Source filename:</strong> \(htmlEscape(document.capture.sourceFilename))<br><strong>Capture SHA-256:</strong> <span class="mono">\(document.capture.sha256)</span><br><strong>Packets:</strong> \(document.capture.packetCount)<br><strong>Captured bytes:</strong> \(document.capture.byteCount)<br><strong>Generated:</strong> \(document.generatedAt.ISO8601Format())<br><strong>Active resolution:</strong> \(document.coverage.activeResolutionEnabled ? "Enabled" : "Disabled")</div>
    <p class="notice">\(htmlEscape(document.evidenceBoundary))</p>
    <h2>Endpoints</h2><table><thead><tr><th>Address</th><th>Scope</th><th>Source packets</th><th>Destination packets</th><th>Protocols</th><th>Process</th></tr></thead><tbody>\(endpoints)</tbody></table>
    <h2>Hostname evidence</h2><table><thead><tr><th>Hostname</th><th>Related IP</th><th>Provenance</th><th>Confidence</th></tr></thead><tbody>\(hostnames)</tbody></table>
    <h2>Protocols</h2><table><thead><tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Identification evidence</th></tr></thead><tbody>\(protocols)</tbody></table>
    <h2>Protocol details</h2><table><thead><tr><th>Protocol</th><th>Category</th><th>Field</th><th>Observed value</th><th>Count</th><th>Evidence source</th><th>Limit</th></tr></thead><tbody>\(protocolDetails)</tbody></table>
    <h2>Ports</h2><table><thead><tr><th>Transport</th><th>Port</th><th>Usual service</th><th>Usual purpose</th><th>Evidence limit</th></tr></thead><tbody>\(ports)</tbody></table>
    <h2>Coverage and limitations</h2><p>\(htmlEscape(document.coverage.tsharkVersion))</p><ul>\(limitations)</ul>
    </body></html>
    """
}

func htmlEscape(_ value: String) -> String {
    value
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#39;")
}
