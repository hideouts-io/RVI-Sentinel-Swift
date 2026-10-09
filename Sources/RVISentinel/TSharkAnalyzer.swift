import Foundation

actor TSharkAnalyzer {
    private let decoder: BoundedDecoder
    private var summaryAccumulator = AnalysisAccumulator()
    private var packetAccumulator: PacketIndexAccumulator?
    private var isAnalyzing = false
    private var cancellationRequested = false
    private var indexingTask: Task<PacketAnalysisResult, Error>?
    private var associationsTask: Task<[PacketRecordID: [CapturedHostnameAssociation]], Error>?
    private var hashTask: Task<String, Error>?

    init(decoder: BoundedDecoder) {
        self.decoder = decoder
    }

    func cancel() async {
        cancellationRequested = true
        indexingTask?.cancel()
        hashTask?.cancel()
        associationsTask?.cancel()
        await decoder.cancel()
    }

    func analyze(captureURL: URL, progress: @escaping @Sendable (AnalysisProgress) -> Void) async throws -> NativeAnalysisResult {
        try await analyze(captureURL: captureURL, source: .unknown, expectedCaptureSHA256: nil, progress: progress)
    }

    /// Reads a stable original in place. Source provenance is supplied by the workflow,
    /// never inferred from process labels, interface names, or the selected extension.
    func analyze(captureURL: URL, source: PacketSourceProvenance, expectedCaptureSHA256: String?, progress: @escaping @Sendable (AnalysisProgress) -> Void) async throws -> NativeAnalysisResult {
        guard !isAnalyzing else { throw NativeAnalysisError.decodingFailed("An analysis is already running. Cancel it or wait for completion.") }
        isAnalyzing = true
        cancellationRequested = false
        summaryAccumulator = AnalysisAccumulator()
        defer {
            isAnalyzing = false
            packetAccumulator = nil
            indexingTask = nil
            hashTask = nil
            associationsTask = nil
        }
        guard captureURL.isFileURL, FileManager.default.fileExists(atPath: captureURL.path),
              ["pcap", "pcapng", "cap"].contains(captureURL.pathExtension.lowercased()) else {
            throw NativeAnalysisError.invalidCapture("Choose an existing local .pcap, .pcapng, or .cap file.")
        }
        guard let tshark = resolveTShark() else { throw NativeAnalysisError.tsharkUnavailable }
        let toolLimits = BoundedDecoderLimits(maximumOutputBytes: 33_554_432, maximumErrorBytes: 16_384, timeout: .seconds(30))
        let versionData = try await decoder.captureData(executableURL: tshark, arguments: ["--version"], limits: toolLimits)
        guard let versionText = String(data: versionData.standardOutput, encoding: .utf8),
              let version = versionText.split(whereSeparator: \.isNewline).first.map(String.init) else {
            throw NativeAnalysisError.fieldCatalogFailed("TShark returned no UTF-8 version identifier.")
        }
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: 0, status: "Reading the installed TShark field catalog."))
        let catalogData = try await decoder.captureData(executableURL: tshark, arguments: ["-G", "fields"], limits: toolLimits)
        guard let catalogText = String(data: catalogData.standardOutput, encoding: .utf8) else {
            throw NativeAnalysisError.fieldCatalogFailed("TShark returned a non-UTF-8 field catalog.")
        }
        let catalog = parseTSharkFieldCatalog(catalogText)
        let supported = TSharkField.allCases.filter { catalog.contains($0.rawValue) }
        let missingRequired = TSharkField.required.subtracting(supported).map(\.rawValue).sorted()
        guard missingRequired.isEmpty else { throw NativeAnalysisError.requiredFieldsMissing(missingRequired) }
        let coverage = AnalysisCoverage(
            tsharkVersion: version, supportedFields: supported,
            unsupportedFields: TSharkField.allCases.filter { !catalog.contains($0.rawValue) },
            activeResolutionEnabled: false,
            limitations: [
                "Unsupported decoder fields are distinct from fields not present in the capture.",
                "Process and effective-process labels are source capture metadata, not independently verified device process identity.",
                "Imported capture origin is unknown unless the user declares RVI provenance; metadata alone does not establish device origin.",
                "Capture-reported interface labels and direction do not establish complete iOS interface coverage.",
                "Encrypted payloads and names remain unavailable unless separately and legitimately decrypted.",
                "Passive analysis performs no active hostname resolution. Current PTR lookup is a separate explicit action.",
                "Packet indexing is limited to 200,000 records and 256 MiB of estimated record storage; exceeding either limit fails explicitly.",
                "Protocol detail values remain bounded per field, with omitted distinct values reported explicitly."
            ]
        )
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: 0, status: "Hashing the original capture."))
        let hashBefore = try await captureHash(captureURL)
        guard source != .liveDeviceRVI || expectedCaptureSHA256 == hashBefore else {
            throw NativeAnalysisError.invalidCapture("Live RVI provenance requires the completed capture's matching SHA-256. Reopen it as an import if its bytes changed.")
        }
        let artifact = PacketCaptureArtifact(id: try PacketArtifactID(sha256: hashBefore, sourceURL: captureURL), source: source, integrity: .verified)
        packetAccumulator = try PacketIndexAccumulator(artifact: artifact, limits: PacketIndexLimits(maximumRecords: 200_000, maximumEstimatedBytes: 268_435_456))
        progress(AnalysisProgress(decodedPackets: 0, status: "Decoding packets and recorded metadata locally."))
        _ = try await decoder.streamLines(
            executableURL: tshark, arguments: tsharkArguments(captureURL: captureURL, fields: supported),
            limits: BoundedDecoderLineLimits(process: BoundedDecoderLimits(maximumOutputBytes: 536_870_912, maximumErrorBytes: 1_048_576, timeout: .seconds(300)), maximumLineBytes: 131_072, maximumLines: 200_000),
            consume: { line in try await self.consumePacketLine(line, fields: supported, progress: progress) }
        )
        try checkCancellation()
        guard summaryAccumulator.packetCount > 0, let accumulator = packetAccumulator else {
            throw NativeAnalysisError.invalidCapture("TShark decoded zero packets. The file may be empty, truncated, or unsupported.")
        }
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Indexing packet sessions and verifying the original capture."))
        let task = Task.detached(priority: .userInitiated) { try accumulator.result() }
        indexingTask = task
        let packets = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Decoding captured DNS resource records."))
        let hasDNS = packets.records.contains { !$0.protocols.filter { [.dns, .mdns, .dnsSD, .llmnr].contains($0) }.isEmpty }
        let dnsMessages = hasDNS ? try await readCapturedDNSRecords(artifactID: artifact.id, tsharkURL: tshark, decoder: decoder, limits: .standard, timeout: .seconds(60)) : []
        try checkCancellation()
        summaryAccumulator.consumeCapturedDNS(messages: dnsMessages, records: packets.records)
        let nameTask = Task.detached(priority: .userInitiated) {
            try resolveCapturedHostnames(messages: dnsMessages, packets: packets.records, maximumAssociations: 400_000)
        }
        associationsTask = nameTask
        let associations = try await withTaskCancellationHandler { try await nameTask.value } onCancel: { nameTask.cancel() }
        try checkCancellation()
        let hashAfter = try await captureHash(captureURL)
        guard hashBefore == hashAfter else {
            throw NativeAnalysisError.invalidCapture("The original capture changed during analysis. Reopen a stable saved file before inspecting its packets.")
        }
        let result = summaryAccumulator.result(captureURL: captureURL, hash: hashAfter, coverage: coverage)
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Analysis complete. Original capture verified; no active DNS lookup performed."))
        return NativeAnalysisResult(summary: result.summary, endpoints: result.endpoints, hostnames: result.hostnames, protocols: result.protocols, protocolDetails: result.protocolDetails, ports: result.ports, coverage: result.coverage, packetAnalysis: packets, capturedHostnameAssociations: associations)
    }

    private func consumePacketLine(_ line: String, fields: [TSharkField], progress: @escaping @Sendable (AnalysisProgress) -> Void) throws {
        try checkCancellation()
        guard !line.isEmpty else { throw NativeAnalysisError.malformedRow("TShark returned an empty packet row") }
        let packet = try decodePacketRow(row: line, fields: fields)
        guard packetAccumulator != nil else { throw NativeAnalysisError.decodingFailed("Packet index was not initialized.") }
        try packetAccumulator?.consume(packet: packet)
        try summaryAccumulator.consume(packet: packet)
        if summaryAccumulator.packetCount.isMultiple(of: 5_000) {
            progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Decoded \(summaryAccumulator.packetCount.formatted()) packets locally."))
        }
    }

    private func checkCancellation() throws {
        try Task.checkCancellation()
        if cancellationRequested { throw CancellationError() }
    }

    private func captureHash(_ url: URL) async throws -> String {
        let task = Task.detached(priority: .userInitiated) { try hashCaptureBytes(url: url, maximumBytes: 4_294_967_296, deadline: ContinuousClock().now + .seconds(60)) }
        hashTask = task
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
}

func resolveTShark() -> URL? {
    let candidates = ["/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark"]
    return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }).map(URL.init(fileURLWithPath:))
}

func parseTSharkFieldCatalog(_ output: String) -> Set<String> {
    Set(output.split(whereSeparator: \.isNewline).compactMap { line in
        let columns = line.split(separator: "\t", omittingEmptySubsequences: false)
        guard columns.count > 2, columns[0] == "F" else { return nil }
        let abbreviation = String(columns[2])
        return abbreviation.isEmpty ? nil : abbreviation
    })
}

func tsharkArguments(captureURL: URL, fields: [TSharkField]) -> [String] {
    var arguments = ["-n", "-r", captureURL.path, "-T", "fields", "-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=\u{1e}"]
    for field in fields { arguments.append(contentsOf: ["-e", field.rawValue]) }
    return arguments
}
