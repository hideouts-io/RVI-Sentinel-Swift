import Foundation

actor TSharkAnalyzer {
    private let decoder: BoundedDecoder
    private var summaryAccumulator = AnalysisAccumulator()
    private var packetWriter: PacketDiskWriter?
    private var isAnalyzing = false
    private var cancellationRequested = false
    private var associationsTask: Task<Void, Error>?
    private var hashTask: Task<String, Error>?
    private var metadataTask: Task<UInt64?, Error>?
    private var containerFrameCount: UInt64?
    private var dnsLookupDatabase: PacketDatabase?
    private var hasDNS = false

    init(decoder: BoundedDecoder) {
        self.decoder = decoder
    }

    func cancel() async {
        cancellationRequested = true
        hashTask?.cancel()
        associationsTask?.cancel()
        metadataTask?.cancel()
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
        hasDNS = false
        defer {
            isAnalyzing = false
            packetWriter = nil
            hashTask = nil
            associationsTask = nil
            metadataTask = nil
            containerFrameCount = nil
            dnsLookupDatabase = nil
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
                "Apple legacy PCAPNG process options are read from the original container independently of TShark field population and compared with decoder facts when present.",
                "Imported capture origin is unknown unless the user declares RVI provenance; metadata alone does not establish device origin.",
                "Capture-reported interface labels and direction do not establish complete iOS interface coverage.",
                "Encrypted payloads and names remain unavailable unless separately and legitimately decrypted.",
                "Passive analysis performs no active hostname resolution. Current PTR lookup is a separate explicit action.",
                "Packet records, session membership and per-frame name associations are indexed in private temporary disk storage. No fixed total capture-size or packet-count ceiling is imposed; available disk space and processing resources still apply.",
                "Protocol detail values remain bounded per field, with omitted distinct values reported explicitly."
            ]
        )
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: 0, status: "Hashing the original capture."))
        let hashBefore = try await captureHash(captureURL)
        guard source != .liveDeviceRVI || expectedCaptureSHA256 == hashBefore else {
            throw NativeAnalysisError.invalidCapture("Live RVI provenance requires the completed capture's matching SHA-256. Reopen it as an import if its bytes changed.")
        }
        let files = try PacketStorageFiles()
        try createPacketStorage(files: files)
        progress(AnalysisProgress(decodedPackets: 0, status: "Streaming original PCAPNG metadata into the private packet index."))
        let originalMetadataTask = Task.detached(priority: .userInitiated) {
            try withPacketDatabase(files: files, access: .write) { database in
                try database.execute("BEGIN", values: [])
                let count = try streamApplePCAPNGMetadata(url: captureURL) { frame, processes in
                    try database.execute("INSERT INTO apple_processes(frame,primary_pid,primary_name,effective_pid,effective_name) VALUES(?,?,?,?,?)", values: [
                        .integer(try packetStorageInteger(frame)), processes.primary.map { .integer(Int64($0.pid)) } ?? .null,
                        processes.primary?.name.map(PacketSQLValue.text) ?? .null,
                        processes.effective.map { .integer(Int64($0.pid)) } ?? .null,
                        processes.effective?.name.map(PacketSQLValue.text) ?? .null
                    ])
                }
                try database.execute("COMMIT", values: [])
                return count
            }
        }
        metadataTask = originalMetadataTask
        containerFrameCount = try await withTaskCancellationHandler { try await originalMetadataTask.value } onCancel: { originalMetadataTask.cancel() }
        try checkCancellation()
        guard try await captureHash(captureURL) == hashBefore else {
            throw NativeAnalysisError.invalidCapture("The original capture changed during container metadata inspection. Reimport a stable saved file.")
        }
        let artifact = PacketCaptureArtifact(id: try PacketArtifactID(sha256: hashBefore, sourceURL: captureURL), source: source, integrity: .verified)
        packetWriter = try PacketDiskWriter(files: files, artifact: artifact)
        progress(AnalysisProgress(decodedPackets: 0, status: "Decoding packets into local disk storage."))
        _ = try await decoder.streamLines(
            executableURL: tshark, arguments: tsharkArguments(captureURL: captureURL, fields: supported),
            limits: BoundedDecoderLineLimits(process: BoundedDecoderLimits(maximumOutputBytes: Int.max, maximumErrorBytes: 1_048_576, timeout: try captureWorkloadTimeout(url: captureURL, minimum: .seconds(300))), maximumLineBytes: 131_072, maximumLines: Int.max),
            consume: { line in try await self.consumePacketLine(line, fields: supported, progress: progress) }
        )
        try checkCancellation()
        guard summaryAccumulator.packetCount > 0, let writer = packetWriter else {
            throw NativeAnalysisError.invalidCapture("TShark decoded zero packets. The file may be empty, truncated, or unsupported.")
        }
        if let containerFrameCount, containerFrameCount != UInt64(summaryAccumulator.packetCount) {
            throw NativeAnalysisError.invalidCapture("TShark packet count does not match the original PCAPNG container. Check the decoder version and reimport the complete capture.")
        }
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Indexing packet sessions and verifying the original capture."))
        let packets = try writer.finish()
        packetWriter = nil
        guard let storage = packets.diskStorage else { throw PacketStorageError.unavailable }
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Decoding captured DNS resource records."))
        if hasDNS {
            dnsLookupDatabase = try PacketDatabase(files: storage.files, access: .write)
            try dnsLookupDatabase?.execute("BEGIN", values: [])
            try await streamCapturedDNSRecords(artifactID: artifact.id, tsharkURL: tshark, decoder: decoder,
                timeout: try captureWorkloadTimeout(url: captureURL, minimum: .seconds(300)), consume: { messages in
                    try await self.consumeDNSMessages(messages, artifact: artifact.id)
                })
            try dnsLookupDatabase?.execute("COMMIT", values: [])
            try dnsLookupDatabase?.close()
            dnsLookupDatabase = nil
        }
        try checkCancellation()
        progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Indexing captured hostname evidence on disk."))
        let nameTask = Task.detached(priority: .userInitiated) {
            try finalizeStoredHostnameEvidence(storage: storage, artifact: artifact.id)
        }
        associationsTask = nameTask
        try await withTaskCancellationHandler { try await nameTask.value } onCancel: { nameTask.cancel() }
        var associations: [PacketRecordID: [CapturedHostnameAssociation]] = [:]
        if packets.recordCount <= 2_000 {
            try withPacketDatabase(files: storage.files, access: .read) { database in
                for packet in packets.records {
                    let evidence = try storedCapturedNames(database: database, id: packet.id)
                    if !evidence.isEmpty { associations[packet.id] = evidence }
                }
            }
        }
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
        let decoded = try decodePacketRow(row: line, fields: fields)
        guard let writer = packetWriter, let text = decoded.first(.frameNumber), let frame = UInt64(text), frame > 0,
              containerFrameCount.map({ frame <= $0 }) ?? true else { throw NativeAnalysisError.decodingFailed("The decoded frame does not identify an original capture packet.") }
        let packet = try applyingApplePCAPNGProcesses(packet: decoded, processes: storedAppleProcesses(database: writer.database, frame: frame))
        try writer.consume(packet: packet)
        if decoded.first(.frameProtocols)?.split(separator: ":").contains(where: { ["dns", "mdns", "llmnr"].contains($0) }) == true { hasDNS = true }
        try summaryAccumulator.consume(packet: packet)
        if summaryAccumulator.packetCount.isMultiple(of: 5_000) {
            progress(AnalysisProgress(decodedPackets: summaryAccumulator.packetCount, status: "Decoded \(summaryAccumulator.packetCount.formatted()) packets locally."))
        }
    }

    private func consumeDNSMessages(_ messages: [CapturedDNSMessage], artifact: PacketArtifactID) throws {
        try checkCancellation()
        guard let database = dnsLookupDatabase else { throw PacketStorageError.unavailable }
        for message in messages {
            guard let packet = try storedPacket(database: database, artifact: artifact, id: message.packetID) else {
                throw CapturedDNSError.malformed(frame: message.packetID.frameNumber, reason: "DNS frame has no matching indexed packet")
            }
            summaryAccumulator.consumeCapturedDNS(message: message, packet: packet)
        }
        try storeDNSMessages(messages: messages, artifact: artifact, database: database)
    }

    private func checkCancellation() throws {
        try Task.checkCancellation()
        if cancellationRequested { throw CancellationError() }
    }

    private func captureHash(_ url: URL) async throws -> String {
        let timeout = try captureWorkloadTimeout(url: url, minimum: .seconds(60))
        let task = Task.detached(priority: .userInitiated) { try hashCaptureBytes(url: url, maximumBytes: Int64.max, deadline: ContinuousClock().now + timeout) }
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
