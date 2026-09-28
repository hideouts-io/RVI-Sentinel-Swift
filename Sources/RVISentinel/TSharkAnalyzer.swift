import Foundation

actor TSharkAnalyzer {
    private let processRunner: ProcessRunner
    private var activeProcess: Process?

    init(processRunner: ProcessRunner) {
        self.processRunner = processRunner
    }

    func cancel() {
        activeProcess?.interrupt()
    }

    func analyze(
        captureURL: URL,
        progress: @escaping @Sendable (AnalysisProgress) -> Void
    ) async throws -> NativeAnalysisResult {
        guard FileManager.default.fileExists(atPath: captureURL.path) else {
            throw NativeAnalysisError.invalidCapture("File does not exist: \(captureURL.path)")
        }
        guard ["pcap", "pcapng", "cap"].contains(captureURL.pathExtension.lowercased()) else {
            throw NativeAnalysisError.invalidCapture("Choose a .pcap, .pcapng, or .cap file.")
        }
        guard let tshark = resolveTShark() else {
            throw NativeAnalysisError.tsharkUnavailable
        }
        let versionResult = try await processRunner.run(executableURL: tshark, arguments: ["--version"])
        guard versionResult.exitCode == 0 else {
            throw NativeAnalysisError.fieldCatalogFailed(versionResult.standardError)
        }
        let version = versionResult.standardOutput.split(whereSeparator: \.isNewline).first.map(String.init) ?? "TShark version unavailable"
        progress(AnalysisProgress(decodedPackets: 0, status: "Reading the installed TShark field catalog."))
        let catalogResult = try await processRunner.run(executableURL: tshark, arguments: ["-G", "fields"])
        guard catalogResult.exitCode == 0 else {
            throw NativeAnalysisError.fieldCatalogFailed(catalogResult.standardError)
        }
        let catalog = parseTSharkFieldCatalog(catalogResult.standardOutput)
        let supported = TSharkField.allCases.filter { catalog.contains($0.rawValue) }
        let missingRequired = TSharkField.required.subtracting(supported).map(\.rawValue).sorted()
        guard missingRequired.isEmpty else {
            throw NativeAnalysisError.requiredFieldsMissing(missingRequired)
        }
        let unsupported = TSharkField.allCases.filter { !catalog.contains($0.rawValue) }
        let coverage = AnalysisCoverage(
            tsharkVersion: version,
            supportedFields: supported,
            unsupportedFields: unsupported,
            activeResolutionEnabled: false,
            limitations: [
                "TShark fields absent from the installed version are marked unsupported, not absent from the capture.",
                "Encrypted TLS, QUIC, VPN, SSH, and IPsec payloads remain unavailable unless separately and legitimately decrypted.",
                "Ordinary PCAP/RVI traffic does not prove an iOS process owner or internal iOS interface.",
                "Source and destination counts are packet directions, not automatically inbound or outbound relative to the phone.",
                "Active hostname and reverse-DNS lookup is disabled; no investigated address is sent to a resolver."
            ]
        )
        progress(AnalysisProgress(decodedPackets: 0, status: "Decoding packets locally with name resolution disabled."))
        let hash = try sha256(url: captureURL)
        let errorURL = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-sentinel-tshark-\(UUID().uuidString).stderr")
        FileManager.default.createFile(atPath: errorURL.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: errorURL) }
        let errorHandle = try FileHandle(forWritingTo: errorURL)
        let outputPipe = Pipe()
        let process = Process()
        process.executableURL = tshark
        process.arguments = tsharkArguments(captureURL: captureURL, fields: supported)
        process.standardOutput = outputPipe
        process.standardError = errorHandle
        activeProcess = process
        do {
            try process.run()
        } catch {
            activeProcess = nil
            try? errorHandle.close()
            throw NativeAnalysisError.decodingFailed(error.localizedDescription)
        }
        do {
            try outputPipe.fileHandleForWriting.close()
        } catch {
            process.terminate()
            activeProcess = nil
            try? errorHandle.close()
            throw NativeAnalysisError.decodingFailed("Could not close the parent-side TShark output pipe: \(error.localizedDescription)")
        }

        var accumulator = AnalysisAccumulator()
        do {
            for try await line in outputPipe.fileHandleForReading.bytes.lines {
                try Task.checkCancellation()
                if line.isEmpty { continue }
                let packet = try decodePacketRow(row: line, fields: supported)
                try accumulator.consume(packet: packet)
                if accumulator.packetCount.isMultiple(of: 5_000) {
                    progress(AnalysisProgress(decodedPackets: accumulator.packetCount, status: "Decoded \(accumulator.packetCount.formatted()) packets locally."))
                }
            }
        } catch {
            process.interrupt()
            process.waitUntilExit()
            activeProcess = nil
            try? errorHandle.close()
            throw error
        }
        process.waitUntilExit()
        activeProcess = nil
        try errorHandle.close()
        let errorText = try String(contentsOf: errorURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0 else {
            if process.terminationReason == .uncaughtSignal {
                throw CancellationError()
            }
            throw NativeAnalysisError.decodingFailed("tshark exit \(process.terminationStatus): \(errorText)")
        }
        guard accumulator.packetCount > 0 else {
            throw NativeAnalysisError.invalidCapture("TShark decoded zero packets. The file may be empty, truncated, or unsupported.")
        }
        progress(AnalysisProgress(decodedPackets: accumulator.packetCount, status: "Analysis complete. No active lookups were performed."))
        return accumulator.result(captureURL: captureURL, hash: hash, coverage: coverage)
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
    var arguments = [
        "-n",
        "-r", captureURL.path,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=/t",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=\u{1e}"
    ]
    for field in fields {
        arguments.append(contentsOf: ["-e", field.rawValue])
    }
    return arguments
}
