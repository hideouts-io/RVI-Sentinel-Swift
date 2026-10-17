import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

enum AnalysisQueueStatus: String, Sendable {
    case queued = "Queued"
    case analyzing = "Analyzing"
    case completed = "Completed"
    case failed = "Failed"
    case cancelled = "Cancelled"
}

struct AnalysisQueueItem: Identifiable, Sendable {
    let id: UUID
    let captureURL: URL
    var source: PacketSourceProvenance
    let expectedSHA256: String?
    var status: AnalysisQueueStatus
    var progress: AnalysisProgress
    var result: NativeAnalysisResult?
    var error: String?

    init(captureURL: URL, source: PacketSourceProvenance, expectedSHA256: String?) {
        self.id = UUID()
        self.captureURL = captureURL
        self.source = source
        self.expectedSHA256 = expectedSHA256
        self.status = .queued
        self.progress = AnalysisProgress(decodedPackets: 0, status: "Queued. Choose Analyze to start local decoding.")
        self.result = nil
        self.error = nil
    }
}

@MainActor
final class AppState: ObservableObject {
    @Published private(set) var setupChecks: [SetupCheck] = []
    @Published private(set) var devices: [DeviceInfo] = []
    @Published private(set) var interfaces: [NetworkInterfaceInfo] = []
    @Published private(set) var isCheckingSetup = false
    @Published private(set) var isRefreshingDevices = false
    @Published private(set) var isCapturing = false
    @Published private(set) var captureProgress = CaptureProgress(phase: .idle, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Ready to configure a capture.")
    @Published private(set) var captureCompletion: CaptureCompletion?
    @Published private(set) var captureRecovery: CaptureRecovery?
    @Published var analysisCaptureURL: URL?
    @Published var importedCaptureSource = PacketSourceProvenance.unknown
    @Published private(set) var analysisQueue: [AnalysisQueueItem] = []
    @Published private(set) var selectedAnalysisID: UUID?
    private var analysisOperationID: UUID?
    private var activeAnalysisTask: Task<NativeAnalysisResult, Error>?
    private var analysisCancellationTask: Task<Void, Never>?
    private var analysisCancellationRequested = false
    @Published private(set) var isAnalyzing = false
    @Published private(set) var analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Choose an authorized capture to begin.")
    @Published var baselineURL: URL?
    @Published private(set) var baselineDocument: BaselineDocument?
    @Published private(set) var baselineComparison: BaselineComparison?
    @Published private(set) var lastBaselineBackupURL: URL?
    @Published var exportDirectory: URL
    @Published private(set) var exportReceipts: [ExportReceipt] = []
    @Published private(set) var isExporting = false
    @Published private(set) var diagnosticsPreview = ""
    @Published private(set) var diagnosticsCopiedAt: Date?
    @Published var lastError: String?
    @Published var selectedDeviceIdentifier: String?
    @Published var outputDirectory: URL
    @Published var showAdvancedDetails = false

    private let discoveryService: DeviceDiscoveryService
    private let setupChecker: SetupChecker
    private let captureCoordinator: CaptureCoordinator
    private let analyzer: TSharkAnalyzer
    private let baselineStore: BaselineStore
    private let reportExporter: ReportExporter

    init(
        discoveryService: DeviceDiscoveryService,
        setupChecker: SetupChecker,
        captureCoordinator: CaptureCoordinator,
        analyzer: TSharkAnalyzer,
        baselineStore: BaselineStore,
        reportExporter: ReportExporter,
        outputDirectory: URL
    ) {
        self.discoveryService = discoveryService
        self.setupChecker = setupChecker
        self.captureCoordinator = captureCoordinator
        self.analyzer = analyzer
        self.baselineStore = baselineStore
        self.reportExporter = reportExporter
        self.outputDirectory = outputDirectory
        self.exportDirectory = outputDirectory
    }

    static func live() -> AppState {
        let runner = ProcessRunner()
        let discovery = DeviceDiscoveryService(processRunner: runner)
        let interfaceService = InterfaceInventoryService()
        let checker = SetupChecker(
            processRunner: runner,
            discoveryService: discovery,
            interfaceService: interfaceService
        )
        let captureCoordinator = CaptureCoordinator(
            processRunner: runner,
            discoveryService: discovery,
            interfaceService: interfaceService
        )
        let analyzer = TSharkAnalyzer(decoder: BoundedDecoder())
        let output = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        return AppState(
            discoveryService: discovery,
            setupChecker: checker,
            captureCoordinator: captureCoordinator,
            analyzer: analyzer,
            baselineStore: BaselineStore(),
            reportExporter: ReportExporter(),
            outputDirectory: output
        )
    }

    var selectedDevice: DeviceInfo? {
        devices.first { $0.identifier == selectedDeviceIdentifier }
    }

    // Queue entries own results; selecting a capture shares its disk-backed result.
    var analysisResult: NativeAnalysisResult? {
        analysisQueue.first { $0.id == selectedAnalysisID }?.result
    }

    var analysisIntegrity: PacketIntegrityState? {
        guard let item = analysisQueue.first(where: { $0.id == selectedAnalysisID }) else { return nil }
        switch item.status {
        case .queued: return nil
        case .analyzing: return .pending
        case .completed: return item.result?.packetAnalysis?.artifact.integrity
        case .failed: return .failed(detail: item.error ?? item.progress.status)
        case .cancelled: return .failed(detail: item.progress.status)
        }
    }

    func runSetupChecks() async {
        isCheckingSetup = true
        lastError = nil
        setupChecks = await setupChecker.run(outputDirectory: outputDirectory)
        isCheckingSetup = false
    }

    func refreshDevices() async {
        isRefreshingDevices = true
        lastError = nil
        do {
            applyDiscoveredDevices(try await discoveryService.discover())
        } catch {
            devices = []
            lastError = error.localizedDescription
        }
        isRefreshingDevices = false
    }

    func loadDevicesIfNeeded() async {
        guard devices.isEmpty else { return }
        do {
            applyDiscoveredDevices(try await discoveryService.discover())
            lastError = nil
        } catch {
            devices = []
            lastError = error.localizedDescription
        }
    }

    private func applyDiscoveredDevices(_ discoveredDevices: [DeviceInfo]) {
        devices = discoveredDevices
        if selectedDevice == nil {
            selectedDeviceIdentifier = discoveredDevices.first(where: { $0.readiness == .ready })?.identifier
        }
    }

    func chooseOutputDirectory() {
        let panel = NSOpenPanel()
        panel.title = "Choose Capture Output Folder"
        panel.prompt = "Choose"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = outputDirectory
        if panel.runModal() == .OK, let selectedURL = panel.url {
            outputDirectory = selectedURL
        }
    }

    func startCapture(durationSeconds: Int, format: CaptureFormat) async {
        guard let device = selectedDevice else {
            lastError = "Select a capture-ready iPhone or iPad first."
            return
        }
        let outputURL = suggestedCaptureURL(
            directory: outputDirectory,
            deviceName: device.name,
            format: format,
            date: Date()
        )
        let configuration = CaptureConfiguration(
            device: device,
            durationSeconds: durationSeconds,
            format: format,
            outputURL: outputURL
        )
        isCapturing = true
        captureCompletion = nil
        captureRecovery = nil
        lastError = nil
        do {
            let completion = try await captureCoordinator.capture(configuration: configuration) { [weak self] update in
                Task { @MainActor in self?.captureProgress = update }
            }
            captureCompletion = completion
        } catch {
            let failurePhase = captureFailurePhase(error: error)
            captureProgress = CaptureProgress(
                phase: failurePhase,
                elapsedSeconds: captureProgress.elapsedSeconds,
                packetCount: captureProgress.packetCount,
                bytesWritten: captureProgress.bytesWritten,
                status: error.localizedDescription
            )
            captureRecovery = captureRecoveryGuidance(error: error)
            lastError = error.localizedDescription
        }
        isCapturing = false
    }

    func cancelCapture() async {
        do {
            try await captureCoordinator.cancel()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func clearCaptureCompletion() {
        captureCompletion = nil
        captureRecovery = nil
        captureProgress = CaptureProgress(phase: .idle, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Ready to configure another capture.")
    }

    func revealCapture() {
        guard let captureCompletion else { return }
        NSWorkspace.shared.activateFileViewerSelecting([captureCompletion.savedURL])
    }

    func prepareCompletedCaptureForAnalysis() {
        guard !isAnalyzing else { lastError = "Wait for the running analysis or cancel it before selecting another capture."; return }
        guard let captureCompletion else { return }
        let item = AnalysisQueueItem(captureURL: captureCompletion.savedURL, source: .liveDeviceRVI, expectedSHA256: captureCompletion.sha256)
        analysisQueue = [item]
        selectedAnalysisID = item.id
        analysisCaptureURL = item.captureURL
        importedCaptureSource = .liveDeviceRVI
        interfaces = []
        baselineComparison = nil
        lastError = nil
        analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Ready to analyze the completed RVI capture passively.")
    }

    func chooseAnalysisCapture() {
        guard !isAnalyzing else { lastError = "Wait for the running analysis or cancel it before selecting another capture."; return }
        let panel = NSOpenPanel()
        panel.title = "Choose Authorized Packet Captures"
        panel.prompt = "Choose"
        panel.allowsMultipleSelection = true
        let contentTypes = packetCaptureContentTypes()
        guard contentTypes.count == supportedPacketCaptureExtensions.count else {
            lastError = "macOS could not register the supported .pcap, .pcapng, and .cap file types."
            return
        }
        panel.allowedContentTypes = contentTypes
        // macOS 27 recalculates file/directory eligibility when content types change.
        // Apply the explicit file-only policy after setting the supported types.
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        if panel.runModal() == .OK {
            prepareAnalysisQueue(captureURLs: panel.urls)
        }
    }

    /// Replaces the queue only on an explicit selection; decoding starts separately.
    func prepareAnalysisQueue(captureURLs: [URL]) {
        guard !isAnalyzing else { lastError = "Wait for the running analysis or cancel it before selecting another capture."; return }
        guard !captureURLs.isEmpty, captureURLs.allSatisfy({ $0.isFileURL && supportedPacketCaptureExtensions.contains($0.pathExtension.lowercased()) }) else {
            lastError = "Choose local .pcap, .pcapng, or .cap files."
            return
        }
        analysisQueue = captureURLs.map { AnalysisQueueItem(captureURL: $0, source: .unknown, expectedSHA256: nil) }
        selectedAnalysisID = analysisQueue.first?.id
        analysisCaptureURL = analysisQueue.first?.captureURL
        importedCaptureSource = .unknown
        interfaces = []
        baselineComparison = nil
        lastError = nil
        analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Ready to analyze \(captureURLs.count.formatted()) capture(s) locally without active DNS lookups.")
    }

    func selectAnalysisResult(id: UUID) {
        guard let item = analysisQueue.first(where: { $0.id == id }), let result = item.result else {
            lastError = "Select a completed capture to view its analysis."
            return
        }
        selectedAnalysisID = item.id
        analysisCaptureURL = item.captureURL
        importedCaptureSource = item.source
        interfaces = captureReportedIOSInterfaces(names: result.summary.interfaces)
        if !isAnalyzing { analysisProgress = item.progress }
        refreshBaselineComparison()
    }

    func startAnalysis() async {
        guard !isAnalyzing else { lastError = "An analysis is already running. Wait for completion or cancel it."; return }
        guard let analysisCaptureURL else {
            lastError = "Choose an authorized capture first."
            return
        }
        if analysisQueue.isEmpty || !analysisQueue.contains(where: { $0.id == selectedAnalysisID && $0.captureURL == analysisCaptureURL }) {
            let source = importedCaptureSource
            prepareAnalysisQueue(captureURLs: [analysisCaptureURL])
            guard analysisQueue.count == 1, analysisQueue[0].captureURL == analysisCaptureURL else { return }
            importedCaptureSource = source
        }
        if analysisQueue.contains(where: { $0.status == .queued }) {
            for index in analysisQueue.indices where analysisQueue[index].status == .queued && analysisQueue[index].source != .liveDeviceRVI {
                analysisQueue[index].source = importedCaptureSource
            }
        } else {
            let incomplete = analysisQueue.indices.filter { analysisQueue[$0].status == .failed || analysisQueue[$0].status == .cancelled }
            let retry = incomplete.isEmpty ? analysisQueue.indices.filter { analysisQueue[$0].id == selectedAnalysisID } : incomplete
            let originCanBeEdited = analysisResult == nil
            for index in retry {
                if originCanBeEdited && analysisQueue[index].source != .liveDeviceRVI {
                    analysisQueue[index].source = importedCaptureSource
                }
                analysisQueue[index].status = .queued
                analysisQueue[index].result = nil
                analysisQueue[index].error = nil
                analysisQueue[index].progress = AnalysisProgress(decodedPackets: 0, status: "Queued for an explicitly requested analysis.")
            }
        }
        let operationID = UUID()
        analysisOperationID = operationID
        isAnalyzing = true
        analysisCancellationRequested = false
        if analysisResult == nil {
            interfaces = []
            baselineComparison = nil
        }
        lastError = nil
        for index in analysisQueue.indices {
            guard !analysisCancellationRequested && !Task.isCancelled else {
                cancelPendingAnalyses()
                break
            }
            guard analysisQueue[index].status == .queued else { continue }
            let item = analysisQueue[index]
            analysisQueue[index].status = .analyzing
            analysisQueue[index].progress = AnalysisProgress(decodedPackets: 0, status: "Starting local analysis.")
            analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Analyzing \(item.captureURL.lastPathComponent).")
            let analyzer = analyzer
            let task = Task { [weak self] in
                try await analyzer.analyze(captureURL: item.captureURL, source: item.source, expectedCaptureSHA256: item.expectedSHA256) { [weak self] update in
                    Task { @MainActor in
                        guard let self, self.analysisOperationID == operationID, !self.analysisCancellationRequested,
                              self.analysisQueue[index].id == item.id, self.analysisQueue[index].status == .analyzing else { return }
                        self.analysisQueue[index].progress = update
                        self.analysisProgress = AnalysisProgress(decodedPackets: update.decodedPackets, status: "\(item.captureURL.lastPathComponent): \(update.status)")
                    }
                }
            }
            activeAnalysisTask = task
            do {
                let result = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
                guard !analysisCancellationRequested && !Task.isCancelled else { throw CancellationError() }
                analysisQueue[index].result = result
                analysisQueue[index].status = .completed
                analysisQueue[index].progress = AnalysisProgress(decodedPackets: result.summary.packetCount, status: "Analysis complete. Original capture verified; no active DNS lookup performed.")
                if analysisResult == nil || selectedAnalysisID == item.id {
                    selectAnalysisResult(id: item.id)
                }
            } catch is CancellationError {
                analysisQueue[index].status = .cancelled
                analysisQueue[index].progress = AnalysisProgress(decodedPackets: analysisQueue[index].progress.decodedPackets, status: "Analysis cancelled. The original capture was not changed.")
                analysisCancellationRequested = true
                cancelPendingAnalyses()
            } catch {
                // Decoder failures stay attached to their capture, including cleanup failures on cancellation.
                analysisQueue[index].status = .failed
                analysisQueue[index].error = error.localizedDescription
                analysisQueue[index].progress = AnalysisProgress(decodedPackets: analysisQueue[index].progress.decodedPackets, status: error.localizedDescription)
                if analysisQueue.count == 1 { lastError = error.localizedDescription }
            }
            activeAnalysisTask = nil
        }
        if let analysisCancellationTask { await analysisCancellationTask.value }
        if analysisQueue.count == 1, let item = analysisQueue.first {
            analysisProgress = item.progress
        } else {
            let completed = analysisQueue.filter { $0.status == .completed }.count
            let failed = analysisQueue.filter { $0.status == .failed }.count
            let cancelled = analysisQueue.filter { $0.status == .cancelled }.count
            analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Queue finished: \(completed.formatted()) completed, \(failed.formatted()) failed, \(cancelled.formatted()) cancelled.")
        }
        analysisOperationID = nil
        analysisCancellationTask = nil
        analysisCancellationRequested = false
        isAnalyzing = false
    }

    func cancelAnalysis() async {
        guard isAnalyzing, !analysisCancellationRequested else { return }
        analysisCancellationRequested = true
        cancelPendingAnalyses()
        activeAnalysisTask?.cancel()
        analysisProgress = AnalysisProgress(decodedPackets: analysisProgress.decodedPackets, status: "Cancelling the active capture and pending queue.")
        let analyzer = analyzer
        let task = Task { await analyzer.cancel() }
        analysisCancellationTask = task
        await task.value
    }

    private func cancelPendingAnalyses() {
        for index in analysisQueue.indices where analysisQueue[index].status == .queued {
            analysisQueue[index].status = .cancelled
            analysisQueue[index].progress = AnalysisProgress(decodedPackets: 0, status: "Cancelled before analysis started. The original capture was not changed.")
        }
    }

    func chooseBaseline() {
        let panel = NSOpenPanel()
        panel.title = "Choose an RVI-Sentinel Baseline"
        panel.prompt = "Choose"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        loadBaseline(url: url)
    }

    func createBaseline(scopeName: String) {
        let panel = NSSavePanel()
        panel.title = "Create a Separate Baseline"
        panel.prompt = "Create"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "\(sanitizedFilename(scopeName))-baseline.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let document = try baselineStore.create(url: url, scopeName: scopeName, createdAt: Date())
            baselineURL = url
            baselineDocument = document
            lastBaselineBackupURL = nil
            refreshBaselineComparison()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func addFindingsToBaseline() {
        guard let baselineURL, let analysisResult else {
            lastError = "Select a baseline and complete an analysis before adding findings."
            return
        }
        do {
            let update = try baselineStore.update(url: baselineURL, result: analysisResult, reviewedAt: Date())
            baselineDocument = update.document
            lastBaselineBackupURL = update.backupURL
            refreshBaselineComparison()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func resetBaseline() {
        guard let baselineURL else {
            lastError = "Select a baseline before resetting it."
            return
        }
        do {
            let reset = try baselineStore.reset(url: baselineURL, resetAt: Date())
            baselineDocument = reset.document
            lastBaselineBackupURL = reset.backupURL
            refreshBaselineComparison()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func exportBaselineCopy() {
        guard let baselineDocument else {
            lastError = "Select a baseline before exporting a copy."
            return
        }
        let panel = NSSavePanel()
        panel.title = "Export Baseline Copy"
        panel.prompt = "Export"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "\(sanitizedFilename(baselineDocument.scopeName))-baseline-copy.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try baselineStore.exportCopy(document: baselineDocument, destinationURL: url)
        } catch {
            lastError = error.localizedDescription
        }
    }

    func chooseExportDirectory() {
        let panel = NSOpenPanel()
        panel.title = "Choose Local Export Folder"
        panel.prompt = "Choose"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = exportDirectory
        if panel.runModal() == .OK, let url = panel.url {
            exportDirectory = url
        }
    }

    func exportAnalysis(format: ReportExportFormat) async {
        guard let analysisResult else {
            lastError = "Complete an analysis before exporting a report."
            return
        }
        isExporting = true
        lastError = nil
        let exporter = reportExporter
        let directory = exportDirectory
        do {
            let receipt = try await Task.detached(priority: .userInitiated) {
                try exporter.export(result: analysisResult, format: format, directory: directory, generatedAt: Date())
            }.value
            exportReceipts.insert(receipt, at: 0)
        } catch {
            lastError = error.localizedDescription
        }
        isExporting = false
    }

    func revealExport(_ receipt: ExportReceipt) {
        if receipt.outputURL.hasDirectoryPath {
            NSWorkspace.shared.open(receipt.outputURL)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([receipt.outputURL])
        }
    }

    func refreshDiagnostics() {
        do {
            diagnosticsPreview = try diagnosticsText(generatedAt: Date())
        } catch {
            diagnosticsPreview = ""
            lastError = error.localizedDescription
        }
    }

    func copyDiagnostics() {
        do {
            let value = try diagnosticsText(generatedAt: Date())
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            guard pasteboard.setString(value, forType: .string) else {
                throw DiagnosticsError.clipboardWriteFailed
            }
            diagnosticsPreview = value
            diagnosticsCopiedAt = Date()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func saveDiagnostics() {
        let panel = NSSavePanel()
        panel.title = "Save Redacted Diagnostics"
        panel.prompt = "Save"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "rvi-sentinel-diagnostics.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let value = try diagnosticsText(generatedAt: Date())
            do {
                try Data(value.utf8).write(to: url, options: .atomic)
            } catch {
                throw DiagnosticsError.exportFailed(path: url.path, reason: error.localizedDescription)
            }
            diagnosticsPreview = value
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func loadBaseline(url: URL) {
        do {
            let document = try baselineStore.load(url: url)
            baselineURL = url
            baselineDocument = document
            lastBaselineBackupURL = nil
            refreshBaselineComparison()
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func refreshBaselineComparison() {
        guard let baselineDocument, let analysisResult else {
            baselineComparison = nil
            return
        }
        baselineComparison = compareBaseline(document: baselineDocument, result: analysisResult, comparedAt: Date())
    }

    private func diagnosticsText(generatedAt: Date) throws -> String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unversioned development build"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unversioned development build"
        let sensitiveValues = devices.flatMap { [$0.name, $0.identifier] } + [
            outputDirectory.path,
            exportDirectory.path,
            baselineURL?.path ?? "",
            analysisCaptureURL?.path ?? "",
            captureCompletion?.savedURL.path ?? ""
        ]
        let input = DiagnosticsInput(
            generatedAt: generatedAt,
            application: DiagnosticApplication(
                name: "RVI-Sentinel",
                version: version,
                build: build,
                operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString,
                architecture: currentArchitectureName()
            ),
            devices: devices,
            setupChecks: setupChecks,
            interfaces: interfaces,
            capturePhase: captureProgress.phase,
            captureRunning: isCapturing,
            validatedCaptureAvailable: captureCompletion != nil,
            analysisRunning: isAnalyzing,
            analysisResultAvailable: analysisResult != nil,
            baselineSelected: baselineDocument != nil,
            localExportCount: exportReceipts.count,
            recentError: lastError,
            sensitiveValues: sensitiveValues
        )
        return try encodeRedactedDiagnostics(makeRedactedDiagnostics(input: input))
    }
}

let supportedPacketCaptureExtensions: [String] = ["pcap", "pcapng", "cap"]

func packetCaptureContentTypes() -> [UTType] {
    supportedPacketCaptureExtensions.compactMap { fileExtension in
        UTType(filenameExtension: fileExtension, conformingTo: .data)
    }
}

func sanitizedFilename(_ value: String) -> String {
    let scalars = value.unicodeScalars.map { scalar -> Character in
        CharacterSet.alphanumerics.contains(scalar) || scalar.value == 45 || scalar.value == 95
            ? Character(String(scalar))
            : "-"
    }
    let normalized = String(scalars).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    return normalized.isEmpty ? "investigation" : normalized
}

func suggestedCaptureURL(
    directory: URL,
    deviceName: String,
    format: CaptureFormat,
    date: Date
) -> URL {
    let safeName = deviceName.lowercased()
        .replacingOccurrences(of: #"[^a-z0-9]+"#, with: "-", options: .regularExpression)
        .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone.current
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    let base = safeName.isEmpty ? "ios-device" : safeName
    return directory.appendingPathComponent("\(base)-\(formatter.string(from: date)).\(format.rawValue)")
}
