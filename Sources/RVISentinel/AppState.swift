import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

@MainActor
final class AppState: ObservableObject {
    @Published var selectedSection: NavigationSection = .overview
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
    @Published private(set) var isAnalyzing = false
    @Published private(set) var analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Choose an authorized capture to begin.")
    @Published private(set) var analysisResult: NativeAnalysisResult?
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
        let analyzer = TSharkAnalyzer(processRunner: runner)
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
            devices = try await discoveryService.discover()
            if selectedDevice == nil {
                selectedDeviceIdentifier = devices.first(where: { $0.readiness == .ready })?.identifier
            }
        } catch {
            devices = []
            lastError = error.localizedDescription
        }
        isRefreshingDevices = false
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
        guard let captureCompletion else { return }
        analysisCaptureURL = captureCompletion.savedURL
        analysisResult = nil
        interfaces = []
        analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Ready to analyze the completed capture with IPv4 and IPv6 resolution enabled.")
        selectedSection = .analysis
    }

    func chooseAnalysisCapture() {
        let panel = NSOpenPanel()
        panel.title = "Choose an Authorized Packet Capture"
        panel.prompt = "Choose"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        let contentTypes = packetCaptureContentTypes()
        guard contentTypes.count == supportedPacketCaptureExtensions.count else {
            lastError = "macOS could not register the supported .pcap, .pcapng, and .cap file types."
            return
        }
        panel.allowedContentTypes = contentTypes
        if panel.runModal() == .OK, let selectedURL = panel.url {
            guard supportedPacketCaptureExtensions.contains(selectedURL.pathExtension.lowercased()) else {
                lastError = "Choose a .pcap, .pcapng, or .cap file."
                return
            }
            analysisCaptureURL = selectedURL
            analysisResult = nil
            interfaces = []
            baselineComparison = nil
            analysisProgress = AnalysisProgress(decodedPackets: 0, status: "Ready to analyze locally with IPv4 and IPv6 resolution enabled.")
        }
    }

    func startAnalysis() async {
        guard let analysisCaptureURL else {
            lastError = "Choose an authorized capture first."
            return
        }
        isAnalyzing = true
        analysisResult = nil
        interfaces = []
        lastError = nil
        do {
            let result = try await analyzer.analyze(captureURL: analysisCaptureURL) { [weak self] update in
                Task { @MainActor in self?.analysisProgress = update }
            }
            analysisResult = result
            interfaces = captureReportedIOSInterfaces(names: result.summary.interfaces)
            if let baselineDocument {
                baselineComparison = compareBaseline(document: baselineDocument, result: result, comparedAt: Date())
            }
        } catch is CancellationError {
            analysisProgress = AnalysisProgress(decodedPackets: analysisProgress.decodedPackets, status: "Analysis cancelled. The original capture was not changed.")
        } catch {
            lastError = error.localizedDescription
            analysisProgress = AnalysisProgress(decodedPackets: analysisProgress.decodedPackets, status: error.localizedDescription)
        }
        isAnalyzing = false
    }

    func cancelAnalysis() async {
        await analyzer.cancel()
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
