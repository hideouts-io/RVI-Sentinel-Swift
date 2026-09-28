import AppKit
import Foundation
import SwiftUI

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
    @Published var lastError: String?
    @Published var selectedDeviceIdentifier: String?
    @Published var outputDirectory: URL
    @Published var showAdvancedDetails = false

    private let discoveryService: DeviceDiscoveryService
    private let interfaceService: InterfaceInventoryService
    private let setupChecker: SetupChecker
    private let captureCoordinator: CaptureCoordinator

    init(
        discoveryService: DeviceDiscoveryService,
        interfaceService: InterfaceInventoryService,
        setupChecker: SetupChecker,
        captureCoordinator: CaptureCoordinator,
        outputDirectory: URL
    ) {
        self.discoveryService = discoveryService
        self.interfaceService = interfaceService
        self.setupChecker = setupChecker
        self.captureCoordinator = captureCoordinator
        self.outputDirectory = outputDirectory
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
        let output = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        return AppState(
            discoveryService: discovery,
            interfaceService: interfaceService,
            setupChecker: checker,
            captureCoordinator: captureCoordinator,
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

    func refreshInterfaces() {
        lastError = nil
        do {
            interfaces = try interfaceService.inventory()
        } catch {
            interfaces = []
            lastError = error.localizedDescription
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
        lastError = nil
        do {
            let completion = try await captureCoordinator.capture(configuration: configuration) { [weak self] update in
                Task { @MainActor in self?.captureProgress = update }
            }
            captureCompletion = completion
        } catch {
            captureProgress = CaptureProgress(
                phase: error is CancellationError ? .cancelled : .failed,
                elapsedSeconds: captureProgress.elapsedSeconds,
                packetCount: captureProgress.packetCount,
                bytesWritten: captureProgress.bytesWritten,
                status: error.localizedDescription
            )
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
        captureProgress = CaptureProgress(phase: .idle, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Ready to configure another capture.")
    }

    func revealCapture() {
        guard let captureCompletion else { return }
        NSWorkspace.shared.activateFileViewerSelecting([captureCompletion.savedURL])
    }
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
