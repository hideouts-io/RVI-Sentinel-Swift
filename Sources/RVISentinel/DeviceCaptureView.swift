import SwiftUI

struct DeviceCaptureView: View {
    @EnvironmentObject private var appState: AppState
    @State private var durationSeconds = 60
    @State private var captureFormat = CaptureFormat.pcapng

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(title: "Device & Capture", subtitle: "Select a trusted USB device and configure bounded evidence collection", symbol: "iphone.gen3")
            HStack {
                Text("Physical iPhones and iPads only. Simulators are excluded.")
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    Task { await appState.refreshDevices() }
                } label: {
                    if appState.isRefreshingDevices {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh Devices", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(appState.isRefreshingDevices)
            }
            GroupBox("Connected Apple mobile devices") {
                if appState.devices.isEmpty {
                    ContentUnavailableView("No device loaded", systemImage: "cable.connector", description: Text("Connect, unlock, and trust the device, then refresh."))
                        .frame(minHeight: 160)
                } else {
                    List(selection: $appState.selectedDeviceIdentifier) {
                        ForEach(appState.devices) { device in
                            DeviceRow(device: device, showAdvancedDetails: appState.showAdvancedDetails)
                                .tag(device.identifier)
                        }
                    }
                    .frame(minHeight: 180)
                }
            }
            GroupBox("Capture configuration") {
                Form {
                    Stepper("Duration: \(durationSeconds) seconds", value: $durationSeconds, in: 5...3_600, step: 5)
                    Picker("Format", selection: $captureFormat) {
                        ForEach(CaptureFormat.allCases) { format in
                            Text(format.rawValue.uppercased()).tag(format)
                        }
                    }
                    LabeledContent("Destination", value: appState.outputDirectory.path)
                }
                .padding(.vertical, 6)
            }
            HStack {
                Spacer()
                Button("Choose Destination…") { appState.chooseOutputDirectory() }
                    .disabled(appState.isCapturing)
                if appState.isCapturing {
                    Button("Cancel Capture", role: .destructive) {
                        Task { await appState.cancelCapture() }
                    }
                }
                Button("Start Guided Capture") {
                    Task { await appState.startCapture(durationSeconds: durationSeconds, format: captureFormat) }
                }
                    .buttonStyle(.borderedProminent)
                    .disabled(appState.selectedDevice?.readiness != .ready || appState.isCapturing)
            }
            CaptureStatusView(
                progress: appState.captureProgress,
                durationSeconds: durationSeconds,
                isCapturing: appState.isCapturing
            )
            if let completion = appState.captureCompletion {
                CaptureCompletionView(completion: completion)
            }
            LimitationBanner()
        }
        .padding(28)
        .navigationTitle("Device & Capture")
        .task {
            if appState.devices.isEmpty { await appState.refreshDevices() }
        }
    }
}

struct CaptureStatusView: View {
    let progress: CaptureProgress
    let durationSeconds: Int
    let isCapturing: Bool

    var body: some View {
        GroupBox("Capture status") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(progress.phase.rawValue).font(.headline)
                    Spacer()
                    if isCapturing { ProgressView().controlSize(.small) }
                }
                ProgressView(
                    value: progress.phase == .capturing || progress.phase == .finalizing ? progress.elapsedSeconds : 0,
                    total: TimeInterval(durationSeconds)
                )
                Text(progress.status).foregroundStyle(.secondary)
                HStack {
                    Label("\(Int(progress.elapsedSeconds)) s", systemImage: "timer")
                    Label(ByteCountFormatter.string(fromByteCount: progress.bytesWritten, countStyle: .file), systemImage: "doc")
                    if progress.packetCount > 0 {
                        Label("\(progress.packetCount) packets", systemImage: "shippingbox")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .padding(.vertical, 6)
        }
    }
}

struct CaptureCompletionView: View {
    @EnvironmentObject private var appState: AppState
    let completion: CaptureCompletion

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label(
                    completion.partialSuccess ? "Capture saved; cleanup needs attention" : "Capture succeeded",
                    systemImage: completion.partialSuccess ? "exclamationmark.triangle.fill" : "checkmark.seal.fill"
                )
                .font(.title2.bold())
                .foregroundStyle(completion.partialSuccess ? .orange : .green)
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 7) {
                    completionRow("Packets", "\(completion.packetCount)")
                    completionRow("File size", ByteCountFormatter.string(fromByteCount: completion.fileSize, countStyle: .file))
                    completionRow("Requested duration", "\(Int(completion.requestedDuration)) seconds")
                    completionRow("Actual packet span", String(format: "%.3f seconds", completion.actualDuration))
                    completionRow("Saved location", completion.savedURL.path)
                    completionRow("Source", "\(completion.source) through \(completion.interfaceName)")
                    completionRow("Cleanup", completion.cleanupStatus)
                    completionRow("SHA-256", completion.sha256)
                }
                .textSelection(.enabled)
                HStack {
                    Button("Analyze") { appState.prepareCompletedCaptureForAnalysis() }
                        .buttonStyle(.borderedProminent)
                    Button("Open File Location") { appState.revealCapture() }
                    Button("Capture Again") { appState.clearCaptureCompletion() }
                }
            }
            .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private func completionRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(label == "SHA-256" ? .caption.monospaced() : .body)
        }
    }
}

struct DeviceRow: View {
    let device: DeviceInfo
    let showAdvancedDetails: Bool

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: device.readiness == .ready ? "iphone.gen3.circle.fill" : "iphone.gen3.slash")
                .font(.title2)
                .foregroundStyle(device.readiness == .ready ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(device.name).font(.headline)
                Text("\(device.model) • \(device.operatingSystem)").foregroundStyle(.secondary)
                Text(device.status).font(.caption).foregroundStyle(device.readiness == .ready ? .green : .orange)
                if showAdvancedDetails {
                    Text("Identifier: \(device.identifier)").font(.caption.monospaced()).textSelection(.enabled)
                    Text("Transport: \(device.transport) • Pairing: \(device.pairingState) • Boot: \(device.bootState)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(.vertical, 5)
    }
}
