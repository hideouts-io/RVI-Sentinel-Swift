import AppKit
import SwiftUI

struct AnalysisView: View {
    @EnvironmentObject private var appState: AppState
    @State private var selectedResultTab = ResultTab.summary

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(title: "Analysis", subtitle: "Local packet decoding with explicit evidence provenance and coverage", symbol: "waveform.path.ecg.rectangle")
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Authorized capture").font(.caption).foregroundStyle(.secondary)
                    Text(appState.analysisCaptureURL?.path ?? "No capture selected")
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Button("Choose Capture…") { appState.chooseAnalysisCapture() }
                    .disabled(appState.isAnalyzing)
                    .accessibilityIdentifier(AccessibilityIdentifier.chooseAnalysisCapture.rawValue)
                if appState.isAnalyzing {
                    Button("Cancel", role: .destructive) { Task { await appState.cancelAnalysis() } }
                        .accessibilityIdentifier(AccessibilityIdentifier.cancelAnalysis.rawValue)
                }
                Button("Analyze Locally") { Task { await appState.startAnalysis() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(appState.analysisCaptureURL == nil || appState.isAnalyzing)
                    .accessibilityIdentifier(AccessibilityIdentifier.startAnalysis.rawValue)
            }
            AnalysisProgressView(progress: appState.analysisProgress, isAnalyzing: appState.isAnalyzing)
            if let result = appState.analysisResult {
                Picker("Result", selection: $selectedResultTab) {
                    ForEach(ResultTab.allCases) { tab in Text(tab.rawValue).tag(tab) }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier(AccessibilityIdentifier.analysisResultPicker.rawValue)
                resultView(result: result)
            } else {
                ContentUnavailableView("No analysis results", systemImage: "doc.text.magnifyingglass", description: Text("Choose an authorized capture. IPv4 and IPv6 hostname resolution runs automatically during analysis."))
            }
        }
        .padding(28)
        .navigationTitle("Analysis")
    }

    @ViewBuilder
    private func resultView(result: NativeAnalysisResult) -> some View {
        switch selectedResultTab {
        case .summary: AnalysisSummaryView(result: result)
        case .endpoints: EndpointResultsView(endpoints: result.endpoints, hostnames: result.hostnames)
        case .hostnames: HostnameResultsView(hostnames: result.hostnames)
        case .protocols: ProtocolResultsView(protocols: result.protocols)
        case .details: ProtocolDetailResultsView(details: result.protocolDetails)
        case .ports: PortResultsView(ports: result.ports)
        case .coverage: CoverageView(coverage: result.coverage)
        }
    }
}

private enum ResultTab: String, CaseIterable, Identifiable {
    case summary = "Summary"
    case endpoints = "Endpoints"
    case hostnames = "Hostnames"
    case protocols = "Protocols"
    case details = "Protocol Details"
    case ports = "Ports"
    case coverage = "Coverage"

    var id: String { rawValue }
}

struct AnalysisProgressView: View {
    let progress: AnalysisProgress
    let isAnalyzing: Bool

    var body: some View {
        HStack(spacing: 10) {
            if isAnalyzing { ProgressView().controlSize(.small) }
            Text(progress.status).foregroundStyle(.secondary)
            Spacer()
            if progress.decodedPackets > 0 { Text("\(progress.decodedPackets.formatted()) packets").font(.caption.monospacedDigit()) }
        }
        .accessibilityIdentifier(AccessibilityIdentifier.analysisProgress.rawValue)
    }
}

struct AnalysisSummaryView: View {
    let result: NativeAnalysisResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 190))], spacing: 12) {
                    metric("Packets", result.summary.packetCount.formatted())
                    metric("Captured bytes", ByteCountFormatter.string(fromByteCount: result.summary.byteCount, countStyle: .file))
                    metric("Endpoints", result.endpoints.count.formatted())
                    metric("Hostname evidence", result.hostnames.count.formatted())
                    metric("Protocols", result.protocols.count.formatted())
                    metric("Interfaces in metadata", result.summary.interfaces.isEmpty ? "Not reported" : result.summary.interfaces.joined(separator: ", "))
                }
                GroupBox("Evidence provenance") {
                    Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 7) {
                        GridRow { Text("Capture").foregroundStyle(.secondary); Text(result.summary.captureURL.path) }
                        GridRow { Text("SHA-256").foregroundStyle(.secondary); Text(result.summary.captureSHA256).font(.caption.monospaced()) }
                        GridRow { Text("First packet").foregroundStyle(.secondary); Text(result.summary.firstPacket?.formatted() ?? "Unavailable") }
                        GridRow { Text("Last packet").foregroundStyle(.secondary); Text(result.summary.lastPacket?.formatted() ?? "Unavailable") }
                        GridRow { Text("Decoder").foregroundStyle(.secondary); Text(result.coverage.tsharkVersion) }
                        GridRow { Text("Active resolution").foregroundStyle(.secondary); Text(result.coverage.activeResolutionEnabled ? "Enabled for IPv4 and IPv6" : "Disabled") }
                    }
                    .textSelection(.enabled)
                    .padding(.vertical, 6)
                }
                LimitationBanner()
            }
        }
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title3.bold()).lineLimit(2)
        }
        .frame(maxWidth: .infinity, minHeight: 65, alignment: .leading)
        .padding()
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}

struct EndpointResultsView: View {
    let endpoints: [EndpointObservation]
    let hostnames: [HostnameEvidence]

    var body: some View {
        Table(endpoints) {
            TableColumn("Address") { Text($0.address).font(.body.monospaced()).textSelection(.enabled) }.width(min: 150, ideal: 220)
            TableColumn("Resolved hostname") { endpoint in
                Text(endpointHostnameLabel(address: endpoint.address, hostnames: hostnames))
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
            .width(min: 170, ideal: 250)
            TableColumn("Name source") { endpoint in
                Text(endpointHostnameProvenanceLabel(address: endpoint.address, hostnames: hostnames))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .width(min: 150, ideal: 210)
            TableColumn("Scope") { Text($0.classification) }.width(110)
            TableColumn("Source / destination packets") { Text("\($0.sourcePackets) / \($0.destinationPackets)").monospacedDigit() }.width(170)
            TableColumn("Traffic") { Text(ByteCountFormatter.string(fromByteCount: $0.sourceBytes + $0.destinationBytes, countStyle: .file)) }.width(95)
            TableColumn("Protocols") { Text($0.protocols.map(\.rawValue).joined(separator: ", ")).lineLimit(2) }
            TableColumn("Process") { Text($0.processAttribution.processName).foregroundStyle(.secondary) }.width(min: 180, ideal: 240)
        }
    }
}

func endpointHostnameLabel(address: String, hostnames: [HostnameEvidence]) -> String {
    let names: [String] = Array(Set(hostnames.filter { $0.address == address }.map(\.hostname))).sorted()
    return names.isEmpty ? "Not resolved" : names.joined(separator: ", ")
}

func endpointHostnameProvenanceLabel(address: String, hostnames: [HostnameEvidence]) -> String {
    let sources: [String] = Array(Set(hostnames.filter { $0.address == address }.map { $0.provenance.rawValue })).sorted()
    return sources.isEmpty ? "No hostname evidence" : sources.joined(separator: ", ")
}

struct HostnameResultsView: View {
    let hostnames: [HostnameEvidence]

    var body: some View {
        Table(hostnames) {
            TableColumn("Hostname") { Text($0.hostname).textSelection(.enabled) }.width(min: 180, ideal: 260)
            TableColumn("Related IP") { Text($0.address ?? "Not established").font(.body.monospaced()) }.width(min: 130, ideal: 180)
            TableColumn("Provenance") { Text($0.provenance.rawValue) }.width(min: 150, ideal: 210)
            TableColumn("Confidence") { Text($0.confidence.rawValue) }.width(90)
            TableColumn("First seen") { Text($0.firstSeen.formatted(date: .omitted, time: .standard)) }.width(100)
            TableColumn("Last seen") { Text($0.lastSeen.formatted(date: .omitted, time: .standard)) }.width(100)
        }
    }
}

struct ProtocolResultsView: View {
    let protocols: [ProtocolObservation]

    var body: some View {
        Table(protocols) {
            TableColumn("Protocol") { Text($0.protocolKind.rawValue).font(.headline) }.width(min: 130, ideal: 180)
            TableColumn("Packets") { Text($0.packetCount.formatted()).monospacedDigit() }.width(90)
            TableColumn("Bytes") { Text(ByteCountFormatter.string(fromByteCount: $0.byteCount, countStyle: .file)) }.width(90)
            TableColumn("Identification evidence") { Text($0.identification).foregroundStyle(.secondary) }
        }
    }
}

struct ProtocolDetailResultsView: View {
    let details: [ProtocolDetailObservation]

    var body: some View {
        if details.isEmpty {
            ContentUnavailableView(
                "No supported protocol details were decoded",
                systemImage: "list.bullet.rectangle",
                description: Text("Review Coverage to see which TShark fields are supported. Missing metadata is not proof that an activity did not occur.")
            )
        } else {
            Table(details) {
                TableColumn("Protocol") { Text($0.protocolKind.rawValue).font(.headline) }.width(min: 110, ideal: 150)
                TableColumn("Category") { Text($0.category) }.width(min: 110, ideal: 150)
                TableColumn("Field") { Text($0.label) }.width(min: 130, ideal: 190)
                TableColumn("Observed value") { Text($0.value).font(.body.monospaced()).textSelection(.enabled) }.width(min: 160, ideal: 260)
                TableColumn("Count") { Text($0.occurrenceCount.formatted()).monospacedDigit() }.width(70)
                TableColumn("Evidence source") { Text($0.field.rawValue).font(.caption.monospaced()) }.width(min: 130, ideal: 190)
                TableColumn("Limit") { Text($0.evidenceBoundary).foregroundStyle(.secondary) }.width(min: 220, ideal: 300)
            }
        }
    }
}

struct PortResultsView: View {
    let ports: [PortObservation]

    var body: some View {
        Table(ports) {
            TableColumn("Transport") { Text($0.transport) }.width(80)
            TableColumn("Port") { Text($0.port.formatted()).monospacedDigit() }.width(70)
            TableColumn("Standard service") { Text($0.standardService).font(.headline) }.width(min: 140, ideal: 190)
            TableColumn("Observed packets") { Text($0.packetCount.formatted()).monospacedDigit() }.width(120)
            TableColumn("Usual purpose") { Text($0.explanation) }
            TableColumn("Limit") { Text($0.evidenceBoundary).foregroundStyle(.secondary) }.width(min: 200, ideal: 280)
        }
    }
}

struct CoverageView: View {
    let coverage: AnalysisCoverage

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Decoder coverage") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(coverage.tsharkVersion).font(.headline)
                        Text("\(coverage.supportedFields.count) requested fields supported; \(coverage.unsupportedFields.count) unsupported by this installation.")
                        Text("Active resolution: \(coverage.activeResolutionEnabled ? "Enabled" : "Disabled")")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
                }
                GroupBox("Unsupported fields") {
                    Text(coverage.unsupportedFields.isEmpty ? "None" : coverage.unsupportedFields.map(\.rawValue).joined(separator: "\n"))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                GroupBox("Limitations") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(coverage.limitations, id: \.self) { Label($0, systemImage: "info.circle") }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
                }
            }
        }
    }
}
