import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        NavigationSplitView {
            List(NavigationSection.allCases, selection: $appState.selectedSection) { section in
                Label(section.rawValue, systemImage: section.symbolName)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 215)
        } detail: {
            Group {
                switch appState.selectedSection {
                case .overview:
                    OverviewView()
                case .setup:
                    SetupView()
                case .devices:
                    DeviceCaptureView()
                case .interfaces:
                    InterfaceInventoryView()
                case .analysis:
                    AnalysisView()
                case .baselines:
                    BaselineView()
                case .exports:
                    ExportView()
                case .diagnostics:
                    DiagnosticsView()
                }
            }
            .toolbar {
                Toggle(isOn: $appState.showAdvancedDetails) {
                    Label("Advanced Details", systemImage: "gearshape.2")
                }
                .toggleStyle(.button)
            }
        }
        .alert("RVI-Sentinel", isPresented: Binding(
            get: { appState.lastError != nil },
            set: { if !$0 { appState.lastError = nil } }
        )) {
            Button("OK", role: .cancel) { appState.lastError = nil }
        } message: {
            Text(appState.lastError ?? "")
        }
    }
}

struct PageHeader: View {
    let title: String
    let subtitle: String
    let symbol: String

    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 56, height: 56)
                .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.largeTitle.bold())
                Text(subtitle).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

struct OverviewView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                PageHeader(
                    title: "RVI-Sentinel",
                    subtitle: "Guided, local iPhone and iPad network evidence collection",
                    symbol: "iphone.gen3.radiowaves.left.and.right"
                )
                Text("Capture only devices and networks you are authorized to inspect. A new endpoint or hostname is a change to investigate—not proof of malicious activity. Encrypted payloads remain protected.")
                    .font(.title3)
                    .padding()
                    .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 16)], spacing: 16) {
                    WorkflowCard(number: 1, title: "Check Setup", detail: "Verify the phone, USB trust, Apple capture tools, analysis backend, destination, disk space, and cleanup state.", symbol: "checkmark.shield") {
                        appState.selectedSection = .setup
                    }
                    WorkflowCard(number: 2, title: "Select Device", detail: "Choose a physical, booted iPhone or iPad paired over USB. The full device identifier stays hidden.", symbol: "iphone.gen3") {
                        appState.selectedSection = .devices
                    }
                    WorkflowCard(number: 3, title: "Choose Evidence Source", detail: "RVI is device traffic. Mac interfaces are inventoried separately and never captured silently.", symbol: "network") {
                        appState.selectedSection = .interfaces
                    }
                    WorkflowCard(number: 4, title: "Capture and Validate", detail: "Authorize the narrow capture operation, verify live packets, capture for a bounded duration, flush, validate, and clean up.", symbol: "record.circle") {
                        appState.selectedSection = .devices
                    }
                    WorkflowCard(number: 5, title: "Review Results", detail: "Separate direct packet evidence from inference and optional enrichment. Preserve hostname provenance.", symbol: "list.bullet.rectangle") {
                        appState.selectedSection = .analysis
                    }
                    WorkflowCard(number: 6, title: "Baseline or Export", detail: "Analyze without changing a baseline, then explicitly add reviewed findings or export local reports.", symbol: "square.and.arrow.up") {
                        appState.selectedSection = .baselines
                    }
                }
                LimitationBanner()
            }
            .padding(28)
        }
        .navigationTitle("Overview")
    }
}

struct WorkflowCard: View {
    let number: Int
    let title: String
    let detail: String
    let symbol: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("\(number)")
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                        .frame(width: 24, height: 24)
                        .background(.tint, in: Circle())
                    Image(systemName: symbol).foregroundStyle(.tint)
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, minHeight: 135, alignment: .topLeading)
            .padding()
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 14))
        }
        .buttonStyle(.plain)
    }
}

struct LimitationBanner: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Label("Evidence boundary", systemImage: "eye.trianglebadge.exclamationmark")
                .font(.headline)
            Text("RVI packets do not inherently reveal an iOS process or the phone's internal en0, pdp_ip, or utun interface. The app must display “Process not observable from this capture” unless independent evidence proves ownership.")
                .foregroundStyle(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct NotYetMigratedView: View {
    let title: String
    let detail: String

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: "hammer")
        } description: {
            Text(detail)
        } actions: {
            Text("Migration status is explicit; the working Python implementation remains available.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
