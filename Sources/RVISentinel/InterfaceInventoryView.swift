import SwiftUI

struct InterfaceInventoryView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(title: "iOS Interfaces", subtitle: "Show only interface labels observed carrying packets in the analyzed iPhone or iPad capture", symbol: "network")
            HStack {
                Text("IPv4 and IPv6 hostname resolution is always enabled during analysis.")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Open Analysis", systemImage: "waveform.path.ecg.rectangle") { appState.selectedSection = .analysis }
                    .accessibilityIdentifier(AccessibilityIdentifier.openAnalysis.rawValue)
            }
            if appState.interfaces.isEmpty {
                ContentUnavailableView(
                    appState.analysisResult == nil ? "Analyze a capture first" : "No iOS interface metadata was reported",
                    systemImage: "network.slash",
                    description: Text(appState.analysisResult == nil
                        ? "Choose an authorized RVI capture and run Analysis. Host Mac interfaces are intentionally not shown here."
                        : "The capture did not contain frame.interface_name metadata for an iOS interface. This does not mean every interface was down.")
                )
            } else {
                Table(appState.interfaces) {
                    TableColumn("Interface") { item in
                        Text(item.name).font(.body.monospaced().bold())
                    }
                    .width(min: 140, ideal: 180)
                    TableColumn("State") { _ in
                        Label("Active in capture", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                    .width(130)
                    TableColumn("Likely role") { item in
                        VStack(alignment: .leading) {
                            Text(item.friendlyType)
                            Text(item.associatedService).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 150, ideal: 210)
                    TableColumn("Evidence") { item in
                        Text(item.evidenceSource).font(.caption).foregroundStyle(.secondary)
                    }
                    .width(min: 180, ideal: 240)
                }
            }
            Text("A row means packets were observed with that capture-reported interface label. It does not prove that every other iOS interface was down or that the capture saw every interface. Temporary Mac-side rvi interfaces are excluded.")
                .font(.callout)
                .padding()
                .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        }
        .padding(28)
        .navigationTitle("iOS Interfaces")
    }
}
