import SwiftUI

struct DiagnosticsView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(
                title: "Diagnostics",
                subtitle: "Share setup evidence without sharing private captures or device identity",
                symbol: "stethoscope"
            )
            Text("The diagnostics document is generated locally. It excludes packet data, addresses, hostnames, device names and identifiers, credentials, and private file paths. Review the preview before copying or saving it.")
                .foregroundStyle(.secondary)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                Button("Refresh Preview") { appState.refreshDiagnostics() }
                Spacer()
                Button("Copy Redacted Diagnostics") { appState.copyDiagnostics() }
                    .buttonStyle(.borderedProminent)
                Button("Save Diagnostics…") { appState.saveDiagnostics() }
            }
            GroupBox("Redacted preview") {
                ScrollView {
                    Text(appState.diagnosticsPreview.isEmpty ? "Generate the preview to inspect exactly what will be copied or saved." : appState.diagnosticsPreview)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(8)
                }
            }
            if let copiedAt = appState.diagnosticsCopiedAt {
                Label("Redacted diagnostics copied at \(copiedAt.formatted(date: .omitted, time: .standard)).", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
        }
        .padding(28)
        .navigationTitle("Diagnostics")
        .task { appState.refreshDiagnostics() }
    }
}
