import SwiftUI

struct ExportView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(
                title: "Exports",
                subtitle: "Create local reports without uploading capture evidence",
                symbol: "square.and.arrow.up"
            )
            Text("Exports contain sensitive endpoint and hostname evidence. They stay in the local folder you choose. The source capture is never rewritten or embedded, and every export records its own SHA-256 hash.")
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Local export folder").font(.caption).foregroundStyle(.secondary)
                    Text(appState.showAdvancedDetails ? appState.exportDirectory.path : appState.exportDirectory.lastPathComponent)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Button("Choose Folder…") { appState.chooseExportDirectory() }
                ForEach(ReportExportFormat.allCases) { format in
                    Button("Export \(format.rawValue)") {
                        Task { await appState.exportAnalysis(format: format) }
                    }
                    .buttonStyle(.bordered)
                    .disabled(appState.analysisResult == nil || appState.isExporting)
                }
            }
            if appState.isExporting {
                HStack { ProgressView(); Text("Writing local export and computing hashes…") }
            }
            if appState.analysisResult == nil {
                ContentUnavailableView(
                    "No analysis results",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text("Analyze an authorized capture first. Exporting never runs active DNS resolution.")
                )
            } else if appState.exportReceipts.isEmpty {
                ContentUnavailableView(
                    "Ready to export",
                    systemImage: "square.and.arrow.up",
                    description: Text("JSON preserves the typed report, CSV creates separate inventories plus a hash manifest, and HTML creates a readable local report.")
                )
            } else {
                Table(appState.exportReceipts) {
                    TableColumn("Format") { Text($0.format.rawValue).font(.headline) }.width(100)
                    TableColumn("Output") { receipt in
                        Text(appState.showAdvancedDetails ? receipt.outputURL.path : receipt.outputURL.lastPathComponent)
                            .textSelection(.enabled)
                    }
                    TableColumn("Files") { Text($0.fileCount.formatted()).monospacedDigit() }.width(60)
                    TableColumn("SHA-256 / manifest SHA-256") { Text($0.sha256).font(.caption.monospaced()).textSelection(.enabled) }
                    TableColumn("Created") { Text($0.createdAt.formatted(date: .omitted, time: .standard)) }.width(100)
                    TableColumn("") { receipt in
                        Button("Show") { appState.revealExport(receipt) }
                    }
                    .width(70)
                }
            }
        }
        .padding(28)
        .navigationTitle("Exports")
    }
}
