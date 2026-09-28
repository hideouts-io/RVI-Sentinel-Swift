import SwiftUI

struct BaselineView: View {
    @EnvironmentObject private var appState: AppState
    @State private var scopeName = ""
    @State private var showingAddConfirmation = false
    @State private var showingResetConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(
                title: "Baselines",
                subtitle: "Compare first; update only after an explicit review",
                symbol: "square.stack.3d.up"
            )
            Text("Analysis never changes a baseline. Create a separate baseline for one device or investigation, review New, Known, Changed, and not-observed findings, then choose Add Findings only when you intend to preserve them.")
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                TextField("Device or investigation name", text: $scopeName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                    .accessibilityIdentifier(AccessibilityIdentifier.baselineScopeName.rawValue)
                Button("Create Separate Baseline…") { appState.createBaseline(scopeName: scopeName) }
                    .accessibilityIdentifier(AccessibilityIdentifier.createBaseline.rawValue)
                Button("Choose Existing…") { appState.chooseBaseline() }
                    .accessibilityIdentifier(AccessibilityIdentifier.chooseBaseline.rawValue)
                Spacer()
                Button("Export Copy…") { appState.exportBaselineCopy() }
                    .disabled(appState.baselineDocument == nil)
                    .accessibilityIdentifier(AccessibilityIdentifier.exportBaseline.rawValue)
                Button("Reset…", role: .destructive) { showingResetConfirmation = true }
                    .disabled(appState.baselineDocument == nil)
                    .accessibilityIdentifier(AccessibilityIdentifier.resetBaseline.rawValue)
            }
            if let document = appState.baselineDocument {
                selectedBaseline(document: document)
                if let comparison = appState.baselineComparison {
                    comparisonView(comparison: comparison)
                } else {
                    ContentUnavailableView(
                        "No analyzed capture to compare",
                        systemImage: "rectangle.stack.badge.questionmark",
                        description: Text("The selected baseline was loaded without changing it. Analyze a capture to produce a read-only comparison.")
                    )
                }
            } else {
                ContentUnavailableView(
                    "No baseline selected",
                    systemImage: "square.stack.3d.up.slash",
                    description: Text("Create or choose a local JSON baseline. No shared default baseline is used.")
                )
            }
        }
        .padding(28)
        .navigationTitle("Baselines")
        .confirmationDialog("Add reviewed findings to this baseline?", isPresented: $showingAddConfirmation, titleVisibility: .visible) {
            Button("Add Findings to Baseline") { appState.addFindingsToBaseline() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text(addConfirmationMessage)
        }
        .confirmationDialog("Reset this baseline?", isPresented: $showingResetConfirmation, titleVisibility: .visible) {
            Button("Reset and Keep Backup", role: .destructive) { appState.resetBaseline() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("The current baseline will be copied to a timestamped backup beside the original before the selected baseline is reset.")
        }
    }

    private func selectedBaseline(document: BaselineDocument) -> some View {
        GroupBox("Selected baseline") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 7) {
                GridRow { Text("Scope").foregroundStyle(.secondary); Text(document.scopeName).font(.headline) }
                GridRow { Text("File").foregroundStyle(.secondary); Text(baselineDisplayPath).textSelection(.enabled) }
                GridRow { Text("Reviewed captures").foregroundStyle(.secondary); Text(document.capturesReviewed.formatted()) }
                GridRow { Text("Stored observations").foregroundStyle(.secondary); Text(document.observations.count.formatted()) }
                GridRow { Text("Updated").foregroundStyle(.secondary); Text(document.updatedAt.formatted()) }
                if let backup = appState.lastBaselineBackupURL {
                    GridRow { Text("Recovery backup").foregroundStyle(.secondary); Text(appState.showAdvancedDetails ? backup.path : backup.lastPathComponent).textSelection(.enabled) }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 6)
        }
    }

    private func comparisonView(comparison: BaselineComparison) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                statusMetric("New", count: comparison.count(state: .new), color: .blue)
                statusMetric("Known", count: comparison.count(state: .known), color: .green)
                statusMetric("Changed", count: comparison.count(state: .changed), color: .orange)
                statusMetric("Removed", count: comparison.count(state: .removed), color: .secondary)
                Spacer()
                Button("Add Findings to Baseline…") { showingAddConfirmation = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(appState.analysisResult == nil)
                    .accessibilityIdentifier(AccessibilityIdentifier.addBaselineFindings.rawValue)
            }
            Table(comparison.differences) {
                TableColumn("State") { difference in
                    Text(difference.state.rawValue)
                        .foregroundStyle(color(state: difference.state))
                }
                .width(min: 100, ideal: 160)
                TableColumn("Kind") { Text($0.kind.rawValue) }.width(min: 100, ideal: 140)
                TableColumn("Observation") { Text($0.title).textSelection(.enabled) }.width(min: 150, ideal: 230)
                TableColumn("Previous") { Text($0.previousSummary ?? "—").foregroundStyle(.secondary).lineLimit(3) }
                TableColumn("Current") { Text($0.currentSummary ?? "—").lineLimit(3) }
            }
        }
    }

    private func statusMetric(_ title: String, count: Int, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(count.formatted()).font(.title2.bold()).foregroundStyle(color)
        }
        .frame(minWidth: 90, alignment: .leading)
        .padding(10)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 9))
    }

    private func color(state: BaselineChangeState) -> Color {
        switch state {
        case .new: .blue
        case .known: .green
        case .changed: .orange
        case .removed: .secondary
        }
    }

    private var baselineDisplayPath: String {
        guard let url = appState.baselineURL else { return "No file selected" }
        return appState.showAdvancedDetails ? url.path : url.lastPathComponent
    }

    private var addConfirmationMessage: String {
        guard let comparison = appState.baselineComparison else { return "No comparison is available." }
        let newCount = comparison.count(state: .new)
        let changedCount = comparison.count(state: .changed)
        let knownCount = comparison.count(state: .known)
        return "This adds \(newCount) new observations, updates \(changedCount) changed observations, and records \(knownCount) known observations as reviewed. A timestamped backup is created first."
    }
}
