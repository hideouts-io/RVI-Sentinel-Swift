import SwiftUI

struct SetupView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(title: "Check Setup", subtitle: "Know what is ready and how to fix what is not", symbol: "checkmark.shield")
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Capture destination").font(.caption).foregroundStyle(.secondary)
                    Text(appState.outputDirectory.path).lineLimit(1).truncationMode(.middle)
                }
                Spacer()
                Button("Choose Folder…") { appState.chooseOutputDirectory() }
                    .accessibilityIdentifier(AccessibilityIdentifier.chooseSetupFolder.rawValue)
                Button {
                    Task { await appState.runSetupChecks() }
                } label: {
                    if appState.isCheckingSetup {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Run Checks", systemImage: "play.fill")
                    }
                }
                .disabled(appState.isCheckingSetup)
                .buttonStyle(.borderedProminent)
                .accessibilityHint(appState.isCheckingSetup
                    ? "Setup checks are already running."
                    : "Runs local readiness checks without starting a capture.")
                .accessibilityIdentifier(AccessibilityIdentifier.runSetupChecks.rawValue)
            }
            if appState.setupChecks.isEmpty {
                ContentUnavailableView("Setup has not been checked", systemImage: "checklist", description: Text("Run checks before starting a capture."))
            } else {
                List(appState.setupChecks) { check in
                    SetupCheckRow(check: check)
                }
                .listStyle(.inset)
            }
        }
        .padding(28)
        .navigationTitle("Check Setup")
    }
}

struct SetupCheckRow: View {
    let check: SetupCheck

    private var color: Color {
        switch check.state {
        case .passed: .green
        case .failed: .red
        case .warning: .orange
        case .pending: .secondary
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Text(check.state.rawValue)
                .font(.caption.bold())
                .foregroundStyle(color)
                .frame(width: 58)
                .padding(.vertical, 5)
                .background(color.opacity(0.12), in: Capsule())
            VStack(alignment: .leading, spacing: 5) {
                Text(check.title).font(.headline)
                Text(check.detail).foregroundStyle(.secondary)
                if check.state != .passed {
                    Label(check.correctiveAction, systemImage: "wrench.and.screwdriver")
                        .font(.callout)
                    Label(check.recoveryGuidance.retry, systemImage: "arrow.clockwise")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Label(check.recoveryGuidance.evidenceImpact, systemImage: "checkmark.shield")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("Evidence: \(check.evidenceSource)")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 6)
    }
}
