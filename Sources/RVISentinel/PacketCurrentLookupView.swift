import SwiftUI

private enum PacketLookupDisplayState {
    case idle
    case loading(Date)
    case cancelled(Date)
    case failed(requestedAt: Date, detail: String)
    case completed(CurrentPTRLookupResult)
}

struct PacketCurrentLookupView: View {
    let packetID: PacketRecordID
    let address: PacketIPAddress?
    let title: String
    let lookupIdentifier: String
    let cancelIdentifier: String
    @State private var state = PacketLookupDisplayState.idle
    @State private var operationID: UUID?
    @State private var operationTask: Task<Void, Never>?
    @State private var decoder: BoundedDecoder?
    @State private var cleanupTask: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("\(title): \(address?.rawValue ?? "Unknown endpoint")").font(.body.monospaced()).textSelection(.enabled)
                Spacer()
                Button("Look Up \(title)") { startLookup() }
                    .disabled(address == nil || operationTask != nil)
                    .accessibilityIdentifier(lookupIdentifier)
                if operationTask != nil {
                    Button("Cancel Lookup", role: .destructive) { cancelLookup() }
                        .accessibilityIdentifier(cancelIdentifier)
                }
            }
            lookupResult
        }
        .onChange(of: packetID) { _, _ in cancelLookup(); state = .idle }
        .onDisappear { cancelLookup() }
    }

    @ViewBuilder
    private var lookupResult: some View {
        switch state {
        case .idle:
            Text("No current lookup requested.").font(.caption).foregroundStyle(.secondary)
        case let .loading(requestedAt):
            HStack { ProgressView().controlSize(.small); Text("Current PTR lookup requested \(requestTime(requestedAt))") }
                .accessibilityIdentifier("\(lookupIdentifier).loading")
        case let .cancelled(requestedAt):
            Text("Current lookup requested \(requestTime(requestedAt)) was cancelled.").font(.caption)
        case let .failed(requestedAt, detail):
            Text("Current lookup requested \(requestTime(requestedAt)) failed: \(detail)")
                .foregroundStyle(.red).textSelection(.enabled).accessibilityIdentifier("\(lookupIdentifier).error")
        case let .completed(result):
            VStack(alignment: .leading, spacing: 5) {
                Text("Present-day enrichment · \(result.provenance.rawValue)").font(.caption).foregroundStyle(.secondary)
                Text("Requested: \(requestTime(result.requestedAt)) · Completed: \(requestTime(result.completedAt))").font(.caption)
                Text("Result: \(lookupStatus(result.status))").accessibilityIdentifier("\(lookupIdentifier).status")
                ForEach(Array(result.answers.enumerated()), id: \.offset) { _, answer in
                    Text("\(answer.owner) · \(answer.recordType.rawValue) · \(answer.value) · TTL \(answer.ttlSeconds) s")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            }.accessibilityIdentifier("\(lookupIdentifier).result")
        }
    }

    private func startLookup() {
        guard let address, operationTask == nil else { return }
        let token = UUID()
        let requestedAt = Date()
        let ownedDecoder = BoundedDecoder()
        let selectedID = packetID
        operationID = token
        decoder = ownedDecoder
        state = .loading(requestedAt)
        operationTask = Task {
            do {
                let result = try await lookupCurrentPTR(
                    address: address.rawValue, packetID: selectedID, decoder: ownedDecoder,
                    timeout: .seconds(5), maximumOutputBytes: 32_768
                )
                try Task.checkCancellation()
                guard operationID == token else { return }
                state = .completed(result)
            } catch is CancellationError {
                guard operationID == token else { return }
                state = .cancelled(requestedAt)
            } catch {
                guard operationID == token else { return }
                state = .failed(requestedAt: requestedAt, detail: "\(error.localizedDescription) Check the Mac's configured resolver before requesting another lookup.")
            }
            guard operationID == token else { return }
            operationTask = nil
            decoder = nil
            operationID = nil
        }
    }

    private func cancelLookup() {
        guard let operationTask else { return }
        if case let .loading(requestedAt) = state { state = .cancelled(requestedAt) }
        operationID = nil
        cleanupTask = stopPacketInspectorWork(task: operationTask, decoder: decoder)
        self.operationTask = nil
        decoder = nil
    }

    private func requestTime(_ date: Date) -> String {
        date.formatted(date: .numeric, time: .standard)
    }

    private func lookupStatus(_ status: CurrentPTRStatus) -> String {
        switch status {
        case .answered: "Answered"
        case .noAnswer: "No PTR answer"
        case .nameDoesNotExist: "Name does not exist (NXDOMAIN)"
        }
    }
}
