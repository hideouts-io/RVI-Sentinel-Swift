import SwiftUI

private enum PacketRawDisplayState {
    case idle
    case loading
    case cancelled
    case failed(String)
    case completed(OriginalPacketEvidence)
}

struct PacketRawBytesView: View {
    let packet: PacketRecord
    let artifact: PacketCaptureArtifact
    let supportedFields: Set<TSharkField>
    @State private var state = PacketRawDisplayState.idle
    @State private var operationID: UUID?
    @State private var operationTask: Task<Void, Never>?
    @State private var decoder: BoundedDecoder?
    @State private var cleanupTask: Task<Void, Never>?
    @State private var byteOffset = 0
    @State private var selectedRange: OriginalPacketByteRange?
    @State private var verifiedRangesExpanded = false
    @State private var unmappedFieldsExpanded = false

    var body: some View {
        GroupBox("Original packet bytes") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button("Inspect Original Packet Bytes") { startInspection() }
                        .disabled(operationTask != nil)
                        .accessibilityIdentifier("analysis.packet.inspect-bytes")
                    if operationTask != nil {
                        Button("Cancel Inspection", role: .destructive) { cancelInspection() }
                            .accessibilityIdentifier("analysis.packet.cancel-inspect-bytes")
                    }
                }
                inspectionResult
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
        }
        .onChange(of: packet.id) { _, _ in
            cancelInspection()
            state = .idle
            byteOffset = 0
            selectedRange = nil
            verifiedRangesExpanded = false
            unmappedFieldsExpanded = false
        }
        .onDisappear { cancelInspection() }
    }

    @ViewBuilder
    private var inspectionResult: some View {
        switch state {
        case .idle:
            Text("Inspect the saved original to verify this frame's bytes against the analyzed capture digest.")
                .font(.caption).foregroundStyle(.secondary)
        case .loading:
            HStack { ProgressView().controlSize(.small); Text("Verifying the original and decoding the selected frame…") }
                .accessibilityIdentifier("analysis.packet.bytes.loading")
        case .cancelled:
            Text("Original packet inspection was cancelled.").font(.caption)
                .accessibilityIdentifier("analysis.packet.bytes.cancelled")
        case let .failed(detail):
            Text(detail).foregroundStyle(.red).textSelection(.enabled)
                .accessibilityIdentifier("analysis.packet.bytes.error")
        case let .completed(evidence):
            byteEvidence(evidence)
        }
    }

    private func byteEvidence(_ evidence: OriginalPacketEvidence) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Original digest verified before and after decoding · \(evidence.bytes.count) captured bytes · \(evidence.wireLength) wire bytes")
                .font(.caption).accessibilityIdentifier("analysis.packet.bytes.verified")
            HStack {
                Text("Offsets \(byteOffset)…\(min(byteOffset + 512, evidence.bytes.count)) of \(evidence.bytes.count) (end exclusive)").font(.caption.monospaced())
                    .accessibilityIdentifier("analysis.packet.bytes.offsets")
                Spacer()
                Button("Previous Bytes") { byteOffset = max(0, byteOffset - 512) }
                    .disabled(byteOffset == 0).accessibilityIdentifier("analysis.packet.bytes.previous")
                Button("Next Bytes") { byteOffset += 512 }
                    .disabled(byteOffset + 512 >= evidence.bytes.count).accessibilityIdentifier("analysis.packet.bytes.next")
            }
            ScrollView(.horizontal) {
                Text(packetHexWindow(bytes: evidence.bytes, offset: byteOffset, maximumBytes: 512))
                    .font(.caption.monospaced()).textSelection(.enabled)
                    .accessibilityIdentifier("analysis.packet.bytes.window")
                    .id(byteOffset)
            }
            if let selectedRange {
                Text("Verified \(selectedRange.field.rawValue): offsets \(selectedRange.offset)…\(selectedRange.offset + selectedRange.length) (end exclusive)")
                    .font(.caption).textSelection(.enabled).accessibilityIdentifier("analysis.packet.bytes.selected-range")
            }
            Button { verifiedRangesExpanded.toggle() } label: {
                Label("Verified field ranges (\(evidence.verifiedRanges.count))", systemImage: verifiedRangesExpanded ? "chevron.down" : "chevron.right")
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("analysis.packet.bytes.verified-ranges")
            .accessibilityValue(verifiedRangesExpanded ? "Expanded" : "Collapsed")
            if verifiedRangesExpanded {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(evidence.verifiedRanges) { range in
                            Button("\(range.field.rawValue) · offset \(range.offset) · \(range.length) bytes") {
                                selectedRange = range
                                byteOffset = (range.offset / 512) * 512
                            }
                            .buttonStyle(.borderless)
                            .accessibilityIdentifier("analysis.packet.bytes.range.\(range.id)")
                        }
                    }
                }.frame(maxHeight: 200)
                    .accessibilityIdentifier("analysis.packet.bytes.range-list")
            }
            Button { unmappedFieldsExpanded.toggle() } label: {
                Label("Fields without a verified on-wire range (\(evidence.unmappedFields.count))", systemImage: unmappedFieldsExpanded ? "chevron.down" : "chevron.right")
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("analysis.packet.bytes.unmapped-fields")
            .accessibilityValue(unmappedFieldsExpanded ? "Expanded" : "Collapsed")
            if unmappedFieldsExpanded {
                Text(evidence.unmappedFields.map(\.rawValue).joined(separator: "\n"))
                    .font(.caption.monospaced()).textSelection(.enabled)
            }
            Text("Capture-container process, PID, interface, and timestamp metadata has no on-wire range. Masked, reassembled, absent, and unavailable fields also remain unmapped; only exact original byte slices appear above.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func startInspection() {
        guard operationTask == nil else { return }
        guard let tsharkURL = resolveTShark() else {
            state = .failed("\(NativeAnalysisError.tsharkUnavailable.localizedDescription) Install Wireshark with TShark in a supported location before inspecting the original packet.")
            return
        }
        let token = UUID()
        let ownedDecoder = BoundedDecoder()
        let selectedPacket = packet
        let selectedArtifact = artifact
        let fields = supportedFields
        operationID = token
        decoder = ownedDecoder
        byteOffset = 0
        selectedRange = nil
        verifiedRangesExpanded = false
        unmappedFieldsExpanded = false
        state = .loading
        operationTask = Task {
            do {
                let evidence = try await inspectOriginalPacket(
                    packet: selectedPacket, artifact: selectedArtifact, fields: fields,
                    tsharkURL: tsharkURL, decoder: ownedDecoder,
                    limits: try OriginalPacketLimits.forCapture(at: selectedArtifact.id.sourceURL)
                )
                try Task.checkCancellation()
                guard operationID == token else { return }
                state = .completed(evidence)
            } catch is CancellationError {
                guard operationID == token else { return }
                state = .cancelled
            } catch {
                guard operationID == token else { return }
                state = .failed("Original packet inspection failed: \(error.localizedDescription) Reimport the saved original or check the installed TShark decoder before trying again.")
            }
            guard operationID == token else { return }
            operationTask = nil
            decoder = nil
            operationID = nil
        }
    }

    private func cancelInspection() {
        guard let operationTask else { return }
        operationID = nil
        state = .cancelled
        cleanupTask = stopPacketInspectorWork(task: operationTask, decoder: decoder)
        self.operationTask = nil
        decoder = nil
    }
}

private func packetHexWindow(bytes: Data, offset: Int, maximumBytes: Int) -> String {
    let end = min(offset + maximumBytes, bytes.count)
    guard offset < end else { return "No captured bytes in this window." }
    return stride(from: offset, to: end, by: 16).map { start in
        let values = bytes[start..<min(start + 16, end)]
        let hex = values.map { String(format: "%02x", $0) }.joined(separator: " ")
        let ascii = String(values.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." })
        return String(format: "%08x", start) + "  " + hex.padding(toLength: 47, withPad: " ", startingAt: 0) + "  " + ascii
    }.joined(separator: "\n")
}
