import AppKit
import SwiftUI

struct PacketInspectorView: View {
    let packet: PacketRecord
    let artifact: PacketCaptureArtifact
    let supportedFields: Set<TSharkField>
    let capturedNames: [CapturedHostnameAssociation]
    let returnToSession: (() -> Void)?
    @State private var captureActionError: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Packet \(packet.id.frameNumber)").font(.title2.bold())
                    Spacer()
                    if let returnToSession {
                        Button("Return to Session", action: returnToSession)
                            .accessibilityIdentifier("analysis.packet.return-session")
                    }
                }
                observationDetails
                recordedMetadata
                captureDetails
                capturedHostnameDetails
                GroupBox("Current reverse DNS") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("An explicit lookup sends the selected address to the Mac's configured resolver. Its present-day answer is separate from captured hostname evidence.")
                            .font(.caption).foregroundStyle(.secondary)
                        PacketCurrentLookupView(
                            packetID: packet.id, address: packet.sourceAddress, title: "Source",
                            lookupIdentifier: "analysis.packet.lookup-source", cancelIdentifier: "analysis.packet.cancel-lookup-source"
                        )
                        Divider()
                        PacketCurrentLookupView(
                            packetID: packet.id, address: packet.destinationAddress, title: "Destination",
                            lookupIdentifier: "analysis.packet.lookup-destination", cancelIdentifier: "analysis.packet.cancel-lookup-destination"
                        )
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                PacketRawBytesView(packet: packet, artifact: artifact, supportedFields: supportedFields)
            }.padding()
        }
        .accessibilityIdentifier("analysis.packet.inspector")
        .onChange(of: packet.id) { _, _ in captureActionError = nil }
    }

    private var observationDetails: some View {
        GroupBox("Directly observed packet") {
            VStack(alignment: .leading, spacing: 8) {
                inspectorValue("Decoded capture epoch seconds", packet.timestamp.originalText, "analysis.packet.timestamp-epoch")
                inspectorValue("Local display time", inspectorLocalTime(packet.timestamp), "analysis.packet.timestamp-local")
                Text("Decoded epoch representation: \(packet.timestamp.decimalDigits) fractional digits. Container timestamp resolution is not established here. Local display rounds to milliseconds; no time offset is applied.")
                    .font(.caption).foregroundStyle(.secondary)
                inspectorValue("Record", String(packet.id.frameNumber), "analysis.packet.record")
                inspectorValue("Source endpoint", inspectorEndpoint(packet.sourceAddress, packet.sourcePort), "analysis.packet.source")
                inspectorValue("Destination endpoint", inspectorEndpoint(packet.destinationAddress, packet.destinationPort), "analysis.packet.destination")
                inspectorValue("Protocol stack", packet.protocolStack.joined(separator: " → "), "analysis.packet.protocol-stack")
                inspectorValue("Wire length", "\(packet.wireLength) bytes", "analysis.packet.wire-length")
                inspectorValue("Captured length", optionalField(packet.capturedLength.map { "\($0) bytes" }, .frameCapturedLength), "analysis.packet.captured-length")
                if packet.protocolStack.contains("tcp") {
                    inspectorValue("Raw TCP sequence", optionalField(packet.tcp?.sequenceRaw.map(String.init), .tcpSequenceRaw), "analysis.packet.tcp-sequence")
                    inspectorValue("Raw TCP acknowledgment", optionalField(packet.tcp?.acknowledgmentRaw.map(String.init), .tcpAcknowledgmentRaw), "analysis.packet.tcp-acknowledgment")
                    inspectorValue("TCP flags", optionalField(packet.tcp?.flags.map { String(format: "0x%04x", $0) }, .tcpFlags), "analysis.packet.tcp-flags")
                    inspectorValue("TCP SYN / ACK", packet.tcp.map { "\($0.isSYN.map(String.init) ?? "Unknown") / \($0.isACK.map(String.init) ?? "Unknown")" } ?? "Unknown", "analysis.packet.tcp-syn-ack")
                    inspectorValue("TCP payload length", optionalField(packet.tcp?.payloadLength.map { "\($0) bytes" }, .tcpPayloadLength), "analysis.packet.tcp-payload-length")
                }
                if let transport = packet.transport {
                    inspectorValue("\(transport.rawValue) stream", optionalField(packet.stream.map(String.init), transport == .tcp ? .tcpStream : .udpStream), "analysis.packet.stream")
                }
                if !packet.diagnostics.isEmpty {
                    Text("Decoder diagnostics: \(packet.diagnostics.map(\.rawValue).joined(separator: ", "))")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
        }
    }

    private var recordedMetadata: some View {
        GroupBox("Recorded capture metadata") {
            VStack(alignment: .leading, spacing: 8) {
                processLabels(
                    title: "Process", metadata: packet.process,
                    nameFields: [.darwinProcessName, .pktapProcessName], idFields: [.darwinProcessID, .pktapProcessID],
                    nameIdentifier: "analysis.packet.process", idIdentifier: "analysis.packet.pid"
                )
                processLabels(
                    title: "Effective process", metadata: packet.effectiveProcess,
                    nameFields: [.darwinEffectiveProcessName, .pktapEffectiveProcessName], idFields: [.darwinEffectiveProcessID, .pktapEffectiveProcessID],
                    nameIdentifier: "analysis.packet.effective-process", idIdentifier: "analysis.packet.effective-pid"
                )
                inspectorValue("Interface", metadataValue(packet.interface.name, packet.interface.state, [.frameInterfaceName, .pktapInterfaceName]), "analysis.packet.interface")
                ForEach(Array(packet.interface.labels.enumerated()), id: \.offset) { _, label in
                    Text("\(inspectorMetadataSource(label.source)): \(label.name)").font(.caption).textSelection(.enabled)
                }
                inspectorValue("Direction", metadataValue(packet.direction.direction == .unknown ? nil : packet.direction.direction.rawValue, packet.direction.state, [.framePacketDirection, .pktapFlags]), "analysis.packet.direction")
                ForEach(Array(packet.direction.labels.enumerated()), id: \.offset) { _, label in
                    Text("\(inspectorMetadataSource(label.source)): \(label.direction.rawValue)").font(.caption)
                }
                Text("Process labels and PIDs are recorded metadata from this artifact. They do not independently verify device process identity or process lifetime. Missing labels remain unknown.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
        }
    }

    @ViewBuilder
    private func processLabels(
        title: String, metadata: PacketProcessMetadata, nameFields: Set<TSharkField>, idFields: Set<TSharkField>,
        nameIdentifier: String, idIdentifier: String
    ) -> some View {
        inspectorValue(title, metadataValue(metadata.name, metadata.state, nameFields), nameIdentifier)
        inspectorValue("\(title) PID", metadataValue(metadata.processID.map(String.init), metadata.state, idFields), idIdentifier)
        ForEach(Array(metadata.labels.enumerated()), id: \.offset) { _, label in
            Text("\(inspectorMetadataSource(label.source)): \(label.name ?? "Unknown name") · PID \(label.processID.map(String.init) ?? "Unknown")")
                .font(.caption).textSelection(.enabled)
        }
    }

    private var captureDetails: some View {
        GroupBox("Original capture") {
            VStack(alignment: .leading, spacing: 8) {
                inspectorValue("Artifact", artifact.id.sourceURL.path, "analysis.packet.artifact")
                inspectorValue("Source provenance", inspectorArtifactSource(artifact.source), "analysis.packet.source-provenance")
                inspectorValue("Integrity", inspectorIntegrity(artifact.integrity), "analysis.packet.integrity")
                inspectorValue("SHA-256 at analysis", artifact.id.sha256, "analysis.packet.sha256")
                HStack {
                    Button("Reveal Original Capture") { revealCapture() }
                        .accessibilityIdentifier("analysis.packet.reveal-capture")
                    Button("Open Original Capture") { openCapture() }
                        .accessibilityIdentifier("analysis.packet.open-capture")
                }
                if let captureActionError {
                    Text(captureActionError).foregroundStyle(.red).textSelection(.enabled)
                        .accessibilityIdentifier("analysis.packet.capture-error")
                }
                Text("The digest identifies the bytes analyzed. Opening or revealing a file does not reverify its current bytes; original packet inspection verifies the digest before and after decoding.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
        }
    }

    private var capturedHostnameDetails: some View {
        GroupBox("Captured hostname evidence") {
            VStack(alignment: .leading, spacing: 8) {
                if packet.recordedNames.isEmpty && capturedNames.isEmpty {
                    Text("No captured hostname established for this packet.").foregroundStyle(.secondary)
                }
                ForEach(Array(packet.recordedNames.enumerated()), id: \.offset) { _, name in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(name.value).font(.headline).textSelection(.enabled)
                        Text("Direct frame observation · \(name.field.rawValue) · frame \(packet.id.frameNumber)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if !packet.recordedNames.isEmpty {
                    Text("A recorded name belongs to this frame. A DNS question alone does not establish an address association.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(Array(capturedNames.enumerated()), id: \.offset) { _, association in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(association.address.map { "\(association.name) · \($0)" } ?? association.name).font(.headline).textSelection(.enabled)
                        Text("\(association.provenance.rawValue) · \(association.isInferred ? "Inferred packet association" : "Recorded association")")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("Supporting frames: \(association.supportingPackets.map { String($0.frameNumber) }.joined(separator: ", "))")
                            .font(.caption).textSelection(.enabled)
                        Text(association.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        if let validUntil = association.validUntil {
                            Text("Captured association validity ends at epoch \(validUntil.originalText) (\(inspectorLocalTime(validUntil))).")
                                .font(.caption).textSelection(.enabled)
                        }
                        if association.canonicalNameChain.count > 1 {
                            Text("CNAME chain: \(association.canonicalNameChain.joined(separator: " → "))")
                                .font(.caption).textSelection(.enabled)
                        }
                    }
                }
                Text("Encrypted traffic or a capture beginning after a handshake can leave names unavailable. No current resolver lookup runs automatically.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
        }
    }

    private func optionalField(_ value: String?, _ field: TSharkField) -> String {
        guard supportedFields.contains(field) else { return "Unsupported by installed decoder (\(field.rawValue))" }
        return value ?? "Not recorded in this frame"
    }

    private func metadataValue(_ value: String?, _ state: PacketMetadataState, _ fields: Set<TSharkField>) -> String {
        if state == .conflict { return "Conflicting recorded labels; see sources below" }
        if let value { return value }
        return supportedFields.isDisjoint(with: fields) ? "Unsupported by installed decoder" : "Unknown; not recorded in this frame"
    }

    private func revealCapture() {
        let url = artifact.id.sourceURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            captureActionError = "Original capture is unavailable at \(url.path). Restore it or reimport its current location."
            return
        }
        captureActionError = nil
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    private func openCapture() {
        let url = artifact.id.sourceURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            captureActionError = "Original capture is unavailable at \(url.path). Restore it or reimport its current location."
            return
        }
        captureActionError = NSWorkspace.shared.open(url) ? nil : "No application could open the original capture. Install or choose a packet viewer, then try again."
    }
}

private func inspectorValue(_ title: String, _ value: String, _ identifier: String) -> some View {
    LabeledContent(title) { Text(value).font(.body.monospaced()).textSelection(.enabled) }
        .accessibilityIdentifier(identifier)
}

private func inspectorEndpoint(_ address: PacketIPAddress?, _ port: UInt16?) -> String {
    guard let address else { return "Unknown; IP header is absent or ambiguous" }
    let ip = address.family == .ipv6 ? "[\(address.rawValue)]" : address.rawValue
    return port.map { "\(ip):\($0)" } ?? "\(ip) · port not recorded"
}

func inspectorLocalTime(_ timestamp: PacketTimestamp) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = .current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS zzz"
    return formatter.string(from: timestamp.displayDate)
}

private func inspectorMetadataSource(_ source: PacketMetadataSource) -> String {
    switch source {
    case .applePCAPNG: "Apple PCAPNG metadata"
    case .pktapHeader: "PKTAP header in this artifact"
    case .captureFrame: "Capture interface metadata"
    case .pcapngPacketOptions: "PCAPNG packet options"
    }
}

private func inspectorArtifactSource(_ source: PacketSourceProvenance) -> String {
    switch source {
    case .liveDeviceRVI: "Guided device RVI capture"
    case .userDeclaredRVI: "User-declared RVI import"
    case .unknown: "Unestablished capture origin"
    }
}

private func inspectorIntegrity(_ integrity: PacketIntegrityState) -> String {
    switch integrity {
    case .pending: "Pending"
    case .verified: "Verified at analysis"
    case let .failed(detail): "Failed: \(detail)"
    }
}

/// Stops only work started by this inspector; awaiting its task also waits for cleanup.
func stopPacketInspectorWork(task: Task<Void, Never>?, decoder: BoundedDecoder?) -> Task<Void, Never> {
    task?.cancel()
    return Task {
        if let decoder { await decoder.cancel() }
        if let task { await task.value }
    }
}
