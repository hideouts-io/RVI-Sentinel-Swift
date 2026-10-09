import SwiftUI

private enum PacketBrowserMode: String, CaseIterable, Identifiable {
    case packets = "Timeline"
    case sessions = "Sessions"
    var id: String { rawValue }
}

private struct PacketBrowserRequestID: Hashable {
    let artifact: PacketArtifactID
    let text: String
    let protocolKind: ProtocolKind?
    let interfaceName: String?
    let direction: PacketDirection?
    let focusedSession: PacketSessionKey?
    let page: PacketPageRequest
    let mode: PacketBrowserMode
}

private struct PacketBrowserRequest {
    let id: PacketBrowserRequestID
    let artifact: PacketArtifactID
    let query: PacketRecordQuery
    let page: PacketPageRequest
    let mode: PacketBrowserMode
}

struct PacketBrowserView: View {
    let result: PacketAnalysisResult
    let supportedFields: Set<TSharkField>
    let interfaceNames: [String]
    let names: [PacketRecordID: [CapturedHostnameAssociation]]
    @State private var mode = PacketBrowserMode.packets
    @State private var search = ""
    @State private var protocolKind: ProtocolKind?
    @State private var interfaceName: String?
    @State private var direction: PacketDirection?
    @State private var offset = 0
    @State private var rows: [PacketRecord] = []
    @State private var sessions: [PacketSession] = []
    @State private var matchingCount = 0
    @State private var nextOffset: Int?
    @State private var selectedPacketID: PacketRecordID?
    @State private var selectedPacket: PacketRecord?
    @State private var selectedSessionID: PacketSessionKey?
    @State private var selectedSession: PacketSession?
    @State private var focusedSessionID: PacketSessionKey?
    @State private var focusedIDs: Set<PacketRecordID>?
    @State private var savedOffset = 0
    @State private var isLoading = false
    @State private var error: String?

    private var request: PacketBrowserRequest {
        let query = focusedIDs.map { PacketRecordQuery(text: "", transport: nil, protocolKind: nil, interfaceName: nil, processID: nil, direction: nil, recordIDs: $0) }
            ?? PacketRecordQuery(text: search, transport: nil, protocolKind: protocolKind, interfaceName: interfaceName, processID: nil, direction: direction, recordIDs: nil)
        let id = PacketBrowserRequestID(artifact: result.artifact.id, text: query.text, protocolKind: query.protocolKind, interfaceName: query.interfaceName, direction: query.direction, focusedSession: focusedSessionID, page: PacketPageRequest(offset: offset, limit: 100), mode: mode)
        return PacketBrowserRequest(id: id, artifact: result.artifact.id, query: query, page: PacketPageRequest(offset: offset, limit: 100), mode: mode)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Picker("Browse", selection: Binding(get: { mode }, set: { mode = $0; offset = 0 })) {
                    ForEach(PacketBrowserMode.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).frame(maxWidth: 250).disabled(focusedIDs != nil)
                    .accessibilityIdentifier("analysis.packet.mode")
                Text(packetOriginLabel(result.artifact.source)).font(.caption).foregroundStyle(.secondary)
                Spacer()
                if focusedIDs != nil {
                    Button("Return to Session") { returnToSession() }.accessibilityIdentifier("analysis.timeline.return-session")
                    Button("Show All Packets") { showAllPackets() }.accessibilityIdentifier("analysis.timeline.show-all")
                }
            }
            if focusedIDs == nil { filters }
            else { Text("Focused session: every member packet is available. Search and filters are suspended.").font(.caption).foregroundStyle(.secondary) }
            HSplitView {
                VStack(alignment: .leading, spacing: 8) {
                    if mode == .packets { packetTable } else { sessionTable }
                    paging
                }.frame(minWidth: 420)
                if let packet = selectedPacket, mode == .packets {
                    PacketInspectorView(packet: packet, artifact: result.artifact, supportedFields: supportedFields, capturedNames: names[packet.id] ?? [], returnToSession: focusedIDs == nil ? nil : { returnToSession() })
                        .id(packet.id).frame(minWidth: 330, idealWidth: 400, maxWidth: 540)
                } else if let session = selectedSession, mode == .sessions {
                    PacketSessionInspectorView(session: session, origin: result.artifact.source, showPackets: { focus(session) })
                        .frame(minWidth: 300, idealWidth: 350, maxWidth: 480)
                }
            }
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            Text("\(result.coverage.ungroupedPackets.formatted()) packets remain outside sessions. Recorded process labels describe capture metadata.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityIdentifier("analysis.packet.browser")
        .task(id: request.id) { await load(request) }
        .onChange(of: search) { _, _ in offset = 0 }
        .onChange(of: protocolKind) { _, _ in offset = 0 }
        .onChange(of: interfaceName) { _, _ in offset = 0 }
        .onChange(of: direction) { _, _ in offset = 0 }
        .onChange(of: selectedPacketID) { _, id in if id == nil { selectedPacket = nil } else if let record = rows.first(where: { $0.id == id }) { selectedPacket = record } }
        .onChange(of: selectedSessionID) { _, id in if id == nil { selectedSession = nil } else if let session = sessions.first(where: { $0.id == id }) { selectedSession = session } }
    }

    private var filters: some View {
        HStack {
            TextField("Search process, PID, protocol, endpoint, or hostname", text: $search)
                .textFieldStyle(.roundedBorder).accessibilityIdentifier("analysis.packet.search")
            Picker("Protocol", selection: $protocolKind) {
                Text("All protocols").tag(Optional<ProtocolKind>.none)
                ForEach(ProtocolKind.allCases) { Text($0.rawValue).tag(Optional($0)) }
            }.frame(maxWidth: 175).accessibilityIdentifier("analysis.packet.protocol-filter")
            Picker("Interface", selection: $interfaceName) {
                Text("All interfaces").tag(Optional<String>.none)
                ForEach(interfaceNames, id: \.self) { Text($0).tag(Optional($0)) }
            }.frame(maxWidth: 160).accessibilityIdentifier("analysis.packet.interface-filter")
            Picker("Direction", selection: $direction) {
                Text("All directions").tag(Optional<PacketDirection>.none)
                Text("Inbound").tag(Optional(PacketDirection.inbound))
                Text("Outbound").tag(Optional(PacketDirection.outbound))
                Text("Unknown").tag(Optional(PacketDirection.unknown))
            }.frame(maxWidth: 170).accessibilityIdentifier("analysis.packet.direction-filter")
        }
    }

    private var packetTable: some View {
        Table(rows, selection: $selectedPacketID) {
            TableColumn("Frame") { Text(String($0.id.frameNumber)).monospacedDigit() }.width(55)
            TableColumn("Capture epoch") { Text($0.timestamp.originalText).font(.caption.monospaced()).textSelection(.enabled) }.width(min: 170, ideal: 190)
            TableColumn("Protocol") { Text($0.protocolStack.last?.uppercased() ?? "Unknown") }.width(85)
            TableColumn("Recorded process") { Text(packetProcessLabel($0.process)).font(.caption) }.width(min: 130, ideal: 160)
            TableColumn("Source → destination") { Text("\(packetEndpointLabel(address: $0.sourceAddress, port: $0.sourcePort)) → \(packetEndpointLabel(address: $0.destinationAddress, port: $0.destinationPort))").font(.caption.monospaced()) }.width(min: 180, ideal: 290)
        }.accessibilityIdentifier("analysis.packet.table")
    }

    private var sessionTable: some View {
        Table(sessions, selection: $selectedSessionID) {
            TableColumn("Stream") { Text("\($0.transport.rawValue) \($0.stream)") }.width(90)
            TableColumn("Endpoints") { Text("\(packetEndpointLabel(address: $0.firstEndpoint.address, port: $0.firstEndpoint.port)) ↔ \(packetEndpointLabel(address: $0.secondEndpoint.address, port: $0.secondEndpoint.port))").font(.caption.monospaced()) }.width(min: 210, ideal: 320)
            TableColumn("Packets") { Text($0.packetCount.formatted()).monospacedDigit() }.width(70)
            TableColumn("Recorded process") { Text(packetProcessLabel($0.process)).font(.caption) }.width(min: 140, ideal: 180)
        }.accessibilityIdentifier("analysis.session.table")
    }

    private var paging: some View {
        HStack {
            if isLoading { ProgressView().controlSize(.small) }
            Text("\(mode == .packets ? rows.count : sessions.count) shown · \(matchingCount.formatted()) matching · \(mode == .packets ? result.records.count : result.sessions.count) total")
                .font(.caption).accessibilityIdentifier("analysis.packet.count")
            Spacer()
            Button("Previous") { offset = max(0, offset - 100) }.disabled(offset == 0 || isLoading).accessibilityIdentifier("analysis.packet.previous")
            Button("Next") { if let nextOffset { offset = nextOffset } }.disabled(nextOffset == nil || isLoading).accessibilityIdentifier("analysis.packet.next")
        }
    }

    private func load(_ request: PacketBrowserRequest) async {
        isLoading = true
        error = nil
        let data = result
        let names = names
        do {
            if request.mode == .packets {
                let task = Task.detached(priority: .userInitiated) { try pagePacketRecords(result: data, query: request.query, names: names, page: request.page) }
                let page = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
                try Task.checkCancellation()
                rows = page.records; matchingCount = page.matchingCount; nextOffset = page.nextOffset
            } else {
                let task = Task.detached(priority: .userInitiated) { try pagePacketSessions(result: data, query: request.query, names: names, page: request.page) }
                let page = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
                try Task.checkCancellation()
                sessions = page.sessions; matchingCount = page.matchingCount; nextOffset = page.nextOffset
            }
            isLoading = false
        } catch is CancellationError {
            // The replacement request owns loading state; stale results are never applied.
        } catch {
            guard !Task.isCancelled else { return }
            self.error = error.localizedDescription
            isLoading = false
        }
    }

    private func focus(_ session: PacketSession) {
        savedOffset = offset
        selectedSession = session
        focusedSessionID = session.id
        focusedIDs = Set(session.packetIDs)
        selectedPacketID = nil
        selectedPacket = nil
        offset = 0
        mode = .packets
    }

    private func returnToSession() {
        focusedSessionID = nil
        focusedIDs = nil
        selectedPacketID = nil
        selectedPacket = nil
        mode = .sessions
        offset = savedOffset
    }

    private func showAllPackets() {
        focusedSessionID = nil
        focusedIDs = nil
        selectedPacketID = nil
        selectedPacket = nil
        offset = 0
    }
}
