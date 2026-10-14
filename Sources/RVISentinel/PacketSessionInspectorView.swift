import SwiftUI

struct PacketSessionInspectorView: View {
    let session: PacketSession
    let origin: PacketSourceProvenance
    let showPackets: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("\(session.transport.rawValue) stream \(session.stream)").font(.title2.bold())
                Text(packetOriginLabel(origin)).foregroundStyle(.secondary)
                Text("\(packetEndpointLabel(address: session.firstEndpoint.address, port: session.firstEndpoint.port)) ↔ \(packetEndpointLabel(address: session.secondEndpoint.address, port: session.secondEndpoint.port))")
                    .font(.body.monospaced()).textSelection(.enabled)
                GroupBox("Observed packet group") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("First observed: \(session.firstTimestamp.originalText)")
                        Text("Last observed: \(session.lastTimestamp.originalText)")
                        Text("\(session.packetCount.formatted()) packets · \(session.wireBytes.formatted()) wire bytes")
                        Text("Interface: \(session.interface.name ?? "Unknown")")
                        Text("Recorded process: \(packetProcessLabel(session.process))")
                        Text("Effective process: \(packetProcessLabel(session.effectiveProcess))")
                    }.font(.caption.monospaced()).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled).padding(.vertical, 6)
                }
                Text("This group is confined to one capture, stream, interface, and recorded process context. Labels do not verify process identity or establish a process lifetime.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("View All Session Packets", action: showPackets).buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("analysis.session.show-packets")
            }.padding()
        }.accessibilityIdentifier("analysis.session.inspector")
    }
}
