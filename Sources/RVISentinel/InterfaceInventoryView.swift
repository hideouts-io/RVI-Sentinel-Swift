import SwiftUI

struct InterfaceInventoryView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(title: "Interfaces", subtitle: "Inventory host-visible interfaces without implying hidden iOS routing", symbol: "network")
            HStack {
                Text("Every row identifies its evidence source and ownership boundary.")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") { appState.refreshInterfaces() }
            }
            if appState.interfaces.isEmpty {
                ContentUnavailableView("No interface inventory loaded", systemImage: "network.slash", description: Text("Choose Refresh to enumerate interfaces visible to this Mac."))
            } else {
                Table(appState.interfaces) {
                    TableColumn("Interface") { item in
                        VStack(alignment: .leading) {
                            Text(item.name).font(.body.monospaced().bold())
                            Text(item.friendlyType).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 140, ideal: 180)
                    TableColumn("State") { item in
                        Label(item.isUp ? "Up" : "Down", systemImage: item.isUp ? "checkmark.circle.fill" : "minus.circle")
                            .foregroundStyle(item.isUp ? .green : .secondary)
                    }
                    .width(75)
                    TableColumn("Addresses") { item in
                        VStack(alignment: .leading) {
                            ForEach(item.ipv4Addresses, id: \.self) { Text($0).font(.caption.monospaced()) }
                            ForEach(item.ipv6Addresses, id: \.self) { Text($0).font(.caption.monospaced()).lineLimit(1) }
                        }
                    }
                    TableColumn("Owner") { item in
                        VStack(alignment: .leading) {
                            Text(item.owner.rawValue)
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
            Text("These are interfaces visible to macOS. An RVI packet does not by itself prove whether the iPhone used Wi-Fi, cellular data, or an internal VPN tunnel.")
                .font(.callout)
                .padding()
                .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        }
        .padding(28)
        .navigationTitle("Interfaces")
        .onAppear {
            if appState.interfaces.isEmpty { appState.refreshInterfaces() }
        }
    }
}
