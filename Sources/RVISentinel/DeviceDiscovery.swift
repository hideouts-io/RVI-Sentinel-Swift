import Foundation

enum DeviceDiscoveryError: LocalizedError {
    case commandFailed(exitCode: Int32, detail: String)
    case malformedOutput(String)

    var errorDescription: String? {
        switch self {
        case let .commandFailed(exitCode, detail):
            "Apple device discovery failed with exit code \(exitCode): \(detail)"
        case let .malformedOutput(detail):
            "Apple device discovery returned unexpected data: \(detail)"
        }
    }
}

private struct DeviceControlEnvelope: Decodable {
    let info: DeviceControlInfo
    let result: DeviceControlResult
}

private struct DeviceControlInfo: Decodable {
    let outcome: String
}

private struct DeviceControlResult: Decodable {
    let devices: [DeviceControlDevice]
}

private struct DeviceControlDevice: Decodable {
    let visibilityClass: String
    let deviceProperties: DeviceControlProperties
    let hardwareProperties: DeviceControlHardware
    let connectionProperties: DeviceControlConnection
}

private struct DeviceControlProperties: Decodable {
    let name: String
    let osVersionNumber: String
    let bootState: String?
    let bootedFromSnapshot: Bool?
}

private struct DeviceControlHardware: Decodable {
    let reality: String
    let platform: String
    let udid: String
    let marketingName: String
    let productType: String
}

private struct DeviceControlConnection: Decodable {
    let pairingState: String
    let transportType: String?
}

struct DeviceDiscoveryService: Sendable {
    let processRunner: ProcessRunner

    func discover() async throws -> [DeviceInfo] {
        let temporaryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rvi-sentinel-devices-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: temporaryURL) }
        let result = try await processRunner.run(
            executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["devicectl", "list", "devices", "--json-output", temporaryURL.path]
        )
        guard result.exitCode == 0 else {
            let detail = result.standardError.isEmpty ? result.standardOutput : result.standardError
            throw DeviceDiscoveryError.commandFailed(exitCode: result.exitCode, detail: detail.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let data = try Data(contentsOf: temporaryURL)
        return try parseDeviceControlOutput(data: data)
    }
}

func parseDeviceControlOutput(data: Data) throws -> [DeviceInfo] {
    let envelope: DeviceControlEnvelope
    do {
        envelope = try JSONDecoder().decode(DeviceControlEnvelope.self, from: data)
    } catch {
        throw DeviceDiscoveryError.malformedOutput(error.localizedDescription)
    }
    guard envelope.info.outcome == "success" else {
        throw DeviceDiscoveryError.malformedOutput("outcome was \(envelope.info.outcome)")
    }
    return envelope.result.devices.compactMap(deviceInfo(from:))
}

private func deviceInfo(from value: DeviceControlDevice) -> DeviceInfo? {
    guard value.hardwareProperties.reality == "physical",
          value.hardwareProperties.platform == "iOS" else {
        return nil
    }
    let bootState = normalizedBootState(properties: value.deviceProperties)
    let transport = value.connectionProperties.transportType ?? "unavailable"
    let isReady = bootState == "booted"
        && value.connectionProperties.pairingState == "paired"
        && transport == "wired"
        && value.visibilityClass == "default"
    return DeviceInfo(
        name: value.deviceProperties.name,
        identifier: value.hardwareProperties.udid,
        model: "\(value.hardwareProperties.marketingName) (\(value.hardwareProperties.productType))",
        operatingSystem: "iOS \(value.deviceProperties.osVersionNumber)",
        transport: transport,
        pairingState: value.connectionProperties.pairingState,
        bootState: bootState,
        readiness: isReady ? .ready : .unavailable,
        status: readinessDescription(
            bootState: bootState,
            pairingState: value.connectionProperties.pairingState,
            transport: transport,
            visibility: value.visibilityClass
        )
    )
}

private func normalizedBootState(properties: DeviceControlProperties) -> String {
    if let bootState = properties.bootState {
        return bootState
    }
    if properties.bootedFromSnapshot == true {
        return "booted"
    }
    return "unknown"
}

func readinessDescription(
    bootState: String,
    pairingState: String,
    transport: String,
    visibility: String
) -> String {
    var reasons: [String] = []
    if pairingState != "paired" { reasons.append("not paired") }
    if transport != "wired" { reasons.append("not connected by USB") }
    if bootState != "booted" { reasons.append("not booted") }
    if visibility != "default" { reasons.append("not currently available") }
    return reasons.isEmpty ? "Ready — paired over USB" : "Not ready — \(reasons.joined(separator: ", "))"
}
