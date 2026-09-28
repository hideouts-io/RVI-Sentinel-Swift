import Foundation

struct DiagnosticApplication: Codable, Equatable, Sendable {
    let name: String
    let version: String
    let build: String
    let operatingSystem: String
    let architecture: String
}

struct DiagnosticSetupCheck: Codable, Equatable, Sendable {
    let identifier: SetupCheckIdentifier
    let state: CheckState
    let detail: String
    let correctiveAction: String
    let evidenceSource: String
}

struct DiagnosticInterface: Codable, Equatable, Sendable {
    let name: String
    let friendlyType: String
    let isUp: Bool
    let owner: InterfaceOwner
    let evidenceSource: String
}

struct DiagnosticWorkflow: Codable, Equatable, Sendable {
    let capturePhase: String
    let captureRunning: Bool
    let validatedCaptureAvailable: Bool
    let analysisRunning: Bool
    let analysisResultAvailable: Bool
    let baselineSelected: Bool
    let localExportCount: Int
}

struct RedactedDiagnostics: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let generatedAt: Date
    let application: DiagnosticApplication
    let visiblePhysicalDeviceCount: Int
    let captureReadyDeviceCount: Int
    let setupChecks: [DiagnosticSetupCheck]
    let interfaces: [DiagnosticInterface]
    let workflow: DiagnosticWorkflow
    let recentError: String?
    let exclusions: [String]
}

struct DiagnosticsInput: Sendable {
    let generatedAt: Date
    let application: DiagnosticApplication
    let devices: [DeviceInfo]
    let setupChecks: [SetupCheck]
    let interfaces: [NetworkInterfaceInfo]
    let capturePhase: CapturePhase
    let captureRunning: Bool
    let validatedCaptureAvailable: Bool
    let analysisRunning: Bool
    let analysisResultAvailable: Bool
    let baselineSelected: Bool
    let localExportCount: Int
    let recentError: String?
    let sensitiveValues: [String]
}

enum DiagnosticsError: LocalizedError {
    case encodingFailed(String)
    case clipboardWriteFailed
    case exportFailed(path: String, reason: String)

    var errorDescription: String? {
        switch self {
        case let .encodingFailed(reason):
            "Could not encode the redacted diagnostics document: \(reason)"
        case .clipboardWriteFailed:
            "macOS did not accept the redacted diagnostics text on the clipboard. Try Save Diagnostics instead."
        case let .exportFailed(path, reason):
            "Could not save redacted diagnostics to \(path): \(reason)"
        }
    }
}

func makeRedactedDiagnostics(input: DiagnosticsInput) -> RedactedDiagnostics {
    let checks = input.setupChecks.map { check in
        DiagnosticSetupCheck(
            identifier: check.identifier,
            state: check.state,
            detail: redactSensitiveText(check.detail, sensitiveValues: input.sensitiveValues),
            correctiveAction: redactSensitiveText(check.correctiveAction, sensitiveValues: input.sensitiveValues),
            evidenceSource: redactSensitiveText(check.evidenceSource, sensitiveValues: input.sensitiveValues)
        )
    }
    let diagnosticInterfaces = input.interfaces.map { interface in
        DiagnosticInterface(
            name: interface.name,
            friendlyType: interface.friendlyType,
            isUp: interface.isUp,
            owner: interface.owner,
            evidenceSource: interface.evidenceSource
        )
    }
    return RedactedDiagnostics(
        schemaVersion: 1,
        generatedAt: input.generatedAt,
        application: input.application,
        visiblePhysicalDeviceCount: input.devices.count,
        captureReadyDeviceCount: input.devices.filter { $0.readiness == .ready }.count,
        setupChecks: checks,
        interfaces: diagnosticInterfaces,
        workflow: DiagnosticWorkflow(
            capturePhase: input.capturePhase.rawValue,
            captureRunning: input.captureRunning,
            validatedCaptureAvailable: input.validatedCaptureAvailable,
            analysisRunning: input.analysisRunning,
            analysisResultAvailable: input.analysisResultAvailable,
            baselineSelected: input.baselineSelected,
            localExportCount: input.localExportCount
        ),
        recentError: input.recentError.map { redactSensitiveText($0, sensitiveValues: input.sensitiveValues) },
        exclusions: [
            "Device names and identifiers",
            "Capture and report paths",
            "Packet contents, addresses, hostnames, and flow records",
            "MAC addresses and interface addresses",
            "Authorization data and credentials"
        ]
    )
}

func encodeRedactedDiagnostics(_ diagnostics: RedactedDiagnostics) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    do {
        let data = try encoder.encode(diagnostics)
        guard let value = String(data: data, encoding: .utf8) else {
            throw DiagnosticsError.encodingFailed("JSONEncoder returned non-UTF-8 data.")
        }
        return value
    } catch let error as DiagnosticsError {
        throw error
    } catch {
        throw DiagnosticsError.encodingFailed(error.localizedDescription)
    }
}

func redactSensitiveText(_ text: String, sensitiveValues: [String]) -> String {
    let explicit = sensitiveValues
        .filter { !$0.isEmpty }
        .sorted { $0.count > $1.count }
        .reduce(text) { result, value in
            result.replacingOccurrences(of: value, with: "<REDACTED>")
        }
    let patterns: [(String, String)] = [
        (#"/Users/[^\s\"']+(?:/[^\s\"']+)*"#, "<PRIVATE_PATH>"),
        (#"/(?:private/)?var/folders/[^\s\"']+"#, "<PRIVATE_PATH>"),
        (#"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b"#, "<DEVICE_IDENTIFIER>"),
        (#"\b[0-9A-Fa-f]{32,40}\b"#, "<DEVICE_IDENTIFIER>"),
        (#"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"#, "<MAC_ADDRESS>"),
        (#"\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}\b"#, "<IP_ADDRESS>"),
        (#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|arpa|com|net|org|io|app|dev|cloud)\b"#, "<HOSTNAME>")
    ]
    return patterns.reduce(explicit) { result, entry in
        result.replacingOccurrences(of: entry.0, with: entry.1, options: .regularExpression)
    }
}

func currentArchitectureName() -> String {
#if arch(arm64)
    return "arm64"
#elseif arch(x86_64)
    return "x86_64"
#else
    return "unsupported architecture"
#endif
}
