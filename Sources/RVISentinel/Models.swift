import Foundation

enum NavigationSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case setup = "Check Setup"
    case devices = "Device & Capture"
    case interfaces = "Interfaces"
    case analysis = "Analysis"
    case baselines = "Baselines"
    case exports = "Exports"

    var id: String { rawValue }

    var symbolName: String {
        switch self {
        case .overview: "house"
        case .setup: "checkmark.shield"
        case .devices: "iphone.gen3"
        case .interfaces: "network"
        case .analysis: "waveform.path.ecg.rectangle"
        case .baselines: "square.stack.3d.up"
        case .exports: "square.and.arrow.up"
        }
    }
}

enum CheckState: String, Codable {
    case passed = "PASS"
    case failed = "FAIL"
    case warning = "CHECK"
    case pending = "PENDING"
}

enum SetupCheckIdentifier: String, CaseIterable, Codable, Identifiable {
    case device
    case usb
    case trust
    case developerSupport
    case rvictl
    case rpmuxd
    case tcpdump
    case analysisBackend
    case outputFolder
    case diskSpace
    case macOSComponents
    case cleanupState

    var id: String { rawValue }
}

struct SetupCheck: Identifiable, Equatable {
    let identifier: SetupCheckIdentifier
    let title: String
    let state: CheckState
    let detail: String
    let correctiveAction: String
    let evidenceSource: String

    var id: SetupCheckIdentifier { identifier }
}

enum DeviceReadiness: String, Codable {
    case ready
    case unavailable
}

struct DeviceInfo: Identifiable, Codable, Equatable, Sendable {
    let name: String
    let identifier: String
    let model: String
    let operatingSystem: String
    let transport: String
    let pairingState: String
    let bootState: String
    let readiness: DeviceReadiness
    let status: String

    var id: String { identifier }
}

enum InterfaceOwner: String, Codable {
    case mac = "Mac"
    case remoteVirtualInterface = "RVI connection"
    case vpn = "VPN or tunnel"
    case unknown = "Unclassified host interface"
}

struct NetworkInterfaceInfo: Identifiable, Equatable, Sendable {
    let name: String
    let friendlyType: String
    let isUp: Bool
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]
    let macAddress: String?
    let mtu: Int?
    let flags: [String]
    let linkType: String
    let associatedService: String
    let owner: InterfaceOwner
    let isSelectable: Bool
    let evidenceSource: String

    var id: String { name }
}

enum EvidenceProvenance: String, Codable, CaseIterable, Sendable {
    case capturedDNSQuery = "Captured DNS query"
    case capturedDNSAnswer = "Captured DNS answer"
    case capturedMDNS = "Captured mDNS"
    case capturedDNSSD = "Captured DNS-SD"
    case tlsSNI = "TLS SNI"
    case httpHost = "HTTP Host header"
    case http2Authority = "HTTP/2 authority"
    case quicHandshake = "QUIC or HTTP/3 handshake evidence"
    case certificate = "Certificate SAN or subject"
    case capturedPTR = "Captured PTR answer"
    case activeReverseLookup = "Optional active reverse lookup"
    case localResolver = "Local hosts or resolver cache"
    case userAnnotation = "User-supplied annotation"
}

enum ConfidenceLevel: String, Codable, Sendable {
    case direct = "Direct"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case unavailable = "Unavailable"
}

struct HostnameEvidence: Identifiable, Codable, Equatable, Sendable {
    let hostname: String
    let address: String?
    let provenance: EvidenceProvenance
    let firstSeen: Date
    let lastSeen: Date
    let confidence: ConfidenceLevel
    let isPostCaptureEnrichment: Bool

    var id: String {
        "\(hostname)|\(address ?? "")|\(provenance.rawValue)"
    }
}

struct ProcessAttribution: Identifiable, Codable, Equatable, Sendable {
    let processName: String
    let processIdentifier: Int?
    let bundleIdentifier: String?
    let executablePath: String?
    let signingIdentity: String?
    let method: String
    let observedAt: Date?
    let confidence: ConfidenceLevel
    let sourceHost: String

    var id: String {
        "\(processName)|\(processIdentifier.map(String.init) ?? "")|\(method)"
    }

    static func unavailable(sourceHost: String) -> ProcessAttribution {
        ProcessAttribution(
            processName: "Process not observable from this capture",
            processIdentifier: nil,
            bundleIdentifier: nil,
            executablePath: nil,
            signingIdentity: nil,
            method: "Ordinary PCAP/RVI packets contain no proven process owner",
            observedAt: nil,
            confidence: .unavailable,
            sourceHost: sourceHost
        )
    }
}

enum CapturePhase: String, Sendable {
    case idle = "Ready"
    case authorizing = "Waiting for administrator authorization"
    case creatingRVI = "Creating the RVI interface"
    case checkingTraffic = "Checking for live packets"
    case capturing = "Capturing"
    case finalizing = "Stopping and flushing the capture"
    case validating = "Validating the saved capture"
    case cleaningUp = "Removing the RVI interface"
    case completed = "Capture complete"
    case partial = "Capture saved; cleanup needs attention"
    case failed = "Capture failed"
    case cancelled = "Capture cancelled"
}

struct CaptureConfiguration: Equatable, Sendable {
    let device: DeviceInfo
    let durationSeconds: Int
    let format: CaptureFormat
    let outputURL: URL
}

enum CaptureFormat: String, CaseIterable, Identifiable, Sendable {
    case pcap
    case pcapng

    var id: String { rawValue }
}

struct CaptureProgress: Equatable, Sendable {
    let phase: CapturePhase
    let elapsedSeconds: TimeInterval
    let packetCount: Int
    let bytesWritten: Int64
    let status: String
}

struct CaptureCompletion: Equatable, Sendable {
    let partialSuccess: Bool
    let packetCount: Int
    let fileSize: Int64
    let requestedDuration: TimeInterval
    let actualDuration: TimeInterval
    let savedURL: URL
    let source: String
    let interfaceName: String
    let cleanupStatus: String
    let sha256: String
}
