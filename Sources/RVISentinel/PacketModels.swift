import Foundation

enum PacketSourceProvenance: String, Codable, Hashable, Sendable {
    case liveDeviceRVI
    case userDeclaredRVI
    case unknown
}

enum PacketIntegrityState: Codable, Equatable, Sendable {
    case pending
    case verified
    case failed(detail: String)
}

struct PacketArtifactID: Codable, Hashable, Sendable {
    let sha256: String
    let sourceURL: URL

    init(sha256: String, sourceURL: URL) throws {
        guard sha256.utf8.count == 64, sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), sourceURL.isFileURL else {
            throw PacketDomainError.invalidArtifact
        }
        self.sha256 = sha256
        self.sourceURL = sourceURL
    }
}

struct PacketCaptureArtifact: Codable, Equatable, Sendable {
    let id: PacketArtifactID
    let source: PacketSourceProvenance
    let integrity: PacketIntegrityState
}

/// Exact decoded epoch, floor-normalized for negative times. Date is display-only.
/// Printed fractional digits do not establish the container's declared timestamp resolution.
struct PacketTimestamp: Codable, Hashable, Comparable, Sendable {
    let epochSeconds: Int64
    let nanoseconds: UInt32
    let originalText: String

    var displayDate: Date { Date(timeIntervalSince1970: Double(epochSeconds) + Double(nanoseconds) / 1_000_000_000) }
    var decimalDigits: Int { originalText.split(separator: ".", omittingEmptySubsequences: false).dropFirst().first?.count ?? 0 }

    static func < (left: Self, right: Self) -> Bool {
        (left.epochSeconds, left.nanoseconds) < (right.epochSeconds, right.nanoseconds)
    }

    static func == (left: Self, right: Self) -> Bool {
        left.epochSeconds == right.epochSeconds && left.nanoseconds == right.nanoseconds
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(epochSeconds)
        hasher.combine(nanoseconds)
    }
}

struct PacketRecordID: Codable, Hashable, Sendable {
    let artifactID: PacketArtifactID
    let frameNumber: UInt64
}

enum PacketIPFamily: String, Codable, Hashable, Sendable { case ipv4, ipv6 }

struct PacketIPAddress: Codable, Hashable, Sendable {
    let rawValue: String
    let family: PacketIPFamily
}

enum PacketTransport: String, Codable, Hashable, Sendable { case tcp = "TCP", udp = "UDP" }
enum PacketMetadataSource: String, Codable, Hashable, Sendable { case applePCAPNG, pktapHeader, captureFrame, pcapngPacketOptions }
enum PacketMetadataState: String, Codable, Hashable, Sendable { case unknown, recorded, conflict }

struct PacketProcessLabel: Codable, Hashable, Sendable {
    let source: PacketMetadataSource
    let processID: Int32?
    let name: String?
}

/// Labels are recorded capture metadata, never independent device process identity.
struct PacketProcessMetadata: Codable, Hashable, Sendable {
    let state: PacketMetadataState
    let labels: [PacketProcessLabel]

    var processID: Int32? {
        guard state == .recorded else { return nil }
        return labels.compactMap(\.processID).first
    }

    var name: String? {
        guard state == .recorded else { return nil }
        return labels.compactMap(\.name).first
    }
}

struct PacketInterfaceLabel: Codable, Hashable, Sendable {
    let source: PacketMetadataSource
    let name: String
}

struct PacketInterfaceMetadata: Codable, Hashable, Sendable {
    let state: PacketMetadataState
    let labels: [PacketInterfaceLabel]

    var name: String? { state == .recorded ? labels.first?.name : nil }
}

enum PacketDirection: String, Codable, Hashable, Sendable { case inbound, outbound, unknown }

struct PacketDirectionLabel: Codable, Hashable, Sendable {
    let source: PacketMetadataSource
    let direction: PacketDirection
}

struct PacketDirectionMetadata: Codable, Hashable, Sendable {
    let state: PacketMetadataState
    let labels: [PacketDirectionLabel]

    var direction: PacketDirection {
        guard state == .recorded else { return .unknown }
        return labels.first?.direction ?? .unknown
    }
}

struct PacketTCPMetadata: Codable, Equatable, Sendable {
    let flags: UInt16?
    let sequenceRaw: UInt32?
    let acknowledgmentRaw: UInt32?
    let payloadLength: UInt32?

    var isSYN: Bool? { flags.map { $0 & 0x0002 != 0 } }
    var isACK: Bool? { flags.map { $0 & 0x0010 != 0 } }
}

/// A directly recorded name belongs to this frame; it does not assign a name to an address.
struct RecordedPacketName: Codable, Hashable, Sendable {
    let field: TSharkField
    let value: String
}

enum PacketDiagnostic: String, Codable, Hashable, Sendable {
    case ambiguousNetworkLayers
    case ambiguousTransportLayers
    case incompleteNetworkHeader
    case incompleteTransportHeader
    case missingStream
    case processMetadataConflict
    case effectiveProcessMetadataConflict
    case interfaceMetadataConflict
    case directionMetadataConflict
}

struct PacketRecord: Codable, Identifiable, Equatable, Sendable {
    let id: PacketRecordID
    let timestamp: PacketTimestamp
    let wireLength: UInt32
    let capturedLength: UInt32?
    let protocolStack: [String]
    let protocols: [ProtocolKind]
    let sourceAddress: PacketIPAddress?
    let destinationAddress: PacketIPAddress?
    let sourcePort: UInt16?
    let destinationPort: UInt16?
    let transport: PacketTransport?
    let stream: UInt64?
    let tcp: PacketTCPMetadata?
    let process: PacketProcessMetadata
    let effectiveProcess: PacketProcessMetadata
    let interface: PacketInterfaceMetadata
    let direction: PacketDirectionMetadata
    let recordedNames: [RecordedPacketName]
    let diagnostics: [PacketDiagnostic]
}

struct PacketIndexLimits: Equatable, Sendable {
    let maximumRecords: Int
    let maximumEstimatedBytes: Int
}

struct PacketIndexCoverage: Codable, Equatable, Sendable {
    let recordCount: Int
    let estimatedBytes: Int
    let maximumRecords: Int
    let maximumEstimatedBytes: Int
    let ungroupedPackets: Int
}

struct PacketAnalysisResult: Codable, Equatable, Sendable {
    let artifact: PacketCaptureArtifact
    let records: [PacketRecord]
    let sessions: [PacketSession]
    let coverage: PacketIndexCoverage
}

enum PacketDomainError: LocalizedError, Equatable {
    case invalidArtifact
    case invalidField(field: TSharkField, detail: String)
    case invalidTimestamp
    case invalidIndexLimits
    case recordLimitExceeded(Int)
    case memoryLimitExceeded(Int)
    case duplicateFrame(UInt64)
    case artifactMismatch
    case invalidPage
    case byteCountOverflow

    var errorDescription: String? {
        switch self {
        case .invalidArtifact: "The capture reference requires a local file URL and a lowercase SHA-256 digest."
        case let .invalidField(field, detail): "TShark field \(field.rawValue) is invalid: \(detail)."
        case .invalidTimestamp: "The capture timestamp must contain signed integral seconds and at most nine fractional digits within the supported range."
        case .invalidIndexLimits: "Packet index record and memory limits must be positive."
        case let .recordLimitExceeded(limit): "Packet indexing exceeded its \(limit)-record limit. Choose a smaller capture."
        case let .memoryLimitExceeded(limit): "Packet indexing exceeded its \(limit)-byte estimated storage limit. Choose a smaller capture."
        case let .duplicateFrame(frame): "The decoder repeated frame \(frame); packet identity is ambiguous."
        case .artifactMismatch: "A packet belongs to a different capture artifact."
        case .invalidPage: "Packet page offsets must be nonnegative and page sizes must be between 1 and 1,000."
        case .byteCountOverflow: "Packet byte accounting exceeded the supported integer range."
        }
    }
}
