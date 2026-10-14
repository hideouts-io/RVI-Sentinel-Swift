import Foundation

struct OriginalPacketByteRange: Codable, Hashable, Identifiable, Sendable {
    let field: TSharkField
    let offset: Int
    let length: Int

    var id: String { "\(field.rawValue):\(offset):\(length)" }
}

struct OriginalPacketEvidence: Sendable {
    let packetID: PacketRecordID
    let bytes: Data
    let wireLength: UInt32
    let verifiedRanges: [OriginalPacketByteRange]
    let unmappedFields: [TSharkField]
}

struct OriginalPacketLimits: Sendable {
    let maximumJSONBytes: Int
    let maximumFrameBytes: Int
    let maximumRanges: Int
    let maximumDepth: Int
    let maximumCaptureBytes: Int64
    let timeout: Duration

    static let standard = OriginalPacketLimits(
        maximumJSONBytes: 8_388_608, maximumFrameBytes: 262_144, maximumRanges: 2_048, maximumDepth: 48,
        maximumCaptureBytes: 4_294_967_296, timeout: .seconds(30)
    )
}

enum OriginalPacketError: LocalizedError {
    case artifactMismatch
    case unfinishedCapture
    case missingCapture(String)
    case changedCapture
    case invalidIdentity
    case malformedRawFrame(String)
    case invalidRange(String)
    case resourceLimit(String)
    case deadlineExceeded

    var errorDescription: String? {
        switch self {
        case .artifactMismatch: "The selected packet belongs to a different capture. Select a packet from the current saved artifact."
        case .unfinishedCapture: "Original byte inspection requires a completed capture with verified integrity. Finish the capture or reimport the saved original."
        case let .missingCapture(path): "The original capture is unavailable at \(path). Restore it or reimport its current location."
        case .changedCapture: "The original capture changed after analysis or during byte inspection. Reimport the saved capture before inspecting its packets."
        case .invalidIdentity: "TShark did not return the selected frame with its recorded lengths. Reimport the original capture and select the frame again."
        case let .malformedRawFrame(reason): "The selected frame's raw response is invalid: \(reason). Check the installed TShark version and reimport the original capture."
        case let .invalidRange(field): "TShark returned an invalid byte range for \(field). The range was rejected; check the decoder version."
        case let .resourceLimit(reason): "Original byte inspection exceeded its limit: \(reason). Choose a smaller frame or capture."
        case .deadlineExceeded: "Original byte inspection exceeded its total deadline. Choose a smaller capture before inspecting saved bytes."
        }
    }
}

/// Extracts one saved frame only after verifying its artifact, identity, and before/after digests.
func inspectOriginalPacket(
    packet: PacketRecord,
    artifact: PacketCaptureArtifact,
    fields: Set<TSharkField>,
    tsharkURL: URL,
    decoder: BoundedDecoder,
    limits: OriginalPacketLimits
) async throws -> OriginalPacketEvidence {
    guard packet.id.artifactID == artifact.id else { throw OriginalPacketError.artifactMismatch }
    guard artifact.integrity == .verified else { throw OriginalPacketError.unfinishedCapture }
    guard packet.id.frameNumber > 0 else { throw OriginalPacketError.invalidIdentity }
    let url = artifact.id.sourceURL
    guard FileManager.default.fileExists(atPath: url.path) else { throw OriginalPacketError.missingCapture(url.path) }
    guard limits.maximumFrameBytes > 0, limits.maximumRanges > 0, limits.maximumCaptureBytes > 0, limits.timeout > .zero,
          packet.capturedLength.map({ UInt64($0) <= UInt64(limits.maximumFrameBytes) }) ?? true else {
        throw OriginalPacketError.resourceLimit("saved frame exceeds \(limits.maximumFrameBytes) captured bytes")
    }
    let deadline = ContinuousClock().now + limits.timeout
    let before = try await hashPacketEvidence(url: url, maximumBytes: limits.maximumCaptureBytes, deadline: deadline)
    guard before == artifact.id.sha256 else { throw OriginalPacketError.changedCapture }
    try Task.checkCancellation()
    let prefix = ["-n", "-r", url.path, "-c", String(packet.id.frameNumber), "-Y", "frame.number == \(packet.id.frameNumber)"]
    let identity = try await decoder.captureData(
        executableURL: tsharkURL,
        arguments: prefix + ["-T", "fields", "-e", "frame.number", "-e", "frame.cap_len", "-e", "frame.len", "-E", "separator=/t", "-E", "occurrence=a"],
        limits: BoundedDecoderLimits(maximumOutputBytes: 1_024, maximumErrorBytes: 4_096, timeout: try packetInspectionTimeRemaining(deadline: deadline))
    )
    let capturedLength = try validateOriginalFrameIdentity(data: identity.standardOutput, packet: packet)
    guard Int(capturedLength) <= limits.maximumFrameBytes else {
        throw OriginalPacketError.resourceLimit("saved frame exceeds \(limits.maximumFrameBytes) captured bytes")
    }
    let raw = try await decoder.captureData(
        executableURL: tsharkURL,
        arguments: prefix + ["-T", "jsonraw", "--no-duplicate-keys", "-J", "frame eth arp ip ipv6 icmp icmpv6 tcp udp dns tls http quic"],
        limits: BoundedDecoderLimits(maximumOutputBytes: limits.maximumJSONBytes, maximumErrorBytes: 4_096, timeout: try packetInspectionTimeRemaining(deadline: deadline))
    )
    let after = try await hashPacketEvidence(url: url, maximumBytes: limits.maximumCaptureBytes, deadline: deadline)
    guard after == before else { throw OriginalPacketError.changedCapture }
    try Task.checkCancellation()
    return try decodeOriginalPacketBytes(
        data: raw.standardOutput, packetID: packet.id, capturedLength: capturedLength,
        wireLength: packet.wireLength, fields: fields, limits: limits
    )
}

func validateOriginalFrameIdentity(data: Data, packet: PacketRecord) throws -> UInt32 {
    guard let text = String(data: data, encoding: .utf8) else { throw OriginalPacketError.invalidIdentity }
    let lines = text.split(whereSeparator: \.isNewline)
    guard lines.count == 1, let line = lines.first else { throw OriginalPacketError.invalidIdentity }
    let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
    guard fields.count == 3,
          fields.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (48...57).contains($0) }) }),
          UInt64(fields[0]) == packet.id.frameNumber, let captured = UInt32(fields[1]),
          UInt32(fields[2]) == packet.wireLength, captured <= packet.wireLength,
          packet.capturedLength.map({ $0 == captured }) ?? true else { throw OriginalPacketError.invalidIdentity }
    return captured
}

/// Only exact unmasked, unreassembled byte slices become highlights. Container metadata stays unmapped.
func decodeOriginalPacketBytes(
    data: Data,
    packetID: PacketRecordID,
    capturedLength: UInt32,
    wireLength: UInt32,
    fields: Set<TSharkField>,
    limits: OriginalPacketLimits
) throws -> OriginalPacketEvidence {
    try validateEvidenceJSONStructure(data: data, maximumBytes: limits.maximumJSONBytes, maximumDepth: limits.maximumDepth)
    let packets = try JSONDecoder().decode([RawWirePacket].self, from: data)
    guard packets.count == 1, let packet = packets.first else {
        throw OriginalPacketError.malformedRawFrame("exactly one raw frame is required")
    }
    let raw = packet.source.layers.frame
    guard raw.offset == 0, raw.length == Int(capturedLength), raw.mask == 0, raw.dataSource == 0,
          capturedLength <= wireLength, raw.length <= limits.maximumFrameBytes else {
        throw OriginalPacketError.malformedRawFrame("frame offset, captured length, mask, or data source does not match the saved frame")
    }
    let bytes = try packetHexBytes(raw.hex, maximumBytes: limits.maximumFrameBytes)
    guard bytes.count == raw.length else { throw OriginalPacketError.malformedRawFrame("frame hex length differs from captured length") }
    var ranges: Set<OriginalPacketByteRange> = []
    for fieldRange in packet.source.layers.ranges where fields.contains(fieldRange.field) {
        let range = fieldRange.range
        if range.length == 0 || range.mask != 0 || range.dataSource != 0 { continue }
        guard range.offset >= 0, range.length > 0, range.length <= bytes.count, range.offset <= bytes.count - range.length else {
            throw OriginalPacketError.invalidRange(fieldRange.field.rawValue)
        }
        let encoded = try packetHexBytes(range.hex, maximumBytes: limits.maximumFrameBytes)
        guard encoded.count == range.length else { throw OriginalPacketError.invalidRange(fieldRange.field.rawValue) }
        guard bytes.subdata(in: range.offset..<(range.offset + range.length)) == encoded else { continue }
        ranges.insert(OriginalPacketByteRange(field: fieldRange.field, offset: range.offset, length: range.length))
        guard ranges.count <= limits.maximumRanges else { throw OriginalPacketError.resourceLimit("more than \(limits.maximumRanges) verified ranges") }
    }
    return OriginalPacketEvidence(
        packetID: packetID, bytes: bytes, wireLength: wireLength,
        verifiedRanges: ranges.sorted { ($0.offset, $0.field.rawValue, $0.length) < ($1.offset, $1.field.rawValue, $1.length) },
        unmappedFields: fields.subtracting(ranges.map(\.field)).sorted { $0.rawValue < $1.rawValue }
    )
}

private struct RawWirePacket: Decodable {
    let source: Source
    enum CodingKeys: String, CodingKey { case source = "_source" }
    struct Source: Decodable { let layers: Layers }
    struct Layers: Decodable {
        let frame: RawTuple
        let ranges: [RawFieldRange]

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: RawKey.self)
            frame = try container.decode(RawTuple.self, forKey: RawKey(stringValue: "frame_raw"))
            var collected: [RawFieldRange] = []
            for protocolName in ["frame", "eth", "arp", "ip", "ipv6", "icmp", "icmpv6", "tcp", "udp", "dns", "tls", "http", "quic"] {
                let key = RawKey(stringValue: protocolName)
                if container.contains(key) {
                    let protocolFields = try container.decode(RawProtocolFields.self, forKey: key)
                    collected.append(contentsOf: protocolFields.ranges)
                }
            }
            ranges = collected
        }
    }
}

private struct RawKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private struct RawFieldRange: Sendable {
    let field: TSharkField
    let range: RawTuple
}

private struct RawProtocolFields: Decodable {
    let ranges: [RawFieldRange]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RawKey.self)
        var collected: [RawFieldRange] = []
        for key in container.allKeys where key.stringValue.hasSuffix("_raw") {
            guard let field = TSharkField(rawValue: String(key.stringValue.dropLast(4))) else { continue }
            let tuples = try container.decode(RawTupleCollection.self, forKey: key)
            collected.append(contentsOf: tuples.values.map { RawFieldRange(field: field, range: $0) })
        }
        // These are known protocol subtrees, not arbitrary recursive provider objects.
        for tree in ["ip.dsfield_tree", "ip.flags_tree", "tcp.flags_tree", "tcp.analysis", "Timestamps"] {
            let key = RawKey(stringValue: tree)
            if container.contains(key) { collected.append(contentsOf: try container.decode(RawProtocolFields.self, forKey: key).ranges) }
        }
        ranges = collected
    }
}

private struct RawTupleCollection: Decodable {
    let values: [RawTuple]

    init(from decoder: Decoder) throws {
        let container = try decoder.unkeyedContainer()
        var shape = container
        let isSingleTuple: Bool
        do {
            _ = try shape.decode(String.self)
            isSingleTuple = true
        } catch DecodingError.typeMismatch(_, _) {
            isSingleTuple = false
        }
        if isSingleTuple {
            values = [try RawTuple(from: decoder)]
        } else {
            var list = container
            var decoded: [RawTuple] = []
            while !list.isAtEnd { decoded.append(try list.decode(RawTuple.self)) }
            values = decoded
        }
    }
}

private struct RawTuple: Decodable, Sendable {
    let hex: String
    let offset: Int
    let length: Int
    let mask: UInt64
    let dataSource: Int

    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        guard container.count == 6 else { throw OriginalPacketError.malformedRawFrame("raw field must contain six typed elements") }
        hex = try container.decode(String.self)
        offset = try container.decode(Int.self)
        length = try container.decode(Int.self)
        mask = try container.decode(UInt64.self)
        _ = try container.decode(Int.self)
        dataSource = try container.decode(Int.self)
        guard offset >= 0, length >= 0, dataSource >= 0 else { throw OriginalPacketError.malformedRawFrame("raw field has a negative offset, length, or data source") }
    }
}

private func packetHexBytes(_ hex: String, maximumBytes: Int) throws -> Data {
    guard hex.utf8.count.isMultiple(of: 2), hex.utf8.count / 2 <= maximumBytes else {
        throw OriginalPacketError.malformedRawFrame("hex data is odd-length or exceeds the frame-byte limit")
    }
    let characters = Array(hex.utf8)
    var result = Data(capacity: characters.count / 2)
    for index in stride(from: 0, to: characters.count, by: 2) {
        guard let high = hexadecimalNibble(characters[index]), let low = hexadecimalNibble(characters[index + 1]) else {
            throw OriginalPacketError.malformedRawFrame("hex data contains a nonhexadecimal digit")
        }
        result.append((high << 4) | low)
    }
    return result
}

private func hexadecimalNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57: byte - 48
    case 65...70: byte - 55
    case 97...102: byte - 87
    default: nil
    }
}

/// Hash I/O is kept off the main actor and observes cancellation once per chunk.
private func hashPacketEvidence(url: URL, maximumBytes: Int64, deadline: ContinuousClock.Instant) async throws -> String {
    let task = Task.detached(priority: .userInitiated) { try packetEvidenceSHA256(url: url, maximumBytes: maximumBytes, deadline: deadline) }
    return try await withTaskCancellationHandler {
        try await task.value
    } onCancel: {
        task.cancel()
    }
}

private func packetInspectionTimeRemaining(deadline: ContinuousClock.Instant) throws -> Duration {
    let remaining = ContinuousClock().now.duration(to: deadline)
    guard remaining > .zero else { throw OriginalPacketError.deadlineExceeded }
    return remaining
}

private func packetEvidenceSHA256(url: URL, maximumBytes: Int64, deadline: ContinuousClock.Instant) throws -> String {
    try hashCaptureBytes(url: url, maximumBytes: maximumBytes, deadline: deadline)
}
