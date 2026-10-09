import Foundation

enum CapturedDNSRecordValue: Codable, Hashable, Sendable {
    case ipv4(String)
    case ipv6(String)
    case canonicalName(String)
    case pointerName(String)
    case service(target: String, port: UInt16, priority: UInt16, weight: UInt16)
}

struct CapturedDNSResourceRecord: Codable, Hashable, Sendable {
    let owner: String?
    let recordType: UInt16
    let recordClass: UInt16
    let ttlSeconds: UInt32
    let value: CapturedDNSRecordValue
}

struct CapturedDNSQuestion: Codable, Hashable, Sendable {
    let name: String
    let recordType: UInt16
    let recordClass: UInt16
}

struct CapturedDNSMessage: Codable, Hashable, Sendable {
    let packetID: PacketRecordID
    let transactionID: UInt16
    let isResponse: Bool
    let isTruncated: Bool
    let responseCode: UInt16
    let questions: [CapturedDNSQuestion]
    let responseToFrame: UInt64?
    let answers: [CapturedDNSResourceRecord]
    let unsupportedRecordTypes: [UInt16]
}

struct CapturedDNSLimits: Sendable {
    let maximumJSONBytes: Int
    let maximumMessages: Int
    let maximumRecords: Int
    let maximumTextBytes: Int
    let maximumDepth: Int

    static let standard = CapturedDNSLimits(
        maximumJSONBytes: 67_108_864,
        maximumMessages: 100_000,
        maximumRecords: 200_000,
        maximumTextBytes: 1_024,
        maximumDepth: 48
    )
}

enum CapturedDNSError: LocalizedError {
    case resourceLimit(String)
    case malformed(frame: UInt64?, reason: String)

    var errorDescription: String? {
        switch self {
        case let .resourceLimit(reason): "Structured DNS evidence exceeded its limit: \(reason). Narrow the capture before analyzing it."
        case let .malformed(frame, reason): "Cannot decode structured DNS evidence\(frame.map { " in frame \($0)" } ?? ""): \(reason). Reimport the original capture or check the installed TShark version."
        }
    }
}

/// Runs a separate passive structured DNS pass with a bounded decoder. No resolver is consulted.
func readCapturedDNSRecords(
    artifactID: PacketArtifactID,
    tsharkURL: URL,
    decoder: BoundedDecoder,
    limits: CapturedDNSLimits,
    timeout: Duration
) async throws -> [CapturedDNSMessage] {
    let response = try await decoder.captureData(
        executableURL: tsharkURL,
        arguments: ["-n", "-r", artifactID.sourceURL.path, "-Y", "dns || mdns || llmnr", "-T", "json", "--no-duplicate-keys", "-J", "frame dns mdns llmnr"],
        limits: BoundedDecoderLimits(maximumOutputBytes: limits.maximumJSONBytes, maximumErrorBytes: 4_096, timeout: timeout)
    )
    return try decodeCapturedDNSRecords(data: response.standardOutput, artifactID: artifactID, limits: limits)
}

/// Reads only consumed DNS answer subtrees. Owners and RDATA are never paired from flattened arrays.
func decodeCapturedDNSRecords(
    data: Data,
    artifactID: PacketArtifactID,
    limits: CapturedDNSLimits
) throws -> [CapturedDNSMessage] {
    guard limits.maximumMessages > 0, limits.maximumRecords > 0, limits.maximumTextBytes > 0 else {
        throw CapturedDNSError.resourceLimit("message, record, and text limits must be positive")
    }
    try validateEvidenceJSONStructure(data: data, maximumBytes: limits.maximumJSONBytes, maximumDepth: limits.maximumDepth)
    try Task.checkCancellation()
    let wire = try JSONDecoder().decode([DNSWirePacket].self, from: data)
    guard wire.count <= limits.maximumMessages else {
        throw CapturedDNSError.resourceLimit("more than \(limits.maximumMessages) DNS frames")
    }
    var messages: [CapturedDNSMessage] = []
    var recordCount = 0
    var seenFrames: Set<UInt64> = []
    for (index, packet) in wire.enumerated() {
        if index.isMultiple(of: 512) { try Task.checkCancellation() }
        let frame = try dnsUnsigned(packet.source.layers.frame.number, frame: nil, field: "frame.number", as: UInt64.self)
        guard frame > 0, seenFrames.insert(frame).inserted else {
            throw CapturedDNSError.malformed(frame: frame, reason: "frame numbers must be positive and unique")
        }
        let layers = packet.source.layers
        let wireMessages = [layers.dns, layers.mdns, layers.llmnr].compactMap { $0 }.flatMap(\.values)
        guard !wireMessages.isEmpty else {
            throw CapturedDNSError.malformed(frame: frame, reason: "DNS frame has no supported DNS subtree")
        }
        for message in wireMessages {
            let flags = message.flags
            let headerFlags = try dnsUnsigned(message.headerFlags, frame: frame, field: "dns.flags", as: UInt16.self)
            let transactionID = try dnsUnsigned(message.identifier, frame: frame, field: "dns.id", as: UInt16.self)
            let isResponse = try dnsBoolean(flags.response, frame: frame, field: "dns.flags.response")
            let isTruncated = try dnsBoolean(flags.truncated, frame: frame, field: "dns.flags.truncated")
            // TShark omits rcode from query trees; its four wire bits remain present in dns.flags.
            let responseCode = headerFlags & 0x000f
            guard isResponse == (headerFlags & 0x8000 != 0), isTruncated == (headerFlags & 0x0200 != 0) else {
                throw CapturedDNSError.malformed(frame: frame, reason: "decoded response/truncation bits conflict with the DNS header")
            }
            if let decodedCode = flags.responseCode {
                guard try dnsUnsigned(decodedCode, frame: frame, field: "dns.flags.rcode", as: UInt16.self) == responseCode else {
                    throw CapturedDNSError.malformed(frame: frame, reason: "decoded response code conflicts with the DNS header")
                }
            }
            let responseTo = try message.responseTo.map { try dnsUnsigned($0, frame: frame, field: "dns.response_to", as: UInt64.self) }
            guard responseCode <= 15, responseTo.map({ $0 > 0 && $0 < frame }) ?? true else {
                throw CapturedDNSError.malformed(frame: frame, reason: "invalid response code or linked query frame")
            }
            var questions: [CapturedDNSQuestion] = []
            for group in (message.queries ?? [:]).values {
                for question in group.values {
                    recordCount += 1
                    if recordCount.isMultiple(of: 512) { try Task.checkCancellation() }
                    guard recordCount <= limits.maximumRecords else {
                        throw CapturedDNSError.resourceLimit("more than \(limits.maximumRecords) DNS questions and records")
                    }
                    questions.append(CapturedDNSQuestion(
                        name: try dnsName(question.name, frame: frame, limits: limits),
                        recordType: try dnsUnsigned(question.type, frame: frame, field: "dns.qry.type", as: UInt16.self),
                        recordClass: try dnsUnsigned(question.recordClass, frame: frame, field: "dns.qry.class", as: UInt16.self)
                    ))
                }
            }
            var answers: [CapturedDNSResourceRecord] = []
            var unsupported: Set<UInt16> = []
            for group in (message.answers ?? [:]).values {
                for record in group.values {
                    recordCount += 1
                    if recordCount.isMultiple(of: 512) { try Task.checkCancellation() }
                    guard recordCount <= limits.maximumRecords else {
                        throw CapturedDNSError.resourceLimit("more than \(limits.maximumRecords) DNS records")
                    }
                    let type = try dnsUnsigned(record.type, frame: frame, field: "dns.resp.type", as: UInt16.self)
                    guard [1, 5, 12, 28, 33].contains(type) else {
                        unsupported.insert(type)
                        continue
                    }
                    let ttl = try dnsUnsigned(record.ttl, frame: frame, field: "dns.resp.ttl", as: UInt32.self)
                    let recordClass = try dnsUnsigned(record.recordClass, frame: frame, field: "dns.resp.class", as: UInt16.self)
                    let owner = try record.owner.map { try dnsName($0, frame: frame, limits: limits) }
                    let value: CapturedDNSRecordValue
                    switch type {
                    case 1, 28:
                        let text = try dnsRequiredString(type == 1 ? record.address : record.address6, frame: frame, field: type == 1 ? "dns.a" : "dns.aaaa")
                        let address = try packetIPAddress(text)
                        guard (type == 1 && address.family == .ipv4) || (type == 28 && address.family == .ipv6) else {
                            throw CapturedDNSError.malformed(frame: frame, reason: "DNS address family does not match RR type")
                        }
                        value = type == 1 ? .ipv4(address.rawValue) : .ipv6(address.rawValue)
                    case 5:
                        value = .canonicalName(try dnsName(record.alias, frame: frame, limits: limits))
                    case 12:
                        value = .pointerName(try dnsName(record.pointer, frame: frame, limits: limits))
                    default:
                        value = .service(
                            target: try dnsName(record.serviceTarget, frame: frame, limits: limits),
                            port: try dnsUnsigned(record.servicePort, frame: frame, field: "dns.srv.port", as: UInt16.self),
                            priority: try dnsUnsigned(record.servicePriority, frame: frame, field: "dns.srv.priority", as: UInt16.self),
                            weight: try dnsUnsigned(record.serviceWeight, frame: frame, field: "dns.srv.weight", as: UInt16.self)
                        )
                    }
                    guard type == 33 || owner != nil else {
                        throw CapturedDNSError.malformed(frame: frame, reason: "address, alias, or PTR record has no owner")
                    }
                    answers.append(CapturedDNSResourceRecord(owner: owner, recordType: type, recordClass: recordClass, ttlSeconds: ttl, value: value))
                }
            }
            // mDNS queries may contain known answers; they remain observations without address links.
            messages.append(CapturedDNSMessage(
                packetID: PacketRecordID(artifactID: artifactID, frameNumber: frame),
                transactionID: transactionID,
                isResponse: isResponse,
                isTruncated: isTruncated,
                responseCode: responseCode,
                questions: questions.sorted { ($0.name, $0.recordType) < ($1.name, $1.recordType) },
                responseToFrame: responseTo,
                answers: answers,
                unsupportedRecordTypes: unsupported.sorted()
            ))
        }
        guard messages.count <= limits.maximumMessages else {
            throw CapturedDNSError.resourceLimit("more than \(limits.maximumMessages) DNS messages")
        }
    }
    return messages.sorted { $0.packetID.frameNumber < $1.packetID.frameNumber }
}

/// Bounds nesting before JSONDecoder traverses external data; string content never changes depth.
func validateEvidenceJSONStructure(data: Data, maximumBytes: Int, maximumDepth: Int) throws {
    guard maximumBytes > 0, maximumDepth > 0, data.count <= maximumBytes else {
        throw CapturedDNSError.resourceLimit("JSON byte budget is invalid or exceeded")
    }
    var depth = 0
    var quoted = false
    var escaped = false
    for (index, byte) in data.enumerated() {
        if index.isMultiple(of: 65_536) { try Task.checkCancellation() }
        if quoted {
            if escaped { escaped = false }
            else if byte == 92 { escaped = true }
            else if byte == 34 { quoted = false }
        } else if byte == 34 {
            quoted = true
        } else if byte == 91 || byte == 123 {
            depth += 1
            guard depth <= maximumDepth else { throw CapturedDNSError.resourceLimit("JSON nesting exceeds \(maximumDepth)") }
        } else if byte == 93 || byte == 125 {
            depth -= 1
            guard depth >= 0 else { throw CapturedDNSError.malformed(frame: nil, reason: "unbalanced JSON structure") }
        }
    }
    guard depth == 0, !quoted else { throw CapturedDNSError.malformed(frame: nil, reason: "incomplete JSON structure") }
}

private struct DNSOneOrMany<Value: Decodable>: Decodable {
    let values: [Value]

    init(from decoder: Decoder) throws {
        var container: UnkeyedDecodingContainer
        do {
            container = try decoder.unkeyedContainer()
        } catch DecodingError.typeMismatch {
            values = [try decoder.singleValueContainer().decode(Value.self)]
            return
        }
        var list: [Value] = []
        while !container.isAtEnd { list.append(try container.decode(Value.self)) }
        values = list
    }
}

private struct DNSWirePacket: Decodable {
    let source: Source
    enum CodingKeys: String, CodingKey { case source = "_source" }
    struct Source: Decodable { let layers: Layers }
    struct Layers: Decodable {
        let frame: Frame
        let dns: DNSOneOrMany<Message>?
        let mdns: DNSOneOrMany<Message>?
        let llmnr: DNSOneOrMany<Message>?
    }
    struct Frame: Decodable {
        let number: DNSOneOrMany<String>
        enum CodingKeys: String, CodingKey { case number = "frame.number" }
    }
    struct Message: Decodable {
        let identifier: DNSOneOrMany<String>
        let headerFlags: DNSOneOrMany<String>
        let flags: Flags
        let queries: [String: DNSOneOrMany<Question>]?
        let answers: [String: DNSOneOrMany<Record>]?
        let responseTo: DNSOneOrMany<String>?
        enum CodingKeys: String, CodingKey {
            case identifier = "dns.id", headerFlags = "dns.flags", flags = "dns.flags_tree", queries = "Queries", answers = "Answers", responseTo = "dns.response_to"
        }
    }
    struct Flags: Decodable {
        let response: DNSOneOrMany<String>
        let truncated: DNSOneOrMany<String>
        let responseCode: DNSOneOrMany<String>?
        enum CodingKeys: String, CodingKey {
            case response = "dns.flags.response", truncated = "dns.flags.truncated", responseCode = "dns.flags.rcode"
        }
    }
    struct Question: Decodable {
        let name: DNSOneOrMany<String>
        let type: DNSOneOrMany<String>
        let recordClass: DNSOneOrMany<String>
        enum CodingKeys: String, CodingKey { case name = "dns.qry.name", type = "dns.qry.type", recordClass = "dns.qry.class" }
    }
    struct Record: Decodable {
        let owner: DNSOneOrMany<String>?
        let type: DNSOneOrMany<String>
        let recordClass: DNSOneOrMany<String>
        let ttl: DNSOneOrMany<String>?
        let address: DNSOneOrMany<String>?
        let address6: DNSOneOrMany<String>?
        let alias: DNSOneOrMany<String>?
        let pointer: DNSOneOrMany<String>?
        let serviceTarget: DNSOneOrMany<String>?
        let servicePort: DNSOneOrMany<String>?
        let servicePriority: DNSOneOrMany<String>?
        let serviceWeight: DNSOneOrMany<String>?
        enum CodingKeys: String, CodingKey {
            case owner = "dns.resp.name", type = "dns.resp.type", recordClass = "dns.resp.class", ttl = "dns.resp.ttl", address = "dns.a", address6 = "dns.aaaa", alias = "dns.cname", pointer = "dns.ptr.domain_name", serviceTarget = "dns.srv.target", servicePort = "dns.srv.port", servicePriority = "dns.srv.priority", serviceWeight = "dns.srv.weight"
        }
    }
}

private func dnsRequiredString(_ value: DNSOneOrMany<String>?, frame: UInt64?, field: String) throws -> String {
    guard let value, value.values.count == 1, let text = value.values.first, !text.isEmpty else {
        throw CapturedDNSError.malformed(frame: frame, reason: "\(field) must contain exactly one value")
    }
    return text
}

private func dnsUnsigned<Value: FixedWidthInteger & UnsignedInteger>(
    _ value: DNSOneOrMany<String>?, frame: UInt64?, field: String, as type: Value.Type
) throws -> Value {
    let text = try dnsRequiredString(value, frame: frame, field: field)
    let radix = text.hasPrefix("0x") ? 16 : 10
    let number = text.hasPrefix("0x") ? String(text.dropFirst(2)) : text
    guard !number.isEmpty, number.utf8.allSatisfy({ radix == 10 ? (48...57).contains($0) : (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }), let result = Value(number, radix: radix) else {
        throw CapturedDNSError.malformed(frame: frame, reason: "\(field) is outside its unsigned range")
    }
    return result
}

private func dnsBoolean(_ value: DNSOneOrMany<String>, frame: UInt64, field: String) throws -> Bool {
    let text = try dnsRequiredString(value, frame: frame, field: field)
    guard text == "0" || text == "1" else { throw CapturedDNSError.malformed(frame: frame, reason: "\(field) must be 0 or 1") }
    return text == "1"
}

private func dnsName(_ value: DNSOneOrMany<String>?, frame: UInt64, limits: CapturedDNSLimits) throws -> String {
    let text = try dnsRequiredString(value, frame: frame, field: "DNS name")
    guard text.utf8.count <= limits.maximumTextBytes, !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw CapturedDNSError.malformed(frame: frame, reason: "DNS name exceeds its text budget or contains control characters")
    }
    if text == "." { return text }
    let normalized = text.lowercased().hasSuffix(".") ? String(text.lowercased().dropLast()) : text.lowercased()
    guard !normalized.isEmpty else { throw CapturedDNSError.malformed(frame: frame, reason: "empty normalized DNS name") }
    return normalized
}
