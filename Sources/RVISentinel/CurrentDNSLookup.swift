import Darwin
import Foundation

enum CurrentPTRStatus: String, Codable, Sendable {
    case answered
    case noAnswer
    case nameDoesNotExist
}

enum CurrentDNSAnswerType: String, Codable, Sendable {
    case pointer = "PTR"
    case canonicalName = "CNAME"
}

struct CurrentDNSAnswer: Codable, Hashable, Sendable {
    let owner: String
    let ttlSeconds: UInt32
    let recordType: CurrentDNSAnswerType
    let value: String
}

struct CurrentPTRLookupResult: Codable, Sendable, Identifiable {
    let id: UUID
    let packetID: PacketRecordID
    let requestedAt: Date
    let completedAt: Date
    let address: String
    let queryName: String
    let status: CurrentPTRStatus
    let answers: [CurrentDNSAnswer]
    let provenance: EvidenceProvenance
}

enum CurrentDNSLookupError: LocalizedError {
    case invalidAddress
    case invalidResolverPort
    case invalidResponse(String)
    case resolverFailure(String)

    var errorDescription: String? {
        switch self {
        case .invalidAddress: "Current reverse DNS requires one valid IPv4 or IPv6 address without a zone identifier. Select a decoded packet endpoint."
        case .invalidResolverPort: "The explicit loopback DNS resolver requires a nonzero UDP port."
        case let .invalidResponse(reason): "The current PTR response could not be validated: \(reason). Check the configured resolver and try a new explicit lookup."
        case let .resolverFailure(status): "The configured resolver returned \(status) for the current PTR lookup. Check resolver availability before requesting another lookup."
        }
    }
}

enum CurrentPTRResolver: Sendable {
    case systemConfigured
    case loopback(port: UInt16)
}

/// An explicit user action. Present-day PTR answers never modify captured hostname evidence.
func lookupCurrentPTR(
    address: String,
    packetID: PacketRecordID,
    resolver: CurrentPTRResolver,
    decoder: BoundedDecoder,
    timeout: Duration,
    maximumOutputBytes: Int
) async throws -> CurrentPTRLookupResult {
    let reverseName = try currentDNSReverseName(address: address)
    let resolverArguments: [String]
    switch resolver {
    case .systemConfigured:
        resolverArguments = []
    case let .loopback(port):
        guard port != 0 else { throw CurrentDNSLookupError.invalidResolverPort }
        resolverArguments = ["@127.0.0.1", "-p", String(port)]
    }
    let requestedAt = Date()
    let response = try await decoder.captureData(
        executableURL: URL(fileURLWithPath: "/usr/bin/dig"),
        arguments: resolverArguments + ["+time=2", "+tries=1", "+noall", "+comments", "+answer", "-x", address],
        limits: BoundedDecoderLimits(maximumOutputBytes: maximumOutputBytes, maximumErrorBytes: 4_096, timeout: timeout)
    )
    guard let output = String(data: response.standardOutput, encoding: .utf8) else {
        throw CurrentDNSLookupError.invalidResponse("dig output is not UTF-8")
    }
    let parsed = try parseCurrentPTRResponse(output: output, queryName: reverseName, maximumAnswers: 128)
    return CurrentPTRLookupResult(
        id: UUID(), packetID: packetID, requestedAt: requestedAt, completedAt: Date(), address: address,
        queryName: reverseName, status: parsed.status, answers: parsed.answers, provenance: .activeReverseLookup
    )
}

struct ParsedCurrentPTRResponse: Sendable {
    let status: CurrentPTRStatus
    let answers: [CurrentDNSAnswer]
}

/// Validates the dig answer section and requires an owner chain beginning at the requested IP.
func parseCurrentPTRResponse(output: String, queryName: String, maximumAnswers: Int) throws -> ParsedCurrentPTRResponse {
    let lines = output.split(whereSeparator: \.isNewline)
    let headers = lines.filter { $0.hasPrefix(";; ->>HEADER<<-") }
    guard headers.count == 1, let header = headers.first,
          let statusPart = header.components(separatedBy: "status: ").dropFirst().first,
          let status = statusPart.split(separator: ",").first.map(String.init) else {
        throw CurrentDNSLookupError.invalidResponse("exactly one DNS status header is required")
    }
    guard status == "NOERROR" || status == "NXDOMAIN" else {
        let safeStatus = status.utf8.allSatisfy { (65...90).contains($0) } && status.utf8.count <= 24 ? status : "an invalid DNS status"
        throw CurrentDNSLookupError.resolverFailure(safeStatus)
    }
    var answers: [CurrentDNSAnswer] = []
    for line in lines where !line.hasPrefix(";") {
        let columns = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard columns.count == 5, columns[2] == "IN", let ttl = UInt32(columns[1]),
              let type = CurrentDNSAnswerType(rawValue: columns[3]) else {
            throw CurrentDNSLookupError.invalidResponse("answer must contain owner, unsigned TTL, IN class, PTR/CNAME type, and one value")
        }
        answers.append(CurrentDNSAnswer(
            owner: try currentDNSName(columns[0]), ttlSeconds: ttl, recordType: type, value: try currentDNSName(columns[4])
        ))
        guard answers.count <= maximumAnswers else { throw CurrentDNSLookupError.invalidResponse("answer count exceeds \(maximumAnswers)") }
    }
    guard status != "NXDOMAIN" || !answers.contains(where: { $0.recordType == .pointer }) else {
        throw CurrentDNSLookupError.invalidResponse("NXDOMAIN response contains a PTR answer")
    }
    let aliases = answers.filter { $0.recordType == .canonicalName }
    var owners: Set<String> = [queryName]
    for _ in 0..<aliases.count {
        let added = aliases.filter { owners.contains($0.owner) }.map(\.value)
        owners.formUnion(added)
    }
    guard answers.allSatisfy({ owners.contains($0.owner) }) else {
        throw CurrentDNSLookupError.invalidResponse("answer owner is unrelated to the requested reverse name")
    }
    return ParsedCurrentPTRResponse(
        status: status == "NXDOMAIN" ? .nameDoesNotExist : answers.contains(where: { $0.recordType == .pointer }) ? .answered : .noAnswer,
        answers: answers
    )
}

func currentDNSReverseName(address: String) throws -> String {
    // Darwin accepts IPv6 zones, and C-string conversion truncates embedded NULs.
    guard !address.isEmpty, address.utf8.count <= 45, !address.contains("%"), !address.utf8.contains(0) else {
        throw CurrentDNSLookupError.invalidAddress
    }
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 {
        return withUnsafeBytes(of: ipv4) { bytes in bytes.reversed().map(String.init).joined(separator: ".") + ".in-addr.arpa" }
    }
    var ipv6 = in6_addr()
    guard inet_pton(AF_INET6, address, &ipv6) == 1 else { throw CurrentDNSLookupError.invalidAddress }
    return withUnsafeBytes(of: ipv6) { bytes in
        bytes.reversed().flatMap { byte in [String(byte & 0x0f, radix: 16), String(byte >> 4, radix: 16)] }.joined(separator: ".") + ".ip6.arpa"
    }
}

private func currentDNSName(_ text: String) throws -> String {
    guard !text.isEmpty, text.utf8.count <= 1_024,
          !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.whitespaces.contains($0) }) else {
        throw CurrentDNSLookupError.invalidResponse("invalid or oversized DNS name")
    }
    if text == "." { return text }
    let lower = text.lowercased()
    let name = lower.hasSuffix(".") ? String(lower.dropLast()) : lower
    guard !name.isEmpty else { throw CurrentDNSLookupError.invalidResponse("empty DNS answer name") }
    return name
}
