import Darwin
import Foundation

enum ControlledDNSReply: Sendable {
    case pointer(String)
    case noAnswer
    case nameDoesNotExist
    case withhold
}

struct ControlledDNSQuery: Sendable {
    let name: String
    let receivedAt: Date
    let question: Data
    let identifier: Data
    let peer: sockaddr_in
}

enum ControlledDNSError: LocalizedError {
    case socket(operation: String, code: Int32)
    case cleanup(primary: String, code: Int32)
    case invalidQuery(String)
    case invalidAnswer
    case queryDeadline
    case unexpectedQuery

    var errorDescription: String? {
        switch self {
        case let .socket(operation, code): "Controlled loopback DNS could not \(operation) (POSIX error \(code))."
        case let .cleanup(primary, code): "\(primary) Closing the controlled DNS socket also failed (POSIX error \(code))."
        case let .invalidQuery(reason): "Controlled loopback DNS received an invalid query: \(reason)."
        case .invalidAnswer: "The controlled DNS answer does not fit one valid UDP DNS response."
        case .queryDeadline: "The controlled loopback DNS server did not observe a query within five seconds."
        case .unexpectedQuery: "An invalid lookup sent a DNS query to the controlled loopback resolver."
        }
    }
}

/// A real UDP endpoint confined to loopback; it never forwards queries or opens an upstream socket.
actor CurrentDNSLoopbackResolver {
    let port: UInt16
    private let descriptor: Int32
    private var observedQueries: [ControlledDNSQuery] = []
    private var closed = false

    init() throws {
        let socket = try openControlledDNSSocket()
        descriptor = socket.descriptor
        port = socket.port
    }

    func respondOnce(reply: ControlledDNSReply) async throws -> ControlledDNSQuery {
        let descriptor = descriptor
        let reader = Task.detached { try receiveControlledDNSQuery(descriptor: descriptor) }
        let query = try await withTaskCancellationHandler {
            try await reader.value
        } onCancel: {
            reader.cancel()
        }
        observedQueries.append(query)
        switch reply {
        case .withhold:
            break
        case .pointer, .noAnswer, .nameDoesNotExist:
            let response = try controlledDNSResponse(query: query, reply: reply)
            var peer = query.peer
            let sent = response.withUnsafeBytes { bytes in
                withUnsafePointer(to: &peer) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                        Darwin.sendto(descriptor, bytes.baseAddress, bytes.count, 0, address, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            guard sent == response.count else { throw ControlledDNSError.socket(operation: "send the complete response", code: errno) }
        }
        return query
    }

    func queries() -> [ControlledDNSQuery] { observedQueries }

    func assertNoQueuedQuery() throws {
        var pending = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        let ready = Darwin.poll(&pending, 1, 0)
        guard ready >= 0 else { throw ControlledDNSError.socket(operation: "check pending queries", code: errno) }
        guard ready == 0 else { throw ControlledDNSError.unexpectedQuery }
    }

    func close() throws {
        guard !closed else { return }
        guard Darwin.close(descriptor) == 0 else { throw ControlledDNSError.socket(operation: "close its socket", code: errno) }
        closed = true
    }
}

private func openControlledDNSSocket() throws -> (descriptor: Int32, port: UInt16) {
    let descriptor = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
    guard descriptor >= 0 else { throw ControlledDNSError.socket(operation: "create its socket", code: errno) }
    do {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: UInt32(0x7f000001).bigEndian)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw ControlledDNSError.socket(operation: "bind 127.0.0.1", code: errno) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.getsockname(descriptor, $0, &length) }
        }
        guard named == 0 else { throw ControlledDNSError.socket(operation: "read its assigned port", code: errno) }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw ControlledDNSError.socket(operation: "configure its socket", code: errno)
        }
        return (descriptor, UInt16(bigEndian: address.sin_port))
    } catch {
        guard Darwin.close(descriptor) == 0 else { throw ControlledDNSError.cleanup(primary: error.localizedDescription, code: errno) }
        throw error
    }
}

private func receiveControlledDNSQuery(descriptor: Int32) throws -> ControlledDNSQuery {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    var pending = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    while clock.now < deadline {
        try Task.checkCancellation()
        let ready = Darwin.poll(&pending, 1, 50)
        if ready < 0 {
            if errno == EINTR { continue }
            throw ControlledDNSError.socket(operation: "wait for a query", code: errno)
        }
        if ready == 0 { continue }
        var buffer = [UInt8](repeating: 0, count: 4_096)
        var peer = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let count = buffer.withUnsafeMutableBytes { bytes in
            withUnsafeMutablePointer(to: &peer) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.recvfrom(descriptor, bytes.baseAddress, bytes.count, 0, $0, &length)
                }
            }
        }
        if count < 0 {
            if errno == EINTR || errno == EAGAIN { continue }
            throw ControlledDNSError.socket(operation: "receive a query", code: errno)
        }
        guard length == MemoryLayout<sockaddr_in>.size, peer.sin_family == sa_family_t(AF_INET),
              peer.sin_addr.s_addr == UInt32(0x7f000001).bigEndian else {
            throw ControlledDNSError.invalidQuery("sender is not the expected IPv4 loopback endpoint")
        }
        return try decodeControlledDNSQuery(data: Data(buffer.prefix(count)), peer: peer, receivedAt: Date())
    }
    throw ControlledDNSError.queryDeadline
}

private func decodeControlledDNSQuery(data: Data, peer: sockaddr_in, receivedAt: Date) throws -> ControlledDNSQuery {
    guard data.count >= 17, data[2] & 0xf8 == 0, data[4] == 0, data[5] == 1 else {
        throw ControlledDNSError.invalidQuery("one standard question is required")
    }
    var cursor = 12
    var labels: [String] = []
    while cursor < data.count {
        let length = Int(data[cursor])
        cursor += 1
        if length == 0 { break }
        guard length <= 63, cursor + length < data.count,
              let label = String(data: data[cursor..<(cursor + length)], encoding: .ascii) else {
            throw ControlledDNSError.invalidQuery("question name is not uncompressed ASCII")
        }
        labels.append(label.lowercased())
        cursor += length
    }
    guard !labels.isEmpty, cursor + 4 <= data.count, data[cursor..<(cursor + 4)] == Data([0, 12, 0, 1]) else {
        throw ControlledDNSError.invalidQuery("one IN PTR question is required")
    }
    return ControlledDNSQuery(
        name: labels.joined(separator: "."), receivedAt: receivedAt,
        question: Data(data[12..<(cursor + 4)]), identifier: Data(data[0..<2]), peer: peer
    )
}

private func controlledDNSResponse(query: ControlledDNSQuery, reply: ControlledDNSReply) throws -> Data {
    let answer: Data
    let flags: UInt16
    switch reply {
    case let .pointer(name):
        let value = try controlledDNSWireName(name)
        guard let length = UInt16(exactly: value.count) else { throw ControlledDNSError.invalidAnswer }
        answer = Data([0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]) + controlledDNSBigEndian(length) + value
        flags = 0x8180
    case .noAnswer:
        answer = Data()
        flags = 0x8180
    case .nameDoesNotExist:
        answer = Data()
        flags = 0x8183
    case .withhold:
        throw ControlledDNSError.invalidAnswer
    }
    return query.identifier + controlledDNSBigEndian(flags) + Data([0, 1, 0, answer.isEmpty ? 0 : 1, 0, 0, 0, 0]) + query.question + answer
}

func controlledDNSWireName(_ name: String) throws -> Data {
    let labels = name.split(separator: ".", omittingEmptySubsequences: false)
    guard !labels.isEmpty, name.utf8.count <= 253 else { throw ControlledDNSError.invalidAnswer }
    var result = Data()
    for label in labels {
        guard (1...63).contains(label.utf8.count), label.utf8.allSatisfy({ $0 < 128 }) else { throw ControlledDNSError.invalidAnswer }
        result.append(UInt8(label.utf8.count))
        result.append(contentsOf: label.utf8)
    }
    result.append(0)
    return result
}

func controlledDNSBigEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}
