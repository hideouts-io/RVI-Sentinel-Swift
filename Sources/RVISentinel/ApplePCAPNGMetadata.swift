import Darwin
import Foundation

struct ApplePCAPNGProcess: Equatable, Sendable {
    let pid: UInt32
    let name: String?
}

struct ApplePCAPNGFrameProcesses: Sendable {
    let primary: ApplePCAPNGProcess?
    let effective: ApplePCAPNGProcess?
}

struct ApplePCAPNGMetadata: Sendable {
    let frameCount: UInt64
    let processes: [UInt64: ApplePCAPNGFrameProcesses]
}

struct ApplePCAPNGMetadataLimits: Sendable {
    let maximumCaptureBytes: Int64
    let maximumFrames: Int
    let maximumProcesses: Int
    let maximumOptionBytes: Int
    let maximumMetadataBytes: Int
    let timeout: Duration

    static let standard = ApplePCAPNGMetadataLimits(maximumCaptureBytes: 4_294_967_296, maximumFrames: 200_000, maximumProcesses: 65_536, maximumOptionBytes: 131_072, maximumMetadataBytes: 67_108_864, timeout: .seconds(60))
}

enum ApplePCAPNGMetadataError: LocalizedError {
    case malformed(offset: UInt64, reason: String)
    case limit(String)
    case decoderConflict(frame: UInt64, field: TSharkField)
    case operationTimedOut

    var errorDescription: String? {
        switch self {
        case let .malformed(offset, reason): "Invalid PCAPNG metadata at byte \(offset): \(reason). Reimport a complete saved capture."
        case let .limit(reason): "PCAPNG metadata exceeded its limit: \(reason). Choose a smaller saved capture."
        case let .decoderConflict(frame, field): "TShark's \(field.rawValue) disagrees with the original PCAPNG process option in frame \(frame). Check the decoder version before using this capture."
        case .operationTimedOut: "A PCAPNG metadata file operation timed out. Check the capture's storage and retry the read."
        }
    }
}

private enum PCAPNGByteOrder { case little, big }
private struct PCAPNGOption { let code: UInt16; let value: Data }

/// Reads Apple legacy process blocks and packet references directly from every PCAPNG.
/// Network decoding remains in TShark. Apple PID/reference values are little endian,
/// independently of section order; block and option headers use the section's order.
/// Sources: Apple libpcap pcap-ng.h and Wireshark wiretap/pcapng-darwin-custom.c.
/// The analyzer brackets this read with original-capture SHA-256 verification.
func readApplePCAPNGMetadata(url: URL, limits: ApplePCAPNGMetadataLimits) throws -> ApplePCAPNGMetadata? {
    guard limits.maximumFrames > 0, limits.maximumProcesses > 0, limits.maximumOptionBytes > 0, limits.maximumMetadataBytes > 0 else {
        throw ApplePCAPNGMetadataError.limit("frame, process, option and storage bounds must be positive")
    }
    return try withPCAPNGMetadataInput(url: url, maximumBytes: limits.maximumCaptureBytes, timeout: limits.timeout) { input in
        var frames: [UInt64: ApplePCAPNGFrameProcesses] = [:]
        guard let frameCount = try scanApplePCAPNGMetadata(input: input, maximumOptionBytes: limits.maximumOptionBytes, limits: limits, consume: { frame, processes in
            frames[frame] = processes
        }) else { return nil }
        return ApplePCAPNGMetadata(frameCount: frameCount, processes: frames)
    }
}

/// Validates the whole container and emits process facts after each packet block is valid.
/// Frame numbers start at one and include packets without process facts, which are not emitted.
/// Frames are never retained; only section-local interface and process definitions are kept.
/// Individual option lists and file operations remain bounded, but total scan size and duration
/// are unrestricted. Consumers must discard partial results if validation or consumption throws.
func streamApplePCAPNGMetadata(url: URL, consume: (UInt64, ApplePCAPNGFrameProcesses) throws -> Void) throws -> UInt64? {
    try withPCAPNGMetadataInput(url: url, maximumBytes: nil, timeout: .seconds(60)) { input in
        try scanApplePCAPNGMetadata(input: input, maximumOptionBytes: 131_072, limits: nil, consume: consume)
    }
}

private func withPCAPNGMetadataInput<Result>(url: URL, maximumBytes: Int64?, timeout: Duration, read: (PCAPNGMetadataInput) throws -> Result) throws -> Result {
    let input = try PCAPNGMetadataInput(url: url, maximumBytes: maximumBytes, timeout: timeout)
    do {
        let result = try read(input)
        try input.close()
        return result
    } catch {
        let primary = error
        do { try input.close() }
        catch { throw BoundedDecoderCleanupError(primaryFailure: primary, cleanupFailure: .cleanupFailed(executable: "PCAPNG metadata read", failures: [error.localizedDescription])) }
        throw primary
    }
}

private func scanApplePCAPNGMetadata(input: PCAPNGMetadataInput, maximumOptionBytes: Int, limits: ApplePCAPNGMetadataLimits?, consume: (UInt64, ApplePCAPNGFrameProcesses) throws -> Void) throws -> UInt64? {
    let deadline = limits.map { ContinuousClock().now + $0.timeout }
    let magic = try input.read(count: 4)
    guard magic == Data([0x0a, 0x0d, 0x0d, 0x0a]) else { return nil }
    try input.seek(to: 0)
    var order: PCAPNGByteOrder?
    var sectionEnd: UInt64?
    var interfaces: [UInt32] = []
    var identities: [ApplePCAPNGProcess] = []
    var frameCount: UInt64 = 0
    var retainedBytes = 0
    while input.position < input.size {
        try autoreleasepool {
            try Task.checkCancellation()
            if let deadline, ContinuousClock().now >= deadline { throw ApplePCAPNGMetadataError.limit("metadata read exceeded its total deadline") }
            let offset = input.position
            let header = try input.read(count: 8)
            let section = header.prefix(4) == magic
            let byteOrder: PCAPNGByteOrder
            if section {
                if let sectionEnd, sectionEnd != offset { throw malformedPCAPNG(offset, "declared section length does not match the next section") }
                let bom = try input.read(count: 4)
                switch Array(bom) {
                case [0x4d, 0x3c, 0x2b, 0x1a]: byteOrder = .little
                case [0x1a, 0x2b, 0x3c, 0x4d]: byteOrder = .big
                default: throw malformedPCAPNG(offset, "invalid section byte-order magic")
                }
                order = byteOrder
                identities = []
                interfaces = []
            } else {
                guard let existing = order else { throw malformedPCAPNG(offset, "block appears before a section header") }
                byteOrder = existing
            }
            let type = pcapngUInt32(header, at: 0, order: byteOrder)
            let length = UInt64(pcapngUInt32(header, at: 4, order: byteOrder))
            guard length >= 12, length.isMultiple(of: 4), length <= input.size - offset else { throw malformedPCAPNG(offset, "invalid, unaligned or truncated block length") }
            let end = offset + length
            if !section, let sectionEnd, end > sectionEnd { throw malformedPCAPNG(offset, "block extends beyond its declared section") }
            var frameProcesses: ApplePCAPNGFrameProcesses?
            switch type {
            case 0x0a0d0d0a:
                guard length >= 28 else { throw malformedPCAPNG(offset, "section header is too short") }
                let fixed = try input.read(count: 12)
                guard pcapngUInt16(fixed, at: 0, order: byteOrder) == 1, pcapngUInt16(fixed, at: 2, order: byteOrder) == 0 else { throw malformedPCAPNG(offset, "unsupported section version") }
                let declared = pcapngUInt64(fixed, at: 4, order: byteOrder)
                if declared == UInt64.max { sectionEnd = nil }
                else {
                    guard declared <= input.size - end else { throw malformedPCAPNG(offset, "declared section length extends beyond the file") }
                    sectionEnd = end + declared
                }
                _ = try readPCAPNGOptions(input: input, end: end - 4, order: byteOrder, maximumBytes: maximumOptionBytes)
            case 1:
                guard length >= 20 else { throw malformedPCAPNG(offset, "interface block is too short") }
                if limits != nil, interfaces.count >= 4_096 { throw malformedPCAPNG(offset, "too many interfaces") }
                let fixed = try input.read(count: 8)
                interfaces.append(pcapngUInt32(fixed, at: 4, order: byteOrder))
                _ = try readPCAPNGOptions(input: input, end: end - 4, order: byteOrder, maximumBytes: maximumOptionBytes)
            case 0x80000001:
                guard length >= 16 else { throw malformedPCAPNG(offset, "process block is too short") }
                if let limits, identities.count >= limits.maximumProcesses { throw malformedPCAPNG(offset, "too many process identities") }
                let pid = pcapngUInt32(try input.read(count: 4), at: 0, order: .little)
                guard pid <= UInt32(Int32.max) else { throw malformedPCAPNG(offset, "process ID exceeds the supported domain range") }
                let options = try readPCAPNGOptions(input: input, end: end - 4, order: byteOrder, maximumBytes: maximumOptionBytes)
                let names = options.filter { $0.code == 2 }
                guard names.count <= 1 else { throw malformedPCAPNG(offset, "process block repeats its name option") }
                let name: String?
                if let value = names.first?.value {
                    guard let text = String(data: value, encoding: .utf8), !text.isEmpty, text.utf8.count <= 256, !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw malformedPCAPNG(offset, "process name is invalid UTF-8, empty, oversized or contains control characters") }
                    name = text
                } else { name = nil }
                identities.append(ApplePCAPNGProcess(pid: pid, name: name))
                if limits != nil { retainedBytes += 64 + (name?.utf8.count ?? 0) }
            case 2, 6:
                guard length >= 32 else { throw malformedPCAPNG(offset, "packet block is too short") }
                let fixed = try input.read(count: 20)
                let interface = type == 6 ? pcapngUInt32(fixed, at: 0, order: byteOrder) : UInt32(pcapngUInt16(fixed, at: 0, order: byteOrder))
                guard Int(interface) < interfaces.count else { throw malformedPCAPNG(offset, "packet references an undefined interface") }
                let captured = pcapngUInt32(fixed, at: 12, order: byteOrder)
                let wire = pcapngUInt32(fixed, at: 16, order: byteOrder)
                guard captured <= wire, interfaces[Int(interface)] == 0 || captured <= interfaces[Int(interface)] else { throw malformedPCAPNG(offset, "captured packet length exceeds wire length or interface snap length") }
                let padded = (UInt64(captured) + 3) & ~UInt64(3)
                guard padded <= end - 4 - input.position else { throw malformedPCAPNG(offset, "packet payload extends beyond its block") }
                try input.seek(to: input.position + padded)
                let options = try readPCAPNGOptions(input: input, end: end - 4, order: byteOrder, maximumBytes: maximumOptionBytes)
                frameCount += 1
                if type == 6 {
                    let primary = try referencedAppleProcess(code: 0x8001, options: options, identities: identities, offset: offset)
                    let effective = try referencedAppleProcess(code: 0x8003, options: options, identities: identities, offset: offset)
                    if primary != nil || effective != nil {
                        frameProcesses = ApplePCAPNGFrameProcesses(primary: primary, effective: effective)
                        if limits != nil { retainedBytes += 256 }
                    }
                }
            case 3:
                guard length >= 16, let snapLength = interfaces.first else { throw malformedPCAPNG(offset, "simple packet has no interface or is too short") }
                let wire = pcapngUInt32(try input.read(count: 4), at: 0, order: byteOrder)
                let captured = snapLength == 0 ? wire : min(wire, snapLength)
                guard (UInt64(captured) + 3) & ~UInt64(3) == end - 4 - input.position else { throw malformedPCAPNG(offset, "simple packet payload length does not match its interface") }
                try input.seek(to: end - 4)
                frameCount += 1
            default: try input.seek(to: end - 4)
            }
            if let limits {
                guard frameCount <= UInt64(limits.maximumFrames), retainedBytes <= limits.maximumMetadataBytes else { throw ApplePCAPNGMetadataError.limit("more than \(limits.maximumFrames) frames or \(limits.maximumMetadataBytes) retained metadata bytes") }
            }
            let trailer = pcapngUInt32(try input.read(count: 4), at: 0, order: byteOrder)
            guard UInt64(trailer) == length, input.position == end else { throw malformedPCAPNG(offset, "block trailer length differs from its header") }
            if let frameProcesses {
                try consume(frameCount, frameProcesses)
                try Task.checkCancellation()
            }
        }
    }
    if let sectionEnd, sectionEnd != input.position { throw malformedPCAPNG(input.position, "final section length does not match the file") }
    return frameCount
}

private func referencedAppleProcess(code: UInt16, options: [PCAPNGOption], identities: [ApplePCAPNGProcess], offset: UInt64) throws -> ApplePCAPNGProcess? {
    let references = options.filter { $0.code == code }
    guard references.count <= 1 else { throw malformedPCAPNG(offset, "packet repeats a process reference") }
    guard let reference = references.first else { return nil }
    guard reference.value.count == 4 else { throw malformedPCAPNG(offset, "process reference is not a 32-bit index") }
    let index = pcapngUInt32(reference.value, at: 0, order: .little)
    guard Int(index) < identities.count else { throw malformedPCAPNG(offset, "packet references an undefined process identity") }
    return identities[Int(index)]
}

private func readPCAPNGOptions(input: PCAPNGMetadataInput, end: UInt64, order: PCAPNGByteOrder, maximumBytes: Int) throws -> [PCAPNGOption] {
    guard input.position <= end, end - input.position <= UInt64(maximumBytes) else { throw ApplePCAPNGMetadataError.limit("block options exceed \(maximumBytes) bytes") }
    let offset = input.position
    let data = try input.read(count: Int(end - offset))
    var position = 0
    var options: [PCAPNGOption] = []
    while position < data.count {
        guard data.count - position >= 4 else { throw malformedPCAPNG(offset + UInt64(position), "truncated option header") }
        let code = pcapngUInt16(data, at: position, order: order)
        let length = Int(pcapngUInt16(data, at: position + 2, order: order))
        position += 4
        if code == 0 {
            guard length == 0, data.dropFirst(position).allSatisfy({ $0 == 0 }) else { throw malformedPCAPNG(offset + UInt64(position), "invalid option terminator") }
            return options
        }
        let padded = (length + 3) & ~3
        guard padded <= data.count - position else { throw malformedPCAPNG(offset + UInt64(position), "option extends beyond its block") }
        options.append(PCAPNGOption(code: code, value: data.subdata(in: position..<(position + length))))
        position += padded
    }
    // An option list may end exactly at its block boundary without opt_endofopt.
    return options
}

/// Compares decoder-populated Apple facts and merges original container facts explicitly.
/// PKTAP fields and their conflict/unknown handling remain separate and unchanged.
func applyingApplePCAPNGProcesses(packet: DecodedPacket, metadata: ApplePCAPNGMetadata) throws -> DecodedPacket {
    let frame = try applePCAPNGFrameNumber(packet: packet)
    guard frame <= metadata.frameCount else { throw malformedPCAPNG(0, "decoder frame number does not identify a container packet") }
    return try applyingApplePCAPNGProcesses(packet: packet, processes: metadata.processes[frame])
}

/// Merges one streamed frame's original facts, rejecting decoder disagreement.
/// A valid positive frame number is required even when no process facts were recorded.
func applyingApplePCAPNGProcesses(packet: DecodedPacket, processes: ApplePCAPNGFrameProcesses?) throws -> DecodedPacket {
    let frame = try applePCAPNGFrameNumber(packet: packet)
    guard let process = processes else { return packet }
    let facts: [(TSharkField, String?)] = [(.darwinProcessID, process.primary.map { String($0.pid) }), (.darwinProcessName, process.primary?.name), (.darwinEffectiveProcessID, process.effective.map { String($0.pid) }), (.darwinEffectiveProcessName, process.effective?.name)]
    var values = packet.values
    for (field, original) in facts {
        guard let original else { continue }
        let observed = packet.all(field)
        guard observed.allSatisfy({ $0 == original }) else { throw ApplePCAPNGMetadataError.decoderConflict(frame: frame, field: field) }
        values[field] = observed.isEmpty ? [original] : observed
    }
    return DecodedPacket(values: values)
}

private func applePCAPNGFrameNumber(packet: DecodedPacket) throws -> UInt64 {
    let values = packet.all(.frameNumber)
    guard values.count == 1, let text = values.first, !text.isEmpty, text.utf8.count <= 20,
          text.utf8.allSatisfy({ (48...57).contains($0) }), let frame = UInt64(text), frame > 0 else {
        throw malformedPCAPNG(0, "decoder frame number does not identify a container packet")
    }
    return frame
}

private func malformedPCAPNG(_ offset: UInt64, _ reason: String) -> ApplePCAPNGMetadataError { .malformed(offset: offset, reason: reason) }
private func pcapngUInt16(_ data: Data, at offset: Int, order: PCAPNGByteOrder) -> UInt16 {
    let a = UInt16(data[offset]), b = UInt16(data[offset + 1])
    return order == .little ? a | b << 8 : a << 8 | b
}
private func pcapngUInt32(_ data: Data, at offset: Int, order: PCAPNGByteOrder) -> UInt32 {
    let bytes = data.subdata(in: offset..<(offset + 4))
    return (order == .little ? Array(bytes.reversed()) : Array(bytes)).reduce(0) { $0 << 8 | UInt32($1) }
}
private func pcapngUInt64(_ data: Data, at offset: Int, order: PCAPNGByteOrder) -> UInt64 {
    let bytes = data.subdata(in: offset..<(offset + 8))
    return (order == .little ? Array(bytes.reversed()) : Array(bytes)).reduce(0) { $0 << 8 | UInt64($1) }
}

/// Descriptor-based bounded I/O connector; payloads and unknown blocks are skipped in place.
private final class PCAPNGMetadataInput {
    private let handle: FileHandle
    private let timeout: Duration
    private var closed = false
    private(set) var position: UInt64 = 0
    let size: UInt64

    init(url: URL, maximumBytes: Int64?, timeout: Duration) throws {
        guard url.isFileURL, maximumBytes.map({ $0 > 0 }) ?? true, timeout > .zero else { throw ApplePCAPNGMetadataError.limit("capture size and timeout must be positive") }
        try Task.checkCancellation()
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw CaptureEvidenceError.openFailed(path: url.path, code: errno) }
        let opened = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            var status = stat()
            guard fstat(descriptor, &status) == 0 else { throw CaptureEvidenceError.inspectionFailed(path: url.path, code: errno) }
            guard status.st_mode & S_IFMT == S_IFREG else { throw CaptureEvidenceError.nonregularFile(url.path) }
            guard status.st_size >= 4 else { throw malformedPCAPNG(0, "capture is too short to identify its container") }
            if let maximumBytes, status.st_size > maximumBytes { throw CaptureEvidenceError.sizeLimit(maximumBytes) }
            size = UInt64(status.st_size)
        } catch {
            let primary = error
            do { try opened.close() }
            catch { throw BoundedDecoderCleanupError(primaryFailure: primary, cleanupFailure: .cleanupFailed(executable: "PCAPNG metadata open", failures: [error.localizedDescription])) }
            throw primary
        }
        handle = opened
        self.timeout = timeout
    }

    private func checkDeadline(_ deadline: ContinuousClock.Instant) throws {
        try Task.checkCancellation()
        guard ContinuousClock().now < deadline else { throw ApplePCAPNGMetadataError.operationTimedOut }
    }

    func read(count: Int) throws -> Data {
        let deadline = ContinuousClock().now + timeout
        try checkDeadline(deadline)
        guard count >= 0, UInt64(count) <= size - position else { throw malformedPCAPNG(position, "read extends beyond the saved file") }
        var data = Data()
        while data.count < count {
            try checkDeadline(deadline)
            let part = try handle.read(upToCount: min(count - data.count, 1_048_576))
            try checkDeadline(deadline)
            guard let part, !part.isEmpty else { throw malformedPCAPNG(position, "file ended during metadata read") }
            data.append(part)
            position += UInt64(part.count)
        }
        return data
    }

    func seek(to offset: UInt64) throws {
        let deadline = ContinuousClock().now + timeout
        try checkDeadline(deadline)
        guard offset <= size else { throw malformedPCAPNG(position, "seek extends beyond the saved file") }
        try handle.seek(toOffset: offset)
        try checkDeadline(deadline)
        position = offset
    }

    func close() throws {
        guard !closed else { return }
        closed = true
        try handle.close()
    }
}
