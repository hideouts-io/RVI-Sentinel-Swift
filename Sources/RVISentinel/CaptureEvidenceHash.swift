import CryptoKit
import Darwin
import Foundation

enum CaptureEvidenceError: LocalizedError {
    case openFailed(path: String, code: Int32)
    case inspectionFailed(path: String, code: Int32)
    case nonregularFile(String)
    case sizeLimit(Int64)
    case deadlineExceeded

    var errorDescription: String? {
        switch self {
        case let .openFailed(path, code): "Cannot open the original capture at \(path) (POSIX error \(code)). Check its location and read permission."
        case let .inspectionFailed(path, code): "Cannot inspect the original capture at \(path) (POSIX error \(code)). Choose a readable regular file."
        case let .nonregularFile(path): "The capture at \(path) is not a regular saved file. Save the capture before analysis."
        case let .sizeLimit(bytes): "The original capture exceeds the \(bytes.formatted())-byte hashing limit. Choose a smaller saved capture."
        case .deadlineExceeded: "Original capture hashing exceeded its deadline. Choose a smaller file on local storage."
        }
    }
}

/// Inspect the opened descriptor rather than trusting a pathname check; FIFOs cannot block opening.
func hashCaptureBytes(url: URL, maximumBytes: Int64, deadline: ContinuousClock.Instant) throws -> String {
    try Task.checkCancellation()
    guard url.isFileURL, maximumBytes > 0 else { throw CaptureEvidenceError.nonregularFile(url.path) }
    let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    guard descriptor >= 0 else { throw CaptureEvidenceError.openFailed(path: url.path, code: errno) }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var digest = SHA256()
    var total: Int64 = 0
    do {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw CaptureEvidenceError.inspectionFailed(path: url.path, code: errno) }
        guard metadata.st_mode & S_IFMT == S_IFREG else { throw CaptureEvidenceError.nonregularFile(url.path) }
        guard metadata.st_size <= maximumBytes else { throw CaptureEvidenceError.sizeLimit(maximumBytes) }
        while true {
            try Task.checkCancellation()
            guard ContinuousClock().now < deadline else { throw CaptureEvidenceError.deadlineExceeded }
            guard let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty else { break }
            let (next, overflow) = total.addingReportingOverflow(Int64(chunk.count))
            guard !overflow, next <= maximumBytes else { throw CaptureEvidenceError.sizeLimit(maximumBytes) }
            total = next
            digest.update(data: chunk)
        }
    } catch {
        let primary = error
        do { try handle.close() }
        catch { throw BoundedDecoderCleanupError(primaryFailure: primary, cleanupFailure: .cleanupFailed(executable: "original capture hash", failures: [error.localizedDescription])) }
        throw primary
    }
    try handle.close()
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}
