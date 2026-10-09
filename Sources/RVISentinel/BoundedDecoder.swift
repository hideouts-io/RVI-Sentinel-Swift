import Darwin
import Foundation

struct BoundedDecoderLimits: Sendable {
    let maximumOutputBytes: Int
    let maximumErrorBytes: Int
    let timeout: Duration
}

struct BoundedDecoderLineLimits: Sendable {
    let process: BoundedDecoderLimits
    let maximumLineBytes: Int
    let maximumLines: Int
}

struct BoundedDecoderResult: Sendable {
    let standardError: String
    let outputBytes: Int
    let lineCount: Int
}

struct BoundedDecoderDataResult: Sendable {
    let standardOutput: Data
    let standardError: String
}

enum BoundedDecoderError: LocalizedError {
    case invalidLimits(String)
    case busy
    case executableMissing(String)
    case launchFailed(executable: String, reason: String)
    case pipeClosureFailed(executable: String, stream: String, reason: String)
    case pipeFailed(executable: String, stream: String, operation: String, code: Int32)
    case processStopFailed(executable: String, code: Int32)
    case outputLimitExceeded(executable: String, stream: String, maximumBytes: Int)
    case lineLimitExceeded(executable: String, maximumBytes: Int)
    case rowLimitExceeded(executable: String, maximumLines: Int)
    case invalidUTF8(executable: String, stream: String)
    case deadlineExceeded(executable: String, timeout: Duration)
    case nonzeroExit(executable: String, status: Int32, uncaughtSignal: Bool, diagnostic: String)
    case cleanupFailed(executable: String, failures: [String])

    var errorDescription: String? {
        switch self {
        case let .invalidLimits(reason):
            "Invalid decoder limits: \(reason)"
        case .busy:
            "A decoder operation is already running. Wait for it to finish or cancel it before starting another."
        case let .executableMissing(executable):
            "Required decoder is missing or not executable: \(executable)"
        case let .launchFailed(executable, reason):
            "Could not launch \(executable): \(reason)"
        case let .pipeClosureFailed(executable, stream, reason):
            "Could not close the parent-side \(stream) pipe for \(executable): \(reason)"
        case let .pipeFailed(executable, stream, operation, code):
            "Could not \(operation) the \(stream) pipe for \(executable) (POSIX error \(code))."
        case let .processStopFailed(executable, code):
            "Could not stop the owned decoder \(executable) (POSIX error \(code)); termination could not be confirmed."
        case let .outputLimitExceeded(executable, stream, maximumBytes):
            "\(executable) exceeded the \(stream) limit of \(maximumBytes.formatted()) bytes. Reduce the selected capture or packet scope."
        case let .lineLimitExceeded(executable, maximumBytes):
            "\(executable) produced a packet row larger than \(maximumBytes.formatted()) bytes. Reduce the selected fields or packet scope."
        case let .rowLimitExceeded(executable, maximumLines):
            "\(executable) exceeded the limit of \(maximumLines.formatted()) decoded rows. Reduce the selected capture scope."
        case let .invalidUTF8(executable, stream):
            "\(executable) returned invalid UTF-8 on \(stream). No replacement characters were inserted."
        case let .deadlineExceeded(executable, timeout):
            "\(executable) exceeded the operation deadline of \(timeout). Reduce the selected capture scope and try again."
        case let .nonzeroExit(executable, status, uncaughtSignal, diagnostic):
            "\(executable) stopped with \(uncaughtSignal ? "signal" : "exit status") \(status). \(diagnostic)"
        case let .cleanupFailed(executable, failures):
            "Could not close decoder resources for \(executable): \(failures.joined(separator: "; "))"
        }
    }
}

struct BoundedDecoderCleanupError: LocalizedError {
    let primaryFailure: Error
    let cleanupFailure: BoundedDecoderError

    var errorDescription: String? {
        "\(primaryFailure.localizedDescription) Resource cleanup also failed: \(cleanupFailure.localizedDescription)"
    }
}

/// Owns one external decoder at a time. Output is consumed with backpressure,
/// strict UTF-8, explicit limits, and a deadline covering launch through exit.
actor BoundedDecoder {
    private var activeProcess: OwnedDecoderProcess?

    func cancel() async {
        guard let activeProcess else { return }
        await activeProcess.stop()
        await activeProcess.reap()
    }

    func streamLines(
        executableURL: URL,
        arguments: [String],
        limits: BoundedDecoderLineLimits,
        consume: @escaping @Sendable (String) async throws -> Void
    ) async throws -> BoundedDecoderResult {
        guard limits.maximumLineBytes > 0, limits.maximumLines > 0 else {
            throw BoundedDecoderError.invalidLimits("Line and row limits must be positive.")
        }
        let result = try await execute(
            executableURL: executableURL,
            arguments: arguments,
            limits: limits.process,
            readOutput: { handle in
                try await readDecoderLines(
                    handle: handle,
                    executable: executableURL.path,
                    limits: limits,
                    consume: consume
                )
            }
        )
        return BoundedDecoderResult(
            standardError: result.standardError,
            outputBytes: result.output.bytes,
            lineCount: result.output.lines
        )
    }

    /// Captures one bounded UTF-8 document, such as selected-packet JSON.
    func captureData(
        executableURL: URL,
        arguments: [String],
        limits: BoundedDecoderLimits
    ) async throws -> BoundedDecoderDataResult {
        let result = try await execute(
            executableURL: executableURL,
            arguments: arguments,
            limits: limits,
            readOutput: { handle in
                let data = try readDecoderData(
                    handle: handle,
                    executable: executableURL.path,
                    stream: "stdout",
                    maximumBytes: limits.maximumOutputBytes
                )
                guard String(data: data, encoding: .utf8) != nil else {
                    throw BoundedDecoderError.invalidUTF8(executable: executableURL.path, stream: "stdout")
                }
                return data
            }
        )
        return BoundedDecoderDataResult(standardOutput: result.output, standardError: result.standardError)
    }

    private func execute<Output: Sendable>(
        executableURL: URL,
        arguments: [String],
        limits: BoundedDecoderLimits,
        readOutput: @escaping @Sendable (FileHandle) async throws -> Output
    ) async throws -> DecoderExecutionResult<Output> {
        guard limits.maximumOutputBytes > 0, limits.maximumErrorBytes > 0, limits.timeout > .zero else {
            throw BoundedDecoderError.invalidLimits("Output limits and deadline must be positive.")
        }
        guard activeProcess == nil else { throw BoundedDecoderError.busy }
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw BoundedDecoderError.executableMissing(executableURL.path)
        }
        let owner = OwnedDecoderProcess(executableURL: executableURL, arguments: arguments)
        activeProcess = owner
        defer { activeProcess = nil }

        let result: DecoderExecutionResult<Output>
        do {
            result = try await withTaskCancellationHandler {
                try Task.checkCancellation()
                return try await executeDecoderProcess(
                    owner: owner,
                    executable: executableURL.path,
                    limits: limits,
                    readOutput: readOutput
                )
            } onCancel: {
                Task { await owner.stop() }
            }
        } catch {
            await owner.stop()
            await owner.reap()
            let failures = await owner.closeResources()
            if !failures.isEmpty {
                throw BoundedDecoderCleanupError(
                    primaryFailure: error,
                    cleanupFailure: .cleanupFailed(executable: executableURL.path, failures: failures)
                )
            }
            throw error
        }
        await owner.reap()
        let failures = await owner.closeResources()
        guard failures.isEmpty else {
            throw BoundedDecoderError.cleanupFailed(executable: executableURL.path, failures: failures)
        }
        try Task.checkCancellation()
        if await owner.wasStopped() { throw CancellationError() }
        guard result.termination.status == 0, !result.termination.uncaughtSignal else {
            throw BoundedDecoderError.nonzeroExit(
                executable: executableURL.path,
                status: result.termination.status,
                uncaughtSignal: result.termination.uncaughtSignal,
                diagnostic: decoderDiagnostic(result.standardError)
            )
        }
        return result
    }
}

private struct DecoderTermination: Sendable {
    let status: Int32
    let uncaughtSignal: Bool
}

private struct DecoderHandles: Sendable {
    let output: FileHandle
    let error: FileHandle
    let termination: AsyncStream<DecoderTermination>
}

private struct DecoderExecutionResult<Output: Sendable>: Sendable {
    let output: Output
    let standardError: String
    let termination: DecoderTermination
}

private enum DecoderEvent<Output: Sendable>: Sendable {
    case output(Output)
    case error(String)
    case termination(DecoderTermination)
}

/// Foundation Process and its handles are confined to this external-I/O actor.
/// Cancellation before launch is retained, so it cannot race into a late launch.
private actor OwnedDecoderProcess {
    private let process: Process
    private let outputPipe: Pipe
    private let errorPipe: Pipe
    private let termination: AsyncStream<DecoderTermination>
    private let executable: String
    private var started = false
    private var stopped = false
    private var stopFailure: BoundedDecoderError?
    private var outputWriterClosed = false
    private var errorWriterClosed = false

    init(executableURL: URL, arguments: [String]) {
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        self.process = process
        self.outputPipe = outputPipe
        self.errorPipe = errorPipe
        executable = executableURL.path
        termination = AsyncStream { continuation in
            process.terminationHandler = { terminated in
                continuation.yield(DecoderTermination(
                    status: terminated.terminationStatus,
                    uncaughtSignal: terminated.terminationReason == .uncaughtSignal
                ))
                continuation.finish()
            }
        }
    }

    func launch() throws -> DecoderHandles {
        try Task.checkCancellation()
        guard !stopped else { throw CancellationError() }
        do {
            try process.run()
        } catch {
            throw BoundedDecoderError.launchFailed(executable: executable, reason: error.localizedDescription)
        }
        started = true
        do { try outputPipe.fileHandleForWriting.close() } catch {
            throw BoundedDecoderError.pipeClosureFailed(executable: executable, stream: "stdout", reason: error.localizedDescription)
        }
        outputWriterClosed = true
        do { try errorPipe.fileHandleForWriting.close() } catch {
            throw BoundedDecoderError.pipeClosureFailed(executable: executable, stream: "stderr", reason: error.localizedDescription)
        }
        errorWriterClosed = true
        return DecoderHandles(
            output: outputPipe.fileHandleForReading,
            error: errorPipe.fileHandleForReading,
            termination: termination
        )
    }

    func stop() {
        stopped = true
        guard started, process.isRunning else { return }
        // SIGKILL is scoped to the still-owned child; no global process lookup.
        if Darwin.kill(process.processIdentifier, SIGKILL) != 0, errno != ESRCH {
            stopFailure = .processStopFailed(executable: executable, code: errno)
        }
    }

    func wasStopped() -> Bool {
        stopped
    }

    func reap() async {
        guard started, stopFailure == nil else { return }
        let process = process
        await Task.detached(priority: .utility) { process.waitUntilExit() }.value
    }

    func closeResources() -> [String] {
        process.terminationHandler = nil
        var failures: [String] = []
        if let stopFailure { failures.append(stopFailure.localizedDescription) }
        for (name, handle) in [("stdout reader", outputPipe.fileHandleForReading), ("stderr reader", errorPipe.fileHandleForReading)] {
            do { try handle.close() } catch { failures.append("\(name): \(error.localizedDescription)") }
        }
        if !outputWriterClosed {
            do { try outputPipe.fileHandleForWriting.close() } catch { failures.append("stdout writer: \(error.localizedDescription)") }
        }
        if !errorWriterClosed {
            do { try errorPipe.fileHandleForWriting.close() } catch { failures.append("stderr writer: \(error.localizedDescription)") }
        }
        return failures
    }
}

private func executeDecoderProcess<Output: Sendable>(
    owner: OwnedDecoderProcess,
    executable: String,
    limits: BoundedDecoderLimits,
    readOutput: @escaping @Sendable (FileHandle) async throws -> Output
) async throws -> DecoderExecutionResult<Output> {
    try await withThrowingTaskGroup(of: DecoderEvent<Output>.self) { group in
        group.addTask {
            try await Task.sleep(for: limits.timeout)
            throw BoundedDecoderError.deadlineExceeded(executable: executable, timeout: limits.timeout)
        }
        do {
            let handles = try await owner.launch()
            group.addTask {
                try await runDecoderReader {
                    .output(try await readOutput(handles.output))
                }
            }
            group.addTask {
                try await runDecoderReader {
                    let data = try readDecoderData(
                        handle: handles.error,
                        executable: executable,
                        stream: "stderr",
                        maximumBytes: limits.maximumErrorBytes
                    )
                    guard let text = String(data: data, encoding: .utf8) else {
                        throw BoundedDecoderError.invalidUTF8(executable: executable, stream: "stderr")
                    }
                    return .error(text)
                }
            }
            group.addTask {
                guard let termination = await handles.termination.first(where: { _ in true }) else {
                    throw CancellationError()
                }
                return .termination(termination)
            }
            var output: Output?
            var errorText: String?
            var termination: DecoderTermination?
            while let event = try await group.next() {
                switch event {
                case let .output(value): output = value
                case let .error(value): errorText = value
                case let .termination(value): termination = value
                }
                if let output, let errorText, let termination {
                    group.cancelAll()
                    return DecoderExecutionResult(output: output, standardError: errorText, termination: termination)
                }
            }
            throw CancellationError()
        } catch {
            await owner.stop()
            group.cancelAll()
            throw error
        }
    }
}

private func runDecoderReader<Value: Sendable>(
    read: @escaping @Sendable () async throws -> Value
) async throws -> Value {
    let reader = Task.detached(priority: .userInitiated, operation: read)
    return try await withTaskCancellationHandler {
        try await reader.value
    } onCancel: {
        reader.cancel()
    }
}

private struct DecoderLineCounts: Sendable {
    let bytes: Int
    let lines: Int
}

private func readDecoderLines(
    handle: FileHandle,
    executable: String,
    limits: BoundedDecoderLineLimits,
    consume: @escaping @Sendable (String) async throws -> Void
) async throws -> DecoderLineCounts {
    try prepareDecoderPipe(handle: handle, executable: executable, stream: "stdout")
    var pending = Data()
    var outputBytes = 0
    var lineCount = 0
    while let chunk = try readDecoderChunk(handle: handle, executable: executable, stream: "stdout") {
        guard chunk.count <= limits.process.maximumOutputBytes - outputBytes else {
            throw BoundedDecoderError.outputLimitExceeded(executable: executable, stream: "stdout", maximumBytes: limits.process.maximumOutputBytes)
        }
        outputBytes += chunk.count
        var start = chunk.startIndex
        while let newline = chunk[start...].firstIndex(of: 10) {
            try Task.checkCancellation()
            let segment = chunk[start..<newline]
            guard segment.count <= limits.maximumLineBytes - pending.count else {
                throw BoundedDecoderError.lineLimitExceeded(executable: executable, maximumBytes: limits.maximumLineBytes)
            }
            pending.append(contentsOf: segment)
            guard lineCount < limits.maximumLines else {
                throw BoundedDecoderError.rowLimitExceeded(executable: executable, maximumLines: limits.maximumLines)
            }
            if pending.last == 13 { pending.removeLast() }
            guard let line = String(data: pending, encoding: .utf8) else {
                throw BoundedDecoderError.invalidUTF8(executable: executable, stream: "stdout")
            }
            try await consume(line)
            lineCount += 1
            pending.removeAll(keepingCapacity: true)
            start = chunk.index(after: newline)
        }
        let remainder = chunk[start...]
        guard remainder.count <= limits.maximumLineBytes - pending.count else {
            throw BoundedDecoderError.lineLimitExceeded(executable: executable, maximumBytes: limits.maximumLineBytes)
        }
        pending.append(contentsOf: remainder)
    }
    if !pending.isEmpty {
        try Task.checkCancellation()
        guard lineCount < limits.maximumLines else {
            throw BoundedDecoderError.rowLimitExceeded(executable: executable, maximumLines: limits.maximumLines)
        }
        guard let line = String(data: pending, encoding: .utf8) else {
            throw BoundedDecoderError.invalidUTF8(executable: executable, stream: "stdout")
        }
        try await consume(line)
        lineCount += 1
    }
    return DecoderLineCounts(bytes: outputBytes, lines: lineCount)
}

private func readDecoderData(handle: FileHandle, executable: String, stream: String, maximumBytes: Int) throws -> Data {
    try prepareDecoderPipe(handle: handle, executable: executable, stream: stream)
    var output = Data()
    while let chunk = try readDecoderChunk(handle: handle, executable: executable, stream: stream) {
        guard chunk.count <= maximumBytes - output.count else {
            throw BoundedDecoderError.outputLimitExceeded(executable: executable, stream: stream, maximumBytes: maximumBytes)
        }
        output.append(chunk)
    }
    return output
}

private func prepareDecoderPipe(handle: FileHandle, executable: String, stream: String) throws {
    let flags = fcntl(handle.fileDescriptor, F_GETFL)
    guard flags != -1, fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) != -1 else {
        throw BoundedDecoderError.pipeFailed(executable: executable, stream: stream, operation: "configure", code: errno)
    }
}

/// Polling prevents a descendant holding an inherited pipe from blocking cleanup.
/// Each read is at most 64 KiB; only pipe readiness uses a short blocking wait.
private func readDecoderChunk(handle: FileHandle, executable: String, stream: String) throws -> Data? {
    var descriptor = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
    var buffer = [UInt8](repeating: 0, count: 65_536)
    while true {
        try Task.checkCancellation()
        let ready = Darwin.poll(&descriptor, 1, 50)
        if ready == -1 {
            if errno == EINTR { continue }
            throw BoundedDecoderError.pipeFailed(executable: executable, stream: stream, operation: "poll", code: errno)
        }
        if ready == 0 { continue }
        let count = Darwin.read(handle.fileDescriptor, &buffer, buffer.count)
        if count > 0 { return Data(buffer.prefix(count)) }
        if count == 0 { return nil }
        if errno == EINTR || errno == EAGAIN { continue }
        throw BoundedDecoderError.pipeFailed(executable: executable, stream: stream, operation: "read", code: errno)
    }
}

private func decoderDiagnostic(_ text: String) -> String {
    let bounded = String(String.UnicodeScalarView(text.unicodeScalars.prefix(512)))
    let sanitized = bounded.unicodeScalars.map { scalar -> String in
        CharacterSet.controlCharacters.contains(scalar) ? " " : String(scalar)
    }.joined().trimmingCharacters(in: .whitespacesAndNewlines)
    return sanitized.isEmpty ? "The decoder supplied no stderr diagnostic." : sanitized
}
