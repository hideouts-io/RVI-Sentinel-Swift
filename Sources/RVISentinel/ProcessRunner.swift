import Foundation

struct ProcessResult: Sendable {
    let exitCode: Int32
    let standardOutput: String
    let standardError: String
}

struct ProcessTerminationResult: Sendable {
    let status: Int32
    let uncaughtSignal: Bool
}

enum ProcessRunnerError: LocalizedError {
    case executableMissing(String)
    case launchFailed(executable: String, reason: String)
    case pipeClosureFailed(executable: String, stream: String, reason: String)
    case invalidUTF8(executable: String, stream: String)
    case terminationUnavailable(executable: String)

    var errorDescription: String? {
        switch self {
        case let .executableMissing(path):
            "Required executable is missing or not executable: \(path)"
        case let .launchFailed(executable, reason):
            "Could not launch \(executable): \(reason)"
        case let .pipeClosureFailed(executable, stream, reason):
            "Could not close the parent-side \(stream) pipe for \(executable): \(reason)"
        case let .invalidUTF8(executable, stream):
            "\(executable) returned non-UTF-8 data on \(stream)."
        case let .terminationUnavailable(executable):
            "Could not confirm that \(executable) terminated."
        }
    }
}

struct ProcessRunner: Sendable {
    func run(executableURL: URL, arguments: [String]) async throws -> ProcessResult {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw ProcessRunnerError.executableMissing(executableURL.path)
        }
        return try await Task.detached(priority: .userInitiated) {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.executableURL = executableURL
            process.arguments = arguments
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            let terminationEvents = processTerminationEvents(process)
            do {
                try process.run()
            } catch {
                throw ProcessRunnerError.launchFailed(
                    executable: executableURL.path,
                    reason: error.localizedDescription
                )
            }
            do {
                try outputPipe.fileHandleForWriting.close()
                try errorPipe.fileHandleForWriting.close()
            } catch {
                process.terminate()
                throw ProcessRunnerError.pipeClosureFailed(
                    executable: executableURL.path,
                    stream: "stdout or stderr",
                    reason: error.localizedDescription
                )
            }
            async let outputData = readPipeToEnd(outputPipe)
            async let errorData = readPipeToEnd(errorPipe)
            let termination = try await firstProcessTermination(
                from: terminationEvents,
                executable: executableURL.path
            )
            let (capturedOutput, capturedError) = await (outputData, errorData)
            guard let output = String(data: capturedOutput, encoding: .utf8) else {
                throw ProcessRunnerError.invalidUTF8(executable: executableURL.path, stream: "stdout")
            }
            guard let error = String(data: capturedError, encoding: .utf8) else {
                throw ProcessRunnerError.invalidUTF8(executable: executableURL.path, stream: "stderr")
            }
            return ProcessResult(
                exitCode: termination.status,
                standardOutput: output,
                standardError: error
            )
        }.value
    }
}

func readPipeToEnd(_ pipe: Pipe) async -> Data {
    await Task.detached(priority: .userInitiated) {
        pipe.fileHandleForReading.readDataToEndOfFile()
    }.value
}

func processTerminationEvents(_ process: Process) -> AsyncStream<ProcessTerminationResult> {
    AsyncStream { continuation in
        process.terminationHandler = { terminatedProcess in
            continuation.yield(
                ProcessTerminationResult(
                    status: terminatedProcess.terminationStatus,
                    uncaughtSignal: terminatedProcess.terminationReason == .uncaughtSignal
                )
            )
            continuation.finish()
        }
    }
}

func firstProcessTermination(
    from events: AsyncStream<ProcessTerminationResult>,
    executable: String
) async throws -> ProcessTerminationResult {
    guard let termination = await events.first(where: { _ in true }) else {
        throw ProcessRunnerError.terminationUnavailable(executable: executable)
    }
    return termination
}
