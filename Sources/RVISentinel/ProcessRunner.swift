import Foundation

struct ProcessResult: Sendable {
    let exitCode: Int32
    let standardOutput: String
    let standardError: String
}

enum ProcessRunnerError: LocalizedError {
    case executableMissing(String)
    case launchFailed(executable: String, reason: String)
    case pipeClosureFailed(executable: String, stream: String, reason: String)
    case invalidUTF8(executable: String, stream: String)

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
            process.waitUntilExit()
            let (capturedOutput, capturedError) = await (outputData, errorData)
            guard let output = String(data: capturedOutput, encoding: .utf8) else {
                throw ProcessRunnerError.invalidUTF8(executable: executableURL.path, stream: "stdout")
            }
            guard let error = String(data: capturedError, encoding: .utf8) else {
                throw ProcessRunnerError.invalidUTF8(executable: executableURL.path, stream: "stderr")
            }
            return ProcessResult(
                exitCode: process.terminationStatus,
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
