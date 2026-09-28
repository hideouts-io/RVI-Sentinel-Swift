import Foundation

struct ProcessResult: Sendable {
    let exitCode: Int32
    let standardOutput: String
    let standardError: String
}

enum ProcessRunnerError: LocalizedError {
    case executableMissing(String)
    case launchFailed(executable: String, reason: String)
    case invalidUTF8(executable: String, stream: String)

    var errorDescription: String? {
        switch self {
        case let .executableMissing(path):
            "Required executable is missing or not executable: \(path)"
        case let .launchFailed(executable, reason):
            "Could not launch \(executable): \(reason)"
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
            process.waitUntilExit()
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: outputData, encoding: .utf8) else {
                throw ProcessRunnerError.invalidUTF8(executable: executableURL.path, stream: "stdout")
            }
            guard let error = String(data: errorData, encoding: .utf8) else {
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
