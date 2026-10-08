import Darwin
import Foundation
import Testing
@testable import RVI_Sentinel

struct BoundedDecoderTests {
    @Test func streamsRowsWhileDrainingBothPipesUnderPressure() async throws {
        let recorder = DecoderTestRecorder()
        let result = try await BoundedDecoder().streamLines(
            executableURL: URL(fileURLWithPath: "/usr/bin/awk"),
            arguments: ["BEGIN { for (i = 0; i < 20000; i++) { print \"0123456789\"; print \"abcdefghij\" > \"/dev/stderr\" } }"],
            limits: decoderTestLineLimits(maximumLineBytes: 128, maximumLines: 20_000),
            consume: { line in await recorder.record(line) }
        )
        #expect(result.outputBytes == 220_000)
        #expect(result.lineCount == 20_000)
        #expect(result.standardError.utf8.count == 220_000)
        #expect(await recorder.count() == 20_000)
        #expect(await recorder.first() == "0123456789")
    }

    @Test func preservesSplitUTF8CRLFAndUnterminatedFinalRow() async throws {
        let recorder = DecoderTestRecorder()
        let result = try await BoundedDecoder().streamLines(
            executableURL: URL(fileURLWithPath: "/usr/bin/awk"),
            arguments: ["BEGIN { for (i = 0; i < 65535; i++) printf \"x\"; printf \"\\303\\251\\r\\nlast\" }"],
            limits: decoderTestLineLimits(maximumLineBytes: 70_000, maximumLines: 2),
            consume: { line in await recorder.record(line) }
        )
        #expect(result.lineCount == 2)
        #expect(result.outputBytes == 65_543)
        #expect(await recorder.first() == String(repeating: "x", count: 65_535) + "é")
        #expect(await recorder.last() == "last")
    }

    @Test func refusesInvalidUTF8InsteadOfReplacingIt() async throws {
        let recorder = DecoderTestRecorder()
        do {
            _ = try await BoundedDecoder().streamLines(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf '\\377\\n'"],
                limits: decoderTestLineLimits(maximumLineBytes: 128, maximumLines: 5),
                consume: { line in await recorder.record(line) }
            )
            Issue.record("Invalid UTF-8 was accepted.")
        } catch let error as BoundedDecoderError {
            guard case .invalidUTF8(_, "stdout") = error else { throw error }
        }
        #expect(await recorder.count() == 0)
    }

    @Test func refusesOversizedRowBeforeDeliveringIt() async throws {
        let recorder = DecoderTestRecorder()
        do {
            _ = try await BoundedDecoder().streamLines(
                executableURL: URL(fileURLWithPath: "/usr/bin/awk"),
                arguments: ["BEGIN { for (i = 0; i < 200000; i++) printf \"x\" }"],
                limits: decoderTestLineLimits(maximumLineBytes: 1_024, maximumLines: 5),
                consume: { line in await recorder.record(line) }
            )
            Issue.record("The row byte limit was ignored.")
        } catch let error as BoundedDecoderError {
            guard case .lineLimitExceeded(_, 1_024) = error else { throw error }
        }
        #expect(await recorder.count() == 0)
    }

    @Test func refusesRowsBeyondExplicitLimit() async throws {
        let recorder = DecoderTestRecorder()
        do {
            _ = try await BoundedDecoder().streamLines(
                executableURL: URL(fileURLWithPath: "/usr/bin/printf"),
                arguments: ["one\ntwo\nthree\n"],
                limits: decoderTestLineLimits(maximumLineBytes: 128, maximumLines: 2),
                consume: { line in await recorder.record(line) }
            )
            Issue.record("The row count limit was ignored.")
        } catch let error as BoundedDecoderError {
            guard case .rowLimitExceeded(_, 2) = error else { throw error }
        }
        #expect(await recorder.count() == 2)
    }

    @Test func capturesBoundedUTF8Document() async throws {
        let result = try await BoundedDecoder().captureData(
            executableURL: URL(fileURLWithPath: "/usr/bin/printf"),
            arguments: ["{\"frame\":55,\"process\":\"maild\"}"],
            limits: decoderTestLimits(timeout: .seconds(5))
        )
        #expect(String(data: result.standardOutput, encoding: .utf8) == "{\"frame\":55,\"process\":\"maild\"}")
        #expect(result.standardError.isEmpty)
    }

    @Test func rejectsInvalidUTF8Document() async throws {
        do {
            _ = try await BoundedDecoder().captureData(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf '\\377'"],
                limits: decoderTestLimits(timeout: .seconds(5))
            )
            Issue.record("Invalid UTF-8 document was accepted.")
        } catch let error as BoundedDecoderError {
            guard case .invalidUTF8(_, "stdout") = error else { throw error }
        }
    }

    @Test func rejectsInvalidUTF8Diagnostic() async throws {
        do {
            _ = try await BoundedDecoder().captureData(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf '\\377' >&2"],
                limits: decoderTestLimits(timeout: .seconds(5))
            )
            Issue.record("Invalid UTF-8 diagnostic was accepted.")
        } catch let error as BoundedDecoderError {
            guard case .invalidUTF8(_, "stderr") = error else { throw error }
        }
    }

    @Test func refusesUnboundedStandardOutput() async throws {
        do {
            _ = try await BoundedDecoder().captureData(
                executableURL: URL(fileURLWithPath: "/usr/bin/yes"),
                arguments: ["0123456789"],
                limits: BoundedDecoderLimits(maximumOutputBytes: 1_024, maximumErrorBytes: 1_024, timeout: .seconds(5))
            )
            Issue.record("The output byte limit was ignored.")
        } catch let error as BoundedDecoderError {
            guard case .outputLimitExceeded(_, "stdout", 1_024) = error else { throw error }
        }
    }

    @Test func refusesUnboundedStandardError() async throws {
        do {
            _ = try await BoundedDecoder().captureData(
                executableURL: URL(fileURLWithPath: "/usr/bin/awk"),
                arguments: ["BEGIN { for (i = 0; i < 20000; i++) print \"0123456789\" > \"/dev/stderr\" }"],
                limits: BoundedDecoderLimits(maximumOutputBytes: 1_024, maximumErrorBytes: 1_024, timeout: .seconds(5))
            )
            Issue.record("The stderr byte limit was ignored.")
        } catch let error as BoundedDecoderError {
            guard case .outputLimitExceeded(_, "stderr", 1_024) = error else { throw error }
        }
    }

    @Test func rejectsNonzeroExitWithBoundedDiagnostic() async throws {
        do {
            _ = try await BoundedDecoder().captureData(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf 'decoder failed\\n' >&2; exit 23"],
                limits: decoderTestLimits(timeout: .seconds(5))
            )
            Issue.record("A nonzero exit was reported as success.")
        } catch let error as BoundedDecoderError {
            guard case let .nonzeroExit(_, status, signal, diagnostic) = error else { throw error }
            #expect(status == 23)
            #expect(!signal)
            #expect(diagnostic == "decoder failed")
        }
    }

    @Test func deadlineStopsAndReapsOwnedProcess() async throws {
        let recorder = DecoderTestRecorder()
        do {
            _ = try await BoundedDecoder().streamLines(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf '%s\\n' \"$$\"; exec /bin/sleep 20"],
                limits: BoundedDecoderLineLimits(
                    process: decoderTestLimits(timeout: .milliseconds(300)),
                    maximumLineBytes: 128,
                    maximumLines: 5
                ),
                consume: { line in await recorder.record(line) }
            )
            Issue.record("The decoder exceeded its deadline without failing.")
        } catch let error as BoundedDecoderError {
            guard case .deadlineExceeded = error else { throw error }
        }
        let line = try #require(await recorder.first())
        let pid = try #require(Int32(line))
        #expect(Darwin.kill(pid, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test func taskCancellationStopsAndReapsOwnedProcess() async throws {
        let recorder = DecoderTestRecorder()
        let decoder = BoundedDecoder()
        let operation = Task {
            try await recordedSleepOperation(decoder: decoder, recorder: recorder)
        }
        let line = try await recorder.waitForFirstLine()
        let pid = try #require(Int32(line))
        operation.cancel()
        do {
            _ = try await operation.value
            Issue.record("A cancelled operation was reported as success.")
        } catch is CancellationError {
            #expect(Darwin.kill(pid, 0) == -1)
            #expect(errno == ESRCH)
        }
    }

    @Test func explicitCancellationStopsOnlyItsOwnedProcess() async throws {
        let recorder = DecoderTestRecorder()
        let decoder = BoundedDecoder()
        let operation = Task {
            try await recordedSleepOperation(decoder: decoder, recorder: recorder)
        }
        let unrelated = Process()
        unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
        unrelated.arguments = ["20"]
        try unrelated.run()
        defer {
            if unrelated.isRunning { unrelated.terminate() }
            unrelated.waitUntilExit()
        }
        let line = try await recorder.waitForFirstLine()
        let pid = try #require(Int32(line))
        await decoder.cancel()
        do {
            _ = try await operation.value
            Issue.record("Explicit cancellation was reported as success.")
        } catch is CancellationError {
            #expect(Darwin.kill(pid, 0) == -1)
            #expect(errno == ESRCH)
            #expect(unrelated.isRunning)
        }
    }
}

private func decoderTestLimits(timeout: Duration) -> BoundedDecoderLimits {
    BoundedDecoderLimits(maximumOutputBytes: 1_000_000, maximumErrorBytes: 1_000_000, timeout: timeout)
}

private func decoderTestLineLimits(maximumLineBytes: Int, maximumLines: Int) -> BoundedDecoderLineLimits {
    BoundedDecoderLineLimits(
        process: decoderTestLimits(timeout: .seconds(5)),
        maximumLineBytes: maximumLineBytes,
        maximumLines: maximumLines
    )
}

private func recordedSleepOperation(decoder: BoundedDecoder, recorder: DecoderTestRecorder) async throws -> BoundedDecoderResult {
    do {
        let result = try await decoder.streamLines(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "printf '%s\\n' \"$$\"; exec /bin/sleep 20"],
            limits: decoderTestLineLimits(maximumLineBytes: 128, maximumLines: 5),
            consume: { line in await recorder.record(line) }
        )
        await recorder.finish()
        return result
    } catch {
        await recorder.finish()
        throw error
    }
}

private enum DecoderTestError: Error {
    case processEndedWithoutRow
}

private actor DecoderTestRecorder {
    private var lines: [String] = []
    private var firstLineWaiters: [CheckedContinuation<String, Error>] = []
    private var finished = false

    func record(_ line: String) {
        lines.append(line)
        for waiter in firstLineWaiters { waiter.resume(returning: line) }
        firstLineWaiters.removeAll()
    }

    func count() -> Int { lines.count }
    func first() -> String? { lines.first }
    func last() -> String? { lines.last }

    func finish() {
        finished = true
        for waiter in firstLineWaiters { waiter.resume(throwing: DecoderTestError.processEndedWithoutRow) }
        firstLineWaiters.removeAll()
    }

    func waitForFirstLine() async throws -> String {
        if let first = lines.first { return first }
        guard !finished else { throw DecoderTestError.processEndedWithoutRow }
        return try await withCheckedThrowingContinuation { firstLineWaiters.append($0) }
    }
}
