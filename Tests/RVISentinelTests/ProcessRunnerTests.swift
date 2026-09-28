import Foundation
import Testing
@testable import RVI_Sentinel

struct ProcessRunnerTests {
    @Test func drainsLargeStandardOutputWithoutDeadlocking() async throws {
        let result = try await ProcessRunner().run(
            executableURL: URL(fileURLWithPath: "/usr/bin/awk"),
            arguments: ["BEGIN { for (i = 0; i < 20000; i++) print \"0123456789\" }"]
        )

        #expect(result.exitCode == 0)
        #expect(result.standardOutput.utf8.count == 220_000)
        #expect(result.standardError.isEmpty)
    }
}
