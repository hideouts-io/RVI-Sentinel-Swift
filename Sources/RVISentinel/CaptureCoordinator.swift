import CryptoKit
import Foundation

enum CaptureCoordinatorError: LocalizedError {
    case invalidConfiguration(String)
    case deviceUnavailable(String)
    case dependencyUnavailable(String)
    case rviCreationFailed(String)
    case rviNotStable(String)
    case authorizationFailed(String)
    case noTraffic(String)
    case captureFailed(String)
    case validationFailed(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case let .invalidConfiguration(detail): "Invalid capture configuration: \(detail)"
        case let .deviceUnavailable(detail): "The selected device is not capture-ready: \(detail)"
        case let .dependencyUnavailable(detail): "A required capture component is unavailable: \(detail)"
        case let .rviCreationFailed(detail): "Apple RVI creation failed: \(detail)"
        case let .rviNotStable(detail): "The RVI interface did not become stable: \(detail)"
        case let .authorizationFailed(detail): "Capture authorization failed: \(detail)"
        case let .noTraffic(detail): "No device traffic was observed: \(detail)"
        case let .captureFailed(detail): "Packet capture failed: \(detail)"
        case let .validationFailed(detail): "The saved capture did not validate: \(detail)"
        case .cancelled: "Capture cancelled. Any incomplete output must be reviewed before use."
        }
    }
}

enum CaptureRecoveryKind: String, Equatable, Sendable {
    case noTraffic
    case deviceUnavailable
    case authorization
    case dependencyOrRVI
    case validation
    case cancelled
    case captureFailure
}

struct CaptureRecovery: Equatable, Sendable {
    let kind: CaptureRecoveryKind
    let title: String
    let action: String
    let retrySafety: String
    let evidenceImpact: String
}

func captureFailurePhase(error: Error) -> CapturePhase {
    if error is CancellationError { return .cancelled }
    guard let captureError = error as? CaptureCoordinatorError else { return .failed }
    if case .cancelled = captureError { return .cancelled }
    return .failed
}

func captureRecoveryGuidance(error: Error) -> CaptureRecovery {
    guard let captureError = error as? CaptureCoordinatorError else {
        return CaptureRecovery(
            kind: .captureFailure,
            title: "Capture stopped unexpectedly",
            action: "Review the error, run Check Setup, then retry with the same settings.",
            retrySafety: "Retrying creates a new timestamped destination and does not overwrite an existing file.",
            evidenceImpact: "Any incomplete output is not validated evidence and must be reviewed separately."
        )
    }
    switch captureError {
    case .noTraffic:
        return CaptureRecovery(
            kind: .noTraffic,
            title: "Device connected, but no packets arrived",
            action: "Keep the device connected and unlocked, open a webpage or another network activity, then try the capture again.",
            retrySafety: "The capture countdown never began. You can retry without changing the selected device, duration, format, or destination.",
            evidenceImpact: "No validated capture was replaced or added to a baseline."
        )
    case .deviceUnavailable:
        return CaptureRecovery(
            kind: .deviceUnavailable,
            title: "The device connection changed",
            action: "Reconnect and unlock the device, confirm Trust if prompted, refresh devices, then retry.",
            retrySafety: "Refreshing device state and retrying do not modify an existing validated capture.",
            evidenceImpact: "No process or network conclusion should be drawn from a disconnected-device failure."
        )
    case .authorizationFailed:
        return CaptureRecovery(
            kind: .authorization,
            title: "macOS authorization did not complete",
            action: "Start again and approve the native administrator dialog. RVI-Sentinel never reads or stores the password.",
            retrySafety: "Retrying requests a new bounded authorization and does not reuse credentials.",
            evidenceImpact: "An output file is not treated as evidence unless post-capture validation succeeds."
        )
    case .dependencyUnavailable, .rviCreationFailed, .rviNotStable, .invalidConfiguration:
        return CaptureRecovery(
            kind: .dependencyOrRVI,
            title: "Capture setup could not become ready",
            action: "Run Check Setup, follow the failed check's corrective action, and retry only after readiness passes.",
            retrySafety: "Setup checks are read-only and retrying uses a new timestamped destination.",
            evidenceImpact: "Existing captures, baselines, and exports remain unchanged."
        )
    case .validationFailed:
        return CaptureRecovery(
            kind: .validation,
            title: "The saved output could not be validated",
            action: "Keep the file only for manual review, run Check Setup, and create a new capture before analysis.",
            retrySafety: "Retrying creates a separate file and does not overwrite the unvalidated output.",
            evidenceImpact: "Do not treat the unvalidated file as complete capture evidence."
        )
    case .cancelled:
        return CaptureRecovery(
            kind: .cancelled,
            title: "Capture cancelled",
            action: "Review any incomplete output separately or try again with the retained settings.",
            retrySafety: "A retry uses a new timestamped destination and does not overwrite the cancelled output.",
            evidenceImpact: "Cancelled output is not reported as a validated capture."
        )
    case .captureFailed:
        return CaptureRecovery(
            kind: .captureFailure,
            title: "Packet capture stopped before validation",
            action: "Review the error and Check Setup results, then retry after correcting the reported cause.",
            retrySafety: "Retrying creates a new timestamped destination and does not overwrite an existing file.",
            evidenceImpact: "Incomplete output remains separate and is not added to a baseline automatically."
        )
    }
}

struct CaptureFileStatistics: Equatable, Sendable {
    let packetCount: Int
    let fileSize: Int64
    let actualDuration: TimeInterval
}

struct CaptureCommandPlan: Equatable, Sendable {
    let shellCommand: String
    let authorizationMarker: URL
    let readyMarker: URL
    let failureMarker: URL
    let cancellationMarker: URL
    let preflightURL: URL
}

actor CaptureCoordinator {
    private let processRunner: ProcessRunner
    private let discoveryService: DeviceDiscoveryService
    private let interfaceService: InterfaceInventoryService
    private var cancellationURL: URL?

    init(
        processRunner: ProcessRunner,
        discoveryService: DeviceDiscoveryService,
        interfaceService: InterfaceInventoryService
    ) {
        self.processRunner = processRunner
        self.discoveryService = discoveryService
        self.interfaceService = interfaceService
    }

    func cancel() throws {
        guard let cancellationURL else { return }
        do {
            try Data().write(to: cancellationURL, options: .atomic)
        } catch {
            throw CaptureCoordinatorError.captureFailed("Could not signal cancellation: \(error.localizedDescription)")
        }
    }

    func capture(
        configuration: CaptureConfiguration,
        progress: @escaping @Sendable (CaptureProgress) -> Void
    ) async throws -> CaptureCompletion {
        try validateCaptureConfiguration(configuration)
        let readyDevice = try await confirmDeviceReady(configuration.device)
        let rvictl = URL(fileURLWithPath: "/Library/Apple/usr/bin/rvictl")
        let tcpdump = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        let osascript = URL(fileURLWithPath: "/usr/bin/osascript")
        guard let capinfos = resolveCapinfos() else {
            throw CaptureCoordinatorError.dependencyUnavailable("Wireshark capinfos is required for exact packet, size, and duration statistics.")
        }
        try requireExecutable(rvictl)
        try requireExecutable(tcpdump)
        try requireExecutable(osascript)
        try requireExecutable(capinfos)

        let interfacesBefore = try rviInterfaceNames()
        progress(CaptureProgress(phase: .creatingRVI, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Creating a temporary RVI for \(readyDevice.name)."))
        let startResult = try await processRunner.run(executableURL: rvictl, arguments: ["-s", readyDevice.identifier])
        let startDetail = [startResult.standardOutput, startResult.standardError]
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard startResult.exitCode == 0,
              !startDetail.contains("[FAILED]"),
              !startDetail.contains("bootstrap_look_up(): 1102") else {
            throw CaptureCoordinatorError.rviCreationFailed(startDetail.isEmpty ? "rvictl returned exit code \(startResult.exitCode)." : startDetail)
        }

        var captureResult: Result<(CaptureFileStatistics, String, String), Error>
        do {
            let interfaceName = try await waitForNewRVI(previous: interfacesBefore, timeoutSeconds: 8)
            let temporaryDirectory = try createCaptureTemporaryDirectory()
            defer { try? FileManager.default.removeItem(at: temporaryDirectory) }
            let plan = try makeAuthorizedCapturePlan(
                configuration: configuration,
                interfaceName: interfaceName,
                temporaryDirectory: temporaryDirectory,
                captureUser: NSUserName()
            )
            cancellationURL = plan.cancellationMarker
            defer { cancellationURL = nil }
            let statistics = try await runAuthorizedCapture(
                configuration: configuration,
                interfaceName: interfaceName,
                plan: plan,
                osascript: osascript,
                tcpdump: tcpdump,
                capinfos: capinfos,
                progress: progress
            )
            let hash = try sha256(url: configuration.outputURL)
            captureResult = .success((statistics, hash, interfaceName))
        } catch {
            captureResult = .failure(error)
        }

        progress(CaptureProgress(phase: .cleaningUp, elapsedSeconds: 0, packetCount: 0, bytesWritten: captureFileSize(url: configuration.outputURL), status: "Removing the temporary RVI interface."))
        let cleanup = await cleanupRVI(
            rvictl: rvictl,
            deviceIdentifier: readyDevice.identifier,
            interfacesBefore: interfacesBefore
        )
        let cleanupErrorDescription: String?
        switch cleanup {
        case .success:
            cleanupErrorDescription = nil
        case let .failure(error):
            cleanupErrorDescription = error.localizedDescription
        }

        switch captureResult {
        case let .failure(error):
            if let cleanupError = cleanupErrorDescription {
                throw CaptureCoordinatorError.captureFailed("\(error.localizedDescription) Cleanup also failed: \(cleanupError)")
            }
            throw error
        case let .success((statistics, hash, interfaceName)):
            let partial = cleanupErrorDescription != nil
            progress(CaptureProgress(phase: partial ? .partial : .completed, elapsedSeconds: statistics.actualDuration, packetCount: statistics.packetCount, bytesWritten: statistics.fileSize, status: partial ? "Capture saved and validated; RVI cleanup needs attention." : "Capture saved, validated, and cleaned up."))
            return CaptureCompletion(
                partialSuccess: partial,
                packetCount: statistics.packetCount,
                fileSize: statistics.fileSize,
                requestedDuration: TimeInterval(configuration.durationSeconds),
                actualDuration: statistics.actualDuration,
                savedURL: configuration.outputURL,
                source: readyDevice.name,
                interfaceName: interfaceName,
                cleanupStatus: cleanupErrorDescription ?? "Temporary RVI removed and verified absent.",
                sha256: hash
            )
        }
    }

    private func confirmDeviceReady(_ requested: DeviceInfo) async throws -> DeviceInfo {
        let devices = try await discoveryService.discover()
        guard let current = devices.first(where: { $0.identifier == requested.identifier }) else {
            throw CaptureCoordinatorError.deviceUnavailable("The device disconnected. Reconnect it by USB, unlock it, trust this Mac, and refresh.")
        }
        guard current.readiness == .ready else {
            throw CaptureCoordinatorError.deviceUnavailable(current.status)
        }
        return current
    }

    private func waitForNewRVI(previous: Set<String>, timeoutSeconds: TimeInterval) async throws -> String {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            let current = try rviInterfaceNames()
            let created = current.subtracting(previous)
            if created.count == 1, let interfaceName = created.first {
                return interfaceName
            }
            if created.count > 1 {
                throw CaptureCoordinatorError.rviNotStable("More than one new RVI appeared: \(created.sorted().joined(separator: ", ")).")
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw CaptureCoordinatorError.rviNotStable("No unique new RVI appeared within \(timeoutSeconds) seconds.")
    }

    private func rviInterfaceNames() throws -> Set<String> {
        Set(try interfaceService.inventory().map(\.name).filter { $0.range(of: #"^rvi[0-9]+$"#, options: .regularExpression) != nil })
    }

    private func cleanupRVI(
        rvictl: URL,
        deviceIdentifier: String,
        interfacesBefore: Set<String>
    ) async -> Result<Void, Error> {
        do {
            let result = try await processRunner.run(executableURL: rvictl, arguments: ["-x", deviceIdentifier])
            let remaining = try rviInterfaceNames().subtracting(interfacesBefore)
            guard remaining.isEmpty else {
                throw CaptureCoordinatorError.captureFailed("rvictl exit \(result.exitCode); remaining RVI interfaces: \(remaining.sorted().joined(separator: ", ")).")
            }
            return .success(())
        } catch {
            return .failure(error)
        }
    }

    private func runAuthorizedCapture(
        configuration: CaptureConfiguration,
        interfaceName: String,
        plan: CaptureCommandPlan,
        osascript: URL,
        tcpdump: URL,
        capinfos: URL,
        progress: @escaping @Sendable (CaptureProgress) -> Void
    ) async throws -> CaptureFileStatistics {
        progress(CaptureProgress(phase: .authorizing, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Approve the macOS authorization dialog. The timer has not started."))
        let observation = ProcessObservation()
        let processTask = Task {
            do {
                let result = try await processRunner.run(
                    executableURL: osascript,
                    arguments: [
                        "-e", "on run argv",
                        "-e", "do shell script (item 1 of argv) with administrator privileges",
                        "-e", "end run",
                        "--", plan.shellCommand
                    ]
                )
                await observation.record(result: result)
                return result
            } catch {
                await observation.record(failure: error.localizedDescription)
                throw error
            }
        }
        let authorizationDeadline = Date().addingTimeInterval(300)
        var captureStart: Date?
        while Date() < authorizationDeadline {
            try Task.checkCancellation()
            if FileManager.default.fileExists(atPath: plan.failureMarker.path) {
                let message = try readFailure(url: plan.failureMarker)
                _ = try await processTask.value
                if message.hasPrefix("No packets arrived") {
                    throw CaptureCoordinatorError.noTraffic(message)
                }
                throw CaptureCoordinatorError.captureFailed(message)
            }
            if FileManager.default.fileExists(atPath: plan.readyMarker.path) {
                captureStart = Date()
                break
            }
            if let earlyResult = await observation.snapshot() {
                switch earlyResult {
                case let .result(result):
                    let detail = result.standardError.isEmpty ? result.standardOutput : result.standardError
                    throw CaptureCoordinatorError.authorizationFailed("osascript exited before packet capture started with code \(result.exitCode): \(detail.trimmingCharacters(in: .whitespacesAndNewlines))")
                case let .failure(detail):
                    throw CaptureCoordinatorError.authorizationFailed(detail)
                }
            }
            if FileManager.default.fileExists(atPath: plan.authorizationMarker.path) {
                progress(CaptureProgress(phase: .checkingTraffic, elapsedSeconds: 0, packetCount: 0, bytesWritten: 0, status: "Authorization succeeded. Open a webpage on the device while the five-second traffic check runs."))
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        guard let captureStart else {
            try? Data().write(to: plan.cancellationMarker, options: .atomic)
            throw CaptureCoordinatorError.authorizationFailed("Timed out waiting for authorization and packet preflight.")
        }

        let completionDeadline = captureStart.addingTimeInterval(TimeInterval(configuration.durationSeconds + 45))
        while Date() < completionDeadline {
            try Task.checkCancellation()
            let elapsed = Date().timeIntervalSince(captureStart)
            let bytes = captureFileSize(url: configuration.outputURL)
            progress(CaptureProgress(phase: elapsed < TimeInterval(configuration.durationSeconds) ? .capturing : .finalizing, elapsedSeconds: min(elapsed, TimeInterval(configuration.durationSeconds)), packetCount: 0, bytesWritten: bytes, status: elapsed < TimeInterval(configuration.durationSeconds) ? "Live packets verified. Capturing \(interfaceName)." : "Requested duration reached. Waiting for tcpdump to flush and close."))
            if await observation.snapshot() != nil {
                break
            }
            if elapsed >= TimeInterval(configuration.durationSeconds + 2) {
                break
            }
            try await Task.sleep(for: .milliseconds(250))
        }

        let processResult = try await processTask.value
        if processResult.exitCode == 44
            || processResult.standardError.contains("error number 44")
            || FileManager.default.fileExists(atPath: plan.cancellationMarker.path) {
            throw CaptureCoordinatorError.cancelled
        }
        if FileManager.default.fileExists(atPath: plan.failureMarker.path) {
            let message = try readFailure(url: plan.failureMarker)
            if message.hasPrefix("No packets arrived") {
                throw CaptureCoordinatorError.noTraffic(message)
            }
            throw CaptureCoordinatorError.captureFailed(message)
        }
        guard processResult.exitCode == 0 else {
            let detail = processResult.standardError.isEmpty ? processResult.standardOutput : processResult.standardError
            throw CaptureCoordinatorError.authorizationFailed("osascript exit \(processResult.exitCode): \(detail.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        progress(CaptureProgress(phase: .validating, elapsedSeconds: TimeInterval(configuration.durationSeconds), packetCount: 0, bytesWritten: captureFileSize(url: configuration.outputURL), status: "Validating capture format and readable packets."))
        return try await validateCaptureFile(configuration: configuration, tcpdump: tcpdump, capinfos: capinfos)
    }

    private func validateCaptureFile(
        configuration: CaptureConfiguration,
        tcpdump: URL,
        capinfos: URL
    ) async throws -> CaptureFileStatistics {
        let handle = try FileHandle(forReadingFrom: configuration.outputURL)
        let header = try handle.read(upToCount: 4) ?? Data()
        try handle.close()
        let valid = captureHeaderMatches(header: header, format: configuration.format)
        guard valid else {
            throw CaptureCoordinatorError.validationFailed("The file header does not match \(configuration.format.rawValue.uppercased()).")
        }
        let packetResult = try await processRunner.run(executableURL: tcpdump, arguments: ["-n", "-c", "1", "-r", configuration.outputURL.path])
        guard packetResult.exitCode == 0, !packetResult.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            let detail = packetResult.standardError.isEmpty ? "No readable packet was returned." : packetResult.standardError
            throw CaptureCoordinatorError.validationFailed(detail.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let statistics = try await captureStatistics(url: configuration.outputURL, capinfos: capinfos)
        guard statistics.packetCount > 0 else {
            throw CaptureCoordinatorError.validationFailed("The capture is readable but contains no packets.")
        }
        return statistics
    }

    private func captureStatistics(url: URL, capinfos: URL) async throws -> CaptureFileStatistics {
        let result = try await processRunner.run(executableURL: capinfos, arguments: ["-T", "-r", "-B", "-c", "-s", "-u", url.path])
        guard result.exitCode == 0 else {
            throw CaptureCoordinatorError.validationFailed("capinfos exit \(result.exitCode): \(result.standardError)")
        }
        return try parseCapinfosTabOutput(output: result.standardOutput, fallbackSize: captureFileSize(url: url))
    }
}

private enum ObservedProcessCompletion: Sendable {
    case result(ProcessResult)
    case failure(String)
}

private actor ProcessObservation {
    private var completion: ObservedProcessCompletion?

    func record(result: ProcessResult) {
        completion = .result(result)
    }

    func record(failure: String) {
        completion = .failure(failure)
    }

    func snapshot() -> ObservedProcessCompletion? {
        completion
    }
}

func validateCaptureConfiguration(_ configuration: CaptureConfiguration) throws {
    guard configuration.device.readiness == .ready else {
        throw CaptureCoordinatorError.invalidConfiguration("The selected device is not ready.")
    }
    guard (5...3_600).contains(configuration.durationSeconds) else {
        throw CaptureCoordinatorError.invalidConfiguration("Duration must be between 5 and 3,600 seconds.")
    }
    guard configuration.outputURL.pathExtension.lowercased() == configuration.format.rawValue else {
        throw CaptureCoordinatorError.invalidConfiguration("The output extension must be .\(configuration.format.rawValue).")
    }
    guard !FileManager.default.fileExists(atPath: configuration.outputURL.path) else {
        throw CaptureCoordinatorError.invalidConfiguration("The output already exists and will not be overwritten: \(configuration.outputURL.path)")
    }
}

func requireExecutable(_ url: URL) throws {
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
        throw CaptureCoordinatorError.dependencyUnavailable(url.path)
    }
}

func resolveCapinfos() -> URL? {
    let candidates = ["/opt/homebrew/bin/capinfos", "/usr/local/bin/capinfos", "/Applications/Wireshark.app/Contents/MacOS/capinfos"]
    return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }).map(URL.init(fileURLWithPath:))
}

func createCaptureTemporaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-sentinel-native-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    return directory
}

func makeAuthorizedCapturePlan(
    configuration: CaptureConfiguration,
    interfaceName: String,
    temporaryDirectory: URL,
    captureUser: String
) throws -> CaptureCommandPlan {
    guard interfaceName.range(of: #"^rvi[0-9]+$"#, options: .regularExpression) != nil else {
        throw CaptureCoordinatorError.invalidConfiguration("Invalid RVI interface name: \(interfaceName)")
    }
    guard captureUser.range(of: #"^[A-Za-z_][A-Za-z0-9_-]*$"#, options: .regularExpression) != nil else {
        throw CaptureCoordinatorError.invalidConfiguration("The local account name cannot be passed safely to tcpdump.")
    }
    let preflight = temporaryDirectory.appendingPathComponent("preflight.pcapng")
    let authorization = temporaryDirectory.appendingPathComponent("authorized")
    let ready = temporaryDirectory.appendingPathComponent("capture-ready")
    let failure = temporaryDirectory.appendingPathComponent("capture-failed.txt")
    let cancellation = temporaryDirectory.appendingPathComponent("cancel-requested")
    let tcpdump = "/usr/sbin/tcpdump"
    let preflightCommand = shellJoin([
        tcpdump, "-i", interfaceName, "-s", "0", "-U", "-n", "-c", "1", "-P", "-Z", captureUser, "-w", preflight.path
    ])
    var captureArguments = [tcpdump, "-i", interfaceName, "-s", "0", "-U", "-n"]
    captureArguments.append(contentsOf: configuration.format == .pcapng ? ["-P"] : ["-y", "RAW"])
    captureArguments.append(contentsOf: ["-Z", captureUser, "-w", configuration.outputURL.path])
    let captureCommand = shellJoin(captureArguments)
    let noPacketMessage = shellQuote("No packets arrived during the five-second RVI preflight. Keep the device connected and unlocked, open a webpage, and retry without changing the setup.")
    let preflightFailedMessage = shellQuote("tcpdump failed during the five-second RVI packet preflight.")
    let captureFailedMessage = shellQuote("tcpdump could not remain running for the requested capture.")
    let command = [
        "set -eu",
        "set -m",
        "capture_pid=''",
        "stop_capture() { if [ -n \"$capture_pid\" ] && /bin/kill -0 \"$capture_pid\" 2>/dev/null; then /bin/kill -USR2 \"$capture_pid\" 2>/dev/null || true; /bin/sleep 1; /bin/kill -KILL \"$capture_pid\" 2>/dev/null || true; wait \"$capture_pid\" 2>/dev/null || true; fi; capture_pid=''; }",
        "cleanup_capture() { stop_capture; /bin/rm -f \(shellQuote(preflight.path)) \(shellQuote(authorization.path)) \(shellQuote(ready.path)) \(shellQuote(cancellation.path)); }",
        "trap cleanup_capture HUP INT TERM EXIT",
        "/usr/bin/touch \(shellQuote(authorization.path))",
        "\(preflightCommand) & capture_pid=$!",
        "for preflight_second in 1 2 3 4 5; do if [ -e \(shellQuote(cancellation.path)) ]; then break; fi; if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then break; fi; /bin/sleep 1; done",
        "if [ -e \(shellQuote(cancellation.path)) ]; then stop_capture; exit 44; fi",
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then stop_capture; /usr/bin/printf '%s\\n' \(noPacketMessage) > \(shellQuote(failure.path)); exit 42; fi",
        "preflight_status=0; wait \"$capture_pid\" || preflight_status=$?; capture_pid=''",
        "if [ \"$preflight_status\" -ne 0 ] || [ ! -s \(shellQuote(preflight.path)) ]; then /usr/bin/printf '%s\\n' \(preflightFailedMessage) > \(shellQuote(failure.path)); exit 43; fi",
        "/bin/rm -f \(shellQuote(preflight.path))",
        "\(captureCommand) & capture_pid=$!",
        "/bin/sleep 1",
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then capture_status=0; wait \"$capture_pid\" || capture_status=$?; capture_pid=''; /usr/bin/printf '%s\\n' \(captureFailedMessage) > \(shellQuote(failure.path)); exit \"$capture_status\"; fi",
        "/usr/bin/touch \(shellQuote(ready.path))",
        "capture_started_at=$(/bin/date +%s)",
        "capture_deadline=$((capture_started_at + \(configuration.durationSeconds)))",
        "while [ \"$(/bin/date +%s)\" -lt \"$capture_deadline\" ] && /bin/kill -0 \"$capture_pid\" 2>/dev/null && [ ! -e \(shellQuote(cancellation.path)) ]; do /bin/sleep 1; done",
        "if [ -e \(shellQuote(cancellation.path)) ]; then stop_capture; exit 44; fi",
        "stop_capture",
        "/bin/rm -f \(shellQuote(authorization.path)) \(shellQuote(ready.path)) \(shellQuote(cancellation.path))",
        "trap - EXIT"
    ].joined(separator: "; ")
    return CaptureCommandPlan(shellCommand: command, authorizationMarker: authorization, readyMarker: ready, failureMarker: failure, cancellationMarker: cancellation, preflightURL: preflight)
}

func shellQuote(_ value: String) -> String {
    "'\(value.replacingOccurrences(of: "'", with: "'\"'\"'"))'"
}

func shellJoin(_ arguments: [String]) -> String {
    arguments.map(shellQuote).joined(separator: " ")
}

func captureHeaderMatches(header: Data, format: CaptureFormat) -> Bool {
    let pcapng = Data([0x0a, 0x0d, 0x0d, 0x0a])
    let pcap: Set<Data> = [
        Data([0xd4, 0xc3, 0xb2, 0xa1]),
        Data([0xa1, 0xb2, 0xc3, 0xd4]),
        Data([0x4d, 0x3c, 0xb2, 0xa1]),
        Data([0xa1, 0xb2, 0x3c, 0x4d])
    ]
    return format == .pcapng ? header == pcapng : pcap.contains(header)
}

func parseCapinfosTabOutput(output: String, fallbackSize: Int64) throws -> CaptureFileStatistics {
    let rows = output.split(whereSeparator: \.isNewline).map(String.init)
    guard let row = rows.last, row.contains("\t") else {
        throw CaptureCoordinatorError.validationFailed("capinfos did not return tab-separated statistics: \(output)")
    }
    let values = row.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
    guard values.count == 4 else {
        throw CaptureCoordinatorError.validationFailed("capinfos returned \(values.count) fields; expected at least 4.")
    }
    guard let packetCount = Int(values[1].trimmingCharacters(in: .whitespacesAndNewlines)), packetCount > 0 else {
        throw CaptureCoordinatorError.validationFailed("capinfos did not report a positive packet count.")
    }
    guard let reportedSize = Int64(values[2].trimmingCharacters(in: .whitespacesAndNewlines)), reportedSize > 0 else {
        throw CaptureCoordinatorError.validationFailed("capinfos did not report a positive file size.")
    }
    guard let duration = Double(values[3].trimmingCharacters(in: .whitespacesAndNewlines)), duration >= 0 else {
        throw CaptureCoordinatorError.validationFailed("capinfos did not report a valid capture duration.")
    }
    return CaptureFileStatistics(packetCount: packetCount, fileSize: max(reportedSize, fallbackSize), actualDuration: duration)
}

func captureFileSize(url: URL) -> Int64 {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes?[.size] as? NSNumber)?.int64Value ?? 0
}

func sha256(url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while true {
        let data = try handle.read(upToCount: 1_048_576) ?? Data()
        if data.isEmpty { break }
        hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

private func readFailure(url: URL) throws -> String {
    try String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
}
