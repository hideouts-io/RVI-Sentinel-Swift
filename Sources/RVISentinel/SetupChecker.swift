import Foundation

struct SetupChecker: Sendable {
    let processRunner: ProcessRunner
    let discoveryService: DeviceDiscoveryService
    let interfaceService: InterfaceInventoryService

    func run(outputDirectory: URL) async -> [SetupCheck] {
        var checks: [SetupCheck] = []
        let devices: [DeviceInfo]
        do {
            devices = try await discoveryService.discover()
            checks.append(contentsOf: deviceChecks(devices: devices))
        } catch {
            checks.append(contentsOf: unavailableDeviceChecks(detail: error.localizedDescription))
        }
        checks.append(executableCheck(identifier: .rvictl, title: "Apple RVI command", path: "/Library/Apple/usr/bin/rvictl", fix: "Install Xcode device support or Apple device-support components, then reconnect the device."))
        checks.append(await commandCheck(identifier: .rpmuxd, title: "Apple rpmuxd service", executable: "/bin/launchctl", arguments: ["print", "system/com.apple.rpmuxd"], successDetail: "Apple's remote-device multiplexer service is available.", fix: "Reconnect and trust the iPhone or iPad, then restart the Mac if rpmuxd remains unavailable."))
        checks.append(executableCheck(identifier: .tcpdump, title: "Capture backend", path: "/usr/sbin/tcpdump", fix: "Restore the macOS tcpdump component. Capture authorization is requested only when a capture starts."))
        checks.append(analysisBackendCheck())
        checks.append(outputFolderCheck(directory: outputDirectory))
        checks.append(diskSpaceCheck(directory: outputDirectory))
        checks.append(macOSComponentCheck())
        checks.append(cleanupCheck())
        return SetupCheckIdentifier.allCases.map { identifier in
            checks.first { $0.identifier == identifier } ?? SetupCheck(identifier: identifier, title: identifier.rawValue, state: .pending, detail: "Not checked.", correctiveAction: "Run setup checks again.", evidenceSource: "None")
        }
    }

    private func analysisBackendCheck() -> SetupCheck {
        let tsharkCandidates = ["/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark"]
        let tshark = tsharkCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
        let capinfos = resolveCapinfos()
        if let tshark, let capinfos {
            return SetupCheck(identifier: .analysisBackend, title: "Packet-analysis backend", state: .passed, detail: "tshark and capinfos are available at \(tshark) and \(capinfos.path).", correctiveAction: "No action required.", evidenceSource: "Executable file check")
        }
        let missing = [tshark == nil ? "tshark" : nil, capinfos == nil ? "capinfos" : nil].compactMap { $0 }.joined(separator: ", ")
        return SetupCheck(identifier: .analysisBackend, title: "Packet-analysis backend", state: .failed, detail: "Missing required Wireshark tools: \(missing).", correctiveAction: "Install current Wireshark for macOS, including its command-line tools.", evidenceSource: "Executable file check")
    }

    private func cleanupCheck() -> SetupCheck {
        do {
            let interfaces = try interfaceService.inventory().filter { $0.name.hasPrefix("rvi") }
            if interfaces.isEmpty {
                return SetupCheck(identifier: .cleanupState, title: "Capture cleanup state", state: .passed, detail: "No existing RVI interfaces were found.", correctiveAction: "No action required.", evidenceSource: "macOS getifaddrs")
            }
            return SetupCheck(identifier: .cleanupState, title: "Capture cleanup state", state: .warning, detail: "Existing RVI interfaces: \(interfaces.map(\.name).joined(separator: ", ")).", correctiveAction: "Confirm that no capture is using them, then remove each orphan with rvictl before starting a new session.", evidenceSource: "macOS getifaddrs")
        } catch {
            return SetupCheck(identifier: .cleanupState, title: "Capture cleanup state", state: .failed, detail: error.localizedDescription, correctiveAction: "Retry after restarting the app. Interface state must be known before capture.", evidenceSource: "macOS getifaddrs")
        }
    }

    private func commandCheck(identifier: SetupCheckIdentifier, title: String, executable: String, arguments: [String], successDetail: String, fix: String) async -> SetupCheck {
        do {
            let result = try await processRunner.run(executableURL: URL(fileURLWithPath: executable), arguments: arguments)
            if result.exitCode == 0 {
                return SetupCheck(identifier: identifier, title: title, state: .passed, detail: successDetail, correctiveAction: "No action required.", evidenceSource: "\(executable) \(arguments.joined(separator: " "))")
            }
            let detail = result.standardError.isEmpty ? result.standardOutput : result.standardError
            return SetupCheck(identifier: identifier, title: title, state: .failed, detail: detail.trimmingCharacters(in: .whitespacesAndNewlines), correctiveAction: fix, evidenceSource: "\(executable) exit code \(result.exitCode)")
        } catch {
            return SetupCheck(identifier: identifier, title: title, state: .failed, detail: error.localizedDescription, correctiveAction: fix, evidenceSource: "Process launch")
        }
    }
}

func deviceChecks(devices: [DeviceInfo]) -> [SetupCheck] {
    let connected = devices.filter { $0.transport == "wired" }
    let ready = devices.filter { $0.readiness == .ready }
    return [
        SetupCheck(identifier: .device, title: "Connected iPhone or iPad", state: devices.isEmpty ? .failed : .passed, detail: devices.isEmpty ? "No physical iPhone or iPad is visible." : "\(devices.count) physical Apple mobile device(s) visible.", correctiveAction: devices.isEmpty ? "Connect an unlocked iPhone or iPad with a data-capable USB cable." : "No action required.", evidenceSource: "Apple CoreDevice via devicectl"),
        SetupCheck(identifier: .usb, title: "USB visibility", state: connected.isEmpty ? .failed : .passed, detail: connected.isEmpty ? "No physical device is reported over wired USB." : "\(connected.count) device(s) are visible over USB.", correctiveAction: connected.isEmpty ? "Unlock the device, reconnect the cable directly, and allow the accessory connection." : "No action required.", evidenceSource: "devicectl connectionProperties.transportType"),
        SetupCheck(identifier: .trust, title: "Device trust and pairing", state: ready.isEmpty ? .failed : .passed, detail: ready.isEmpty ? "No USB device is booted, paired, and ready." : "\(ready.count) device(s) are paired and capture-ready.", correctiveAction: ready.isEmpty ? "Unlock the device, choose Trust when prompted, enter the device passcode, and refresh." : "No action required.", evidenceSource: "devicectl pairing, boot, transport, and visibility state"),
        SetupCheck(identifier: .developerSupport, title: "Developer support", state: devices.isEmpty ? .warning : .passed, detail: devices.isEmpty ? "Developer support cannot be evaluated without a visible device." : "Apple CoreDevice returned device details successfully.", correctiveAction: devices.isEmpty ? "Connect the device, then enable Developer Mode only if macOS explicitly requires it for RVI." : "No action required.", evidenceSource: "devicectl device metadata")
    ]
}

func unavailableDeviceChecks(detail: String) -> [SetupCheck] {
    [.device, .usb, .trust, .developerSupport].map { identifier in
        SetupCheck(identifier: identifier, title: identifier.rawValue, state: .failed, detail: detail, correctiveAction: "Install or select current Xcode command-line tools, then reconnect and trust the device.", evidenceSource: "Apple CoreDevice discovery failure")
    }
}

func executableCheck(identifier: SetupCheckIdentifier, title: String, path: String, fix: String) -> SetupCheck {
    let available = FileManager.default.isExecutableFile(atPath: path)
    return SetupCheck(identifier: identifier, title: title, state: available ? .passed : .failed, detail: available ? "Available at \(path)." : "Not executable at \(path).", correctiveAction: available ? "No action required." : fix, evidenceSource: "Executable file check")
}

func outputFolderCheck(directory: URL) -> SetupCheck {
    var isDirectory: ObjCBool = false
    let exists = FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory)
    let writable = exists && isDirectory.boolValue && FileManager.default.isWritableFile(atPath: directory.path)
    return SetupCheck(identifier: .outputFolder, title: "Output-folder permissions", state: writable ? .passed : .failed, detail: writable ? "The selected folder is writable." : "The selected path is missing, not a folder, or not writable.", correctiveAction: writable ? "No action required." : "Choose an existing local folder where your account can create files.", evidenceSource: "FileManager path and permission check")
}

func diskSpaceCheck(directory: URL) -> SetupCheck {
    do {
        let values = try directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        guard let available = values.volumeAvailableCapacityForImportantUsage else {
            return SetupCheck(identifier: .diskSpace, title: "Available disk space", state: .failed, detail: "macOS did not report available capacity.", correctiveAction: "Choose another local volume and retry.", evidenceSource: "URL volume resource values")
        }
        let minimum: Int64 = 1_073_741_824
        return SetupCheck(identifier: .diskSpace, title: "Available disk space", state: available >= minimum ? .passed : .failed, detail: "\(ByteCountFormatter.string(fromByteCount: available, countStyle: .file)) available.", correctiveAction: available >= minimum ? "No action required." : "Free at least 1 GB or select another local volume.", evidenceSource: "volumeAvailableCapacityForImportantUsage")
    } catch {
        return SetupCheck(identifier: .diskSpace, title: "Available disk space", state: .failed, detail: error.localizedDescription, correctiveAction: "Choose an accessible local output folder and retry.", evidenceSource: "URL volume resource values")
    }
}

func macOSComponentCheck() -> SetupCheck {
    let required = ["/usr/bin/xcrun", "/sbin/ifconfig", "/usr/bin/osascript", "/usr/bin/shasum"]
    let missing = required.filter { !FileManager.default.isExecutableFile(atPath: $0) }
    return SetupCheck(identifier: .macOSComponents, title: "Required macOS components", state: missing.isEmpty ? .passed : .failed, detail: missing.isEmpty ? "Required Apple system tools are available." : "Missing: \(missing.joined(separator: ", ")).", correctiveAction: missing.isEmpty ? "No action required." : "Repair or reinstall macOS/Xcode command-line components before capture.", evidenceSource: "Executable file checks")
}
