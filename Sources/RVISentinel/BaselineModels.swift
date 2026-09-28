import Foundation

enum BaselineEntityKind: String, CaseIterable, Codable, Identifiable, Sendable {
    case endpoint = "Endpoint"
    case hostname = "Hostname evidence"
    case protocolKind = "Protocol"
    case port = "Port"

    var id: String { rawValue }
}

enum BaselineChangeState: String, CaseIterable, Codable, Identifiable, Sendable {
    case new = "New"
    case known = "Known"
    case changed = "Changed"
    case removed = "Removed"

    var id: String { rawValue }
}

struct BaselineObservation: Codable, Equatable, Identifiable, Sendable {
    let kind: BaselineEntityKind
    let identity: String
    let title: String
    let signature: String
    let summary: String
    let firstSeen: Date
    let lastSeen: Date
    let reviewedCaptures: Int

    var id: String { "\(kind.rawValue)|\(identity)" }
}

struct BaselineCaptureReference: Codable, Equatable, Identifiable, Sendable {
    let sha256: String
    let reviewedAt: Date
    let packetCount: Int

    var id: String { sha256 }
}

struct BaselineDocument: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let scopeName: String
    let createdAt: Date
    let updatedAt: Date
    let capturesReviewed: Int
    let observations: [BaselineObservation]
    let captures: [BaselineCaptureReference]
}

struct BaselineDifference: Equatable, Identifiable, Sendable {
    let kind: BaselineEntityKind
    let identity: String
    let title: String
    let state: BaselineChangeState
    let previousSummary: String?
    let currentSummary: String?

    var id: String { "\(kind.rawValue)|\(identity)" }
}

struct BaselineComparison: Equatable, Sendable {
    let differences: [BaselineDifference]

    func count(state: BaselineChangeState) -> Int {
        differences.count { $0.state == state }
    }
}

enum BaselineStoreError: LocalizedError {
    case invalidName
    case invalidExtension(String)
    case missingFile(String)
    case destinationExists(String)
    case unsupportedSchema(Int)
    case duplicateObservation(String)
    case invalidDocument(String)

    var errorDescription: String? {
        switch self {
        case .invalidName:
            "Enter a baseline name that identifies one device or investigation."
        case let .invalidExtension(path):
            "Baseline files must use the .json extension: \(path)"
        case let .missingFile(path):
            "The baseline file does not exist: \(path)"
        case let .destinationExists(path):
            "The destination already exists and will not be overwritten: \(path)"
        case let .unsupportedSchema(version):
            "Baseline schema version \(version) is not supported by this app."
        case let .duplicateObservation(identity):
            "The baseline contains a duplicate observation identity: \(identity)"
        case let .invalidDocument(detail):
            "The baseline is invalid: \(detail)"
        }
    }
}

func emptyBaseline(scopeName: String, createdAt: Date) throws -> BaselineDocument {
    let normalizedName = scopeName.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedName.isEmpty else { throw BaselineStoreError.invalidName }
    return BaselineDocument(
        schemaVersion: 1,
        scopeName: normalizedName,
        createdAt: createdAt,
        updatedAt: createdAt,
        capturesReviewed: 0,
        observations: [],
        captures: []
    )
}

func baselineObservations(result: NativeAnalysisResult, observedAt: Date) -> [BaselineObservation] {
    let endpoints = result.endpoints.map { endpoint in
        let protocols = endpoint.protocols.map(\.rawValue).sorted().joined(separator: ", ")
        let ports = endpoint.ports.sorted().joined(separator: ", ")
        let summary = "\(endpoint.classification); protocols: \(protocols.isEmpty ? "none identified" : protocols); ports: \(ports.isEmpty ? "none observed" : ports)"
        return BaselineObservation(
            kind: .endpoint,
            identity: endpoint.address,
            title: endpoint.address,
            signature: "\(endpoint.classification)|\(protocols)|\(ports)",
            summary: summary,
            firstSeen: endpoint.firstSeen,
            lastSeen: endpoint.lastSeen,
            reviewedCaptures: 1
        )
    }
    let hostnames = result.hostnames.map { hostname in
        let address = hostname.address ?? "no related address"
        let enrichment = hostname.isPostCaptureEnrichment ? "post-capture enrichment" : "captured evidence"
        let summary = "\(hostname.provenance.rawValue); \(address); \(enrichment)"
        return BaselineObservation(
            kind: .hostname,
            identity: hostname.id,
            title: hostname.hostname,
            signature: "\(hostname.provenance.rawValue)|\(address)|\(hostname.confidence.rawValue)|\(hostname.isPostCaptureEnrichment)",
            summary: summary,
            firstSeen: hostname.firstSeen,
            lastSeen: hostname.lastSeen,
            reviewedCaptures: 1
        )
    }
    let protocols = result.protocols.map { observation in
        BaselineObservation(
            kind: .protocolKind,
            identity: observation.protocolKind.rawValue,
            title: observation.protocolKind.rawValue,
            signature: observation.identification,
            summary: observation.identification,
            firstSeen: observedAt,
            lastSeen: observedAt,
            reviewedCaptures: 1
        )
    }
    let ports = result.ports.map { port in
        let identity = "\(port.transport)|\(port.port)"
        let summary = "\(port.transport) \(port.port); \(port.standardService); \(port.explanation)"
        return BaselineObservation(
            kind: .port,
            identity: identity,
            title: "\(port.transport) \(port.port) — \(port.standardService)",
            signature: "\(port.standardService)|\(port.explanation)|\(port.evidenceBoundary)",
            summary: summary,
            firstSeen: observedAt,
            lastSeen: observedAt,
            reviewedCaptures: 1
        )
    }
    return (endpoints + hostnames + protocols + ports).sorted {
        $0.kind.rawValue == $1.kind.rawValue ? $0.identity < $1.identity : $0.kind.rawValue < $1.kind.rawValue
    }
}

func compareBaseline(document: BaselineDocument, result: NativeAnalysisResult, comparedAt: Date) -> BaselineComparison {
    let current = baselineObservations(result: result, observedAt: comparedAt)
    let previousByID = Dictionary(uniqueKeysWithValues: document.observations.map { ($0.id, $0) })
    let currentByID = Dictionary(uniqueKeysWithValues: current.map { ($0.id, $0) })
    var differences: [BaselineDifference] = current.map { observation in
        guard let previous = previousByID[observation.id] else {
            return BaselineDifference(
                kind: observation.kind,
                identity: observation.identity,
                title: observation.title,
                state: .new,
                previousSummary: nil,
                currentSummary: observation.summary
            )
        }
        return BaselineDifference(
            kind: observation.kind,
            identity: observation.identity,
            title: observation.title,
            state: previous.signature == observation.signature ? .known : .changed,
            previousSummary: previous.summary,
            currentSummary: observation.summary
        )
    }
    differences.append(contentsOf: document.observations.compactMap { observation in
        guard currentByID[observation.id] == nil else { return nil }
        return BaselineDifference(
            kind: observation.kind,
            identity: observation.identity,
            title: observation.title,
            state: .removed,
            previousSummary: observation.summary,
            currentSummary: nil
        )
    })
    differences.sort {
        if $0.state.rawValue != $1.state.rawValue { return $0.state.rawValue < $1.state.rawValue }
        if $0.kind.rawValue != $1.kind.rawValue { return $0.kind.rawValue < $1.kind.rawValue }
        return $0.title < $1.title
    }
    return BaselineComparison(differences: differences)
}

func mergedBaseline(document: BaselineDocument, result: NativeAnalysisResult, reviewedAt: Date) -> BaselineDocument {
    let current = baselineObservations(result: result, observedAt: reviewedAt)
    let currentByID = Dictionary(uniqueKeysWithValues: current.map { ($0.id, $0) })
    var merged = document.observations.map { existing in
        guard let observation = currentByID[existing.id] else { return existing }
        return BaselineObservation(
            kind: observation.kind,
            identity: observation.identity,
            title: observation.title,
            signature: observation.signature,
            summary: observation.summary,
            firstSeen: min(existing.firstSeen, observation.firstSeen),
            lastSeen: max(existing.lastSeen, observation.lastSeen),
            reviewedCaptures: existing.reviewedCaptures + 1
        )
    }
    let existingIDs = Set(document.observations.map(\.id))
    merged.append(contentsOf: current.filter { !existingIDs.contains($0.id) })
    merged.sort {
        $0.kind.rawValue == $1.kind.rawValue ? $0.identity < $1.identity : $0.kind.rawValue < $1.kind.rawValue
    }
    let captureReference = BaselineCaptureReference(
        sha256: result.summary.captureSHA256,
        reviewedAt: reviewedAt,
        packetCount: result.summary.packetCount
    )
    let captures = document.captures.contains(where: { $0.sha256 == captureReference.sha256 })
        ? document.captures
        : document.captures + [captureReference]
    return BaselineDocument(
        schemaVersion: document.schemaVersion,
        scopeName: document.scopeName,
        createdAt: document.createdAt,
        updatedAt: reviewedAt,
        capturesReviewed: document.capturesReviewed + 1,
        observations: merged,
        captures: captures
    )
}
