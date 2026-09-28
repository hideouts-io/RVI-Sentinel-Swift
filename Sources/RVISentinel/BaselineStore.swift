import Foundation

struct BaselineStore: Sendable {
    func load(url: URL) throws -> BaselineDocument {
        try validateBaselineURL(url)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw BaselineStoreError.missingFile(url.path)
        }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document: BaselineDocument
        do {
            document = try decoder.decode(BaselineDocument.self, from: data)
        } catch {
            throw BaselineStoreError.invalidDocument(error.localizedDescription)
        }
        try validateBaselineDocument(document)
        return document
    }

    func create(url: URL, scopeName: String, createdAt: Date) throws -> BaselineDocument {
        try validateBaselineURL(url)
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw BaselineStoreError.destinationExists(url.path)
        }
        let document = try emptyBaseline(scopeName: scopeName, createdAt: createdAt)
        try write(document: document, url: url)
        return document
    }

    func update(url: URL, result: NativeAnalysisResult, reviewedAt: Date) throws -> (document: BaselineDocument, backupURL: URL) {
        let existing = try load(url: url)
        let updated = mergedBaseline(document: existing, result: result, reviewedAt: reviewedAt)
        let backupURL = try backup(url: url, createdAt: reviewedAt)
        try write(document: updated, url: url)
        return (updated, backupURL)
    }

    func reset(url: URL, resetAt: Date) throws -> (document: BaselineDocument, backupURL: URL) {
        let existing = try load(url: url)
        let backupURL = try backup(url: url, createdAt: resetAt)
        let resetDocument = try emptyBaseline(scopeName: existing.scopeName, createdAt: resetAt)
        try write(document: resetDocument, url: url)
        return (resetDocument, backupURL)
    }

    func exportCopy(document: BaselineDocument, destinationURL: URL) throws {
        try validateBaselineURL(destinationURL)
        guard !FileManager.default.fileExists(atPath: destinationURL.path) else {
            throw BaselineStoreError.destinationExists(destinationURL.path)
        }
        try write(document: document, url: destinationURL)
    }

    private func backup(url: URL, createdAt: Date) throws -> URL {
        let timestamp = filenameTimestamp(date: createdAt)
        let backupURL = url.deletingPathExtension()
            .appendingPathExtension("backup-\(timestamp)-\(UUID().uuidString.prefix(8)).json")
        try FileManager.default.copyItem(at: url, to: backupURL)
        return backupURL
    }

    private func write(document: BaselineDocument, url: URL) throws {
        try validateBaselineDocument(document)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(document)
        try data.write(to: url, options: .atomic)
    }
}

func validateBaselineURL(_ url: URL) throws {
    guard url.pathExtension.lowercased() == "json" else {
        throw BaselineStoreError.invalidExtension(url.path)
    }
}

func validateBaselineDocument(_ document: BaselineDocument) throws {
    guard document.schemaVersion == 1 else {
        throw BaselineStoreError.unsupportedSchema(document.schemaVersion)
    }
    guard !document.scopeName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw BaselineStoreError.invalidName
    }
    guard document.capturesReviewed >= 0 else {
        throw BaselineStoreError.invalidDocument("capturesReviewed cannot be negative")
    }
    var identities = Set<String>()
    for observation in document.observations {
        guard observation.reviewedCaptures > 0 else {
            throw BaselineStoreError.invalidDocument("reviewedCaptures must be positive for \(observation.id)")
        }
        guard identities.insert(observation.id).inserted else {
            throw BaselineStoreError.duplicateObservation(observation.id)
        }
    }
}

func filenameTimestamp(date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.calendar = Calendar(identifier: .gregorian)
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    return formatter.string(from: date)
}
