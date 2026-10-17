import Darwin
import Foundation
import OSLog
import SQLite3

enum PacketStorageError: LocalizedError {
    case database(operation: String, code: Int32)
    case invalidValue(String)
    case unavailable
    case serialization

    var errorDescription: String? {
        switch self {
        case let .database(operation, code):
            "Local packet storage could not \(operation) (SQLite \(code)). Check available disk space and the temporary folder's permissions, then retry the original capture."
        case let .invalidValue(field): "Local packet storage contains an invalid \(field). Reanalyze the original capture."
        case .unavailable: "The local packet index is unavailable. Reanalyze the original capture."
        case .serialization: "A disk-backed packet index cannot be embedded in JSON. Use the existing report export to save the analysis summary, and retain the original capture."
        }
    }
}

private let packetStorageLogger = Logger(subsystem: "io.hideouts.RVISentinel", category: "PacketStorage")

/// Owns only a uniquely created private temporary directory. A result keeps its index alive
/// while it is selected or retained in the import queue; dropping that result removes the index.
final class PacketStorageFiles: Sendable, Equatable {
    let directory: URL
    let database: URL

    init() throws {
        let temporaryPath = FileManager.default.temporaryDirectory.path
        guard let canonical = Darwin.realpath(temporaryPath, nil) else {
            throw CaptureEvidenceError.inspectionFailed(path: temporaryPath, code: errno)
        }
        let root = URL(fileURLWithPath: String(cString: canonical), isDirectory: true)
        free(canonical)
        directory = root.appendingPathComponent("rvi-packet-index-\(UUID().uuidString)", isDirectory: true)
        database = directory.appendingPathComponent("packets.sqlite")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            let descriptor = open(database.path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard descriptor >= 0 else { throw CaptureEvidenceError.openFailed(path: database.path, code: errno) }
            guard Darwin.close(descriptor) == 0 else { throw CaptureEvidenceError.inspectionFailed(path: database.path, code: errno) }
        } catch {
            let primary = error
            do { try FileManager.default.removeItem(at: directory) }
            catch { throw BoundedDecoderCleanupError(primaryFailure: primary, cleanupFailure: .cleanupFailed(executable: "packet index creation", failures: [error.localizedDescription])) }
            throw primary
        }
    }

    deinit {
        do { try FileManager.default.removeItem(at: directory) }
        catch {
            // Deinitializers cannot throw. Report cleanup failure without disclosing the path.
            packetStorageLogger.error("Private packet index cleanup failed; error code: \((error as NSError).code)")
        }
    }

    static func == (left: PacketStorageFiles, right: PacketStorageFiles) -> Bool { left.database == right.database }
}

enum PacketSQLValue {
    case integer(Int64)
    case text(String)
    case bytes(Data)
    case null
}

/// A synchronous connection is confined to its calling actor/task. Readers open their own
/// read-only connections; no SQLite handle or statement crosses a concurrency boundary.
final class PacketDatabase {
    private var handle: OpaquePointer?
    private var statements: [String: OpaquePointer] = [:]
    let files: PacketStorageFiles

    init(files: PacketStorageFiles, access: PacketDatabaseAccess) throws {
        self.files = files
        let flags: Int32 = (access == .read ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE) | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_FULLMUTEX
        let status = sqlite3_open_v2(files.database.path, &handle, flags, nil)
        guard status == SQLITE_OK else {
            if let handle { sqlite3_close_v2(handle) }
            handle = nil
            throw PacketStorageError.database(operation: "open the packet index", code: status)
        }
        sqlite3_progress_handler(handle, 1_000, { _ in Task<Never, Never>.isCancelled ? 1 : 0 }, nil)
        try execute("PRAGMA trusted_schema=OFF", values: [])
        try execute("PRAGMA cache_size=-8192", values: [])
        try execute("PRAGMA temp_store=FILE", values: [])
        try execute("PRAGMA mmap_size=0", values: [])
    }

    deinit {
        for statement in statements.values {
            let code = sqlite3_finalize(statement)
            if code != SQLITE_OK { packetStorageLogger.error("Packet statement cleanup failed; SQLite code: \(code)") }
        }
        if let handle {
            let code = sqlite3_close_v2(handle)
            if code != SQLITE_OK { packetStorageLogger.error("Packet connection cleanup failed; SQLite code: \(code)") }
        }
    }

    func close() throws {
        var failure: Int32?
        for statement in statements.values {
            let code = sqlite3_finalize(statement)
            if code != SQLITE_OK { failure = code }
        }
        statements.removeAll()
        if let handle {
            let code = sqlite3_close(handle)
            if code == SQLITE_OK { self.handle = nil } else { failure = code }
        }
        if let failure { throw PacketStorageError.database(operation: "close the packet index", code: failure) }
    }

    func execute(_ sql: String, values: [PacketSQLValue]) throws {
        try rows(sql, values: values) { _ in }
    }

    func rows(_ sql: String, values: [PacketSQLValue], consume: (PacketDatabaseRow) throws -> Void) throws {
        try Task.checkCancellation()
        guard let handle else { throw PacketStorageError.unavailable }
        let statement: OpaquePointer
        if let cached = statements[sql] { statement = cached }
        else {
            var prepared: OpaquePointer?
            let status = sqlite3_prepare_v2(handle, sql, -1, &prepared, nil)
            guard status == SQLITE_OK, let prepared else {
                throw PacketStorageError.database(operation: "prepare a packet query", code: status)
            }
            statement = prepared
            statements[sql] = statement
        }
        defer {
            sqlite3_reset(statement)
            sqlite3_clear_bindings(statement)
        }
        for (offset, value) in values.enumerated() { try bind(value, at: Int32(offset + 1), statement: statement) }
        while true {
            try Task.checkCancellation()
            let status = sqlite3_step(statement)
            if status == SQLITE_DONE { return }
            guard status == SQLITE_ROW else {
                if status == SQLITE_INTERRUPT { try Task.checkCancellation() }
                throw PacketStorageError.database(operation: "read or write packet data", code: status)
            }
            try consume(PacketDatabaseRow(statement: statement))
        }
    }

    func integer(_ sql: String, values: [PacketSQLValue]) throws -> Int64 {
        var value: Int64?
        try rows(sql, values: values) { row in value = try row.integer(0) }
        guard let value else { throw PacketStorageError.invalidValue("count") }
        return value
    }

    private func bind(_ value: PacketSQLValue, at index: Int32, statement: OpaquePointer) throws {
        let status: Int32
        switch value {
        case let .integer(integer): status = sqlite3_bind_int64(statement, index, integer)
        case let .text(text):
            let bytes = Data(text.utf8)
            guard bytes.count < Int(Int32.max), let allocated = sqlite3_malloc64(UInt64(bytes.count + 1)) else {
                throw PacketStorageError.database(operation: "allocate a query value", code: SQLITE_NOMEM)
            }
            let chars = allocated.bindMemory(to: CChar.self, capacity: bytes.count + 1)
            bytes.withUnsafeBytes { source in if let base = source.baseAddress { allocated.copyMemory(from: base, byteCount: bytes.count) } }
            chars[bytes.count] = 0
            status = sqlite3_bind_text(statement, index, chars, Int32(bytes.count), { sqlite3_free($0) })
        case let .bytes(bytes):
            guard bytes.count < Int(Int32.max), let allocated = sqlite3_malloc64(UInt64(max(1, bytes.count))) else {
                throw PacketStorageError.database(operation: "allocate a packet value", code: SQLITE_NOMEM)
            }
            bytes.withUnsafeBytes { source in if let base = source.baseAddress { allocated.copyMemory(from: base, byteCount: bytes.count) } }
            status = sqlite3_bind_blob(statement, index, allocated, Int32(bytes.count), { sqlite3_free($0) })
        case .null: status = sqlite3_bind_null(statement, index)
        }
        guard status == SQLITE_OK else { throw PacketStorageError.database(operation: "bind a packet query", code: status) }
    }
}

enum PacketDatabaseAccess { case read, write }

struct PacketDatabaseRow {
    let statement: OpaquePointer

    func integer(_ column: Int32) throws -> Int64 {
        guard sqlite3_column_type(statement, column) == SQLITE_INTEGER else { throw PacketStorageError.invalidValue("integer") }
        return sqlite3_column_int64(statement, column)
    }

    func optionalInteger(_ column: Int32) throws -> Int64? {
        sqlite3_column_type(statement, column) == SQLITE_NULL ? nil : try integer(column)
    }

    func optionalText(_ column: Int32) throws -> String? {
        sqlite3_column_type(statement, column) == SQLITE_NULL ? nil : try text(column)
    }

    func text(_ column: Int32) throws -> String {
        guard sqlite3_column_type(statement, column) == SQLITE_TEXT,
              let pointer = sqlite3_column_text(statement, column) else { throw PacketStorageError.invalidValue("text") }
        let data = Data(bytes: pointer, count: Int(sqlite3_column_bytes(statement, column)))
        guard let value = String(data: data, encoding: .utf8) else { throw PacketStorageError.invalidValue("UTF-8 text") }
        return value
    }

    func bytes(_ column: Int32) throws -> Data {
        guard sqlite3_column_type(statement, column) == SQLITE_BLOB else { throw PacketStorageError.invalidValue("packet bytes") }
        let count = Int(sqlite3_column_bytes(statement, column))
        guard count > 0, let pointer = sqlite3_column_blob(statement, column) else { throw PacketStorageError.invalidValue("empty packet bytes") }
        return Data(bytes: pointer, count: count)
    }
}

func withPacketDatabase<Value>(files: PacketStorageFiles, access: PacketDatabaseAccess, operation: (PacketDatabase) throws -> Value) throws -> Value {
    let connection = try PacketDatabase(files: files, access: access)
    let value: Value
    do { value = try operation(connection) }
    catch {
        let primary = error
        do { try connection.close() }
        catch { throw BoundedDecoderCleanupError(primaryFailure: primary, cleanupFailure: .cleanupFailed(executable: "packet index", failures: [error.localizedDescription])) }
        throw primary
    }
    try connection.close()
    return value
}
