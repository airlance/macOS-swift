import Foundation
import CryptoKit
import Security

/// Хранит статический X25519 keypair устройства в Keychain macOS.
/// Аналог клиентского "device key" из серверного flow: `ConfirmEmailCode`
/// доказывает владение этим ключом через Noise handshake — `Conn.RemoteStaticKey()`
/// на сервере равен публичной части этого keypair'а (см. router.go: `conn.RemoteStaticKey()`
/// передаётся в `usecase.DeviceInfo.PublicKey`).
enum DeviceIdentity {
    private static let keychainService = "com.airlance.client.devicekey"
    private static let keychainAccount = "device-static-x25519"

    /// Загружает существующий ключ из Keychain или генерирует и сохраняет новый.
    static func loadOrCreate() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let existing = try load() {
            return existing
        }
        let newKey = Curve25519.KeyAgreement.PrivateKey()
        try save(newKey)
        return newKey
    }

    private static func load() throws -> Curve25519.KeyAgreement.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandled(status: status)
        }
    }

    private static func save(_ key: Curve25519.KeyAgreement.PrivateKey) throws {
        let data = key.rawRepresentation
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        // Удаляем существующую запись на случай гонки/повторной генерации, затем добавляем.
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status: status)
        }
    }

    enum KeychainError: Error, CustomStringConvertible {
        case unhandled(status: OSStatus)
        var description: String {
            switch self {
            case .unhandled(let status):
                return "airlance: keychain operation failed (OSStatus \(status))"
            }
        }
    }

    // MARK: - Fingerprint

    private static let fingerprintKeychainService = "com.airlance.client.fingerprint"
    private static let fingerprintKeychainAccount = "device-fingerprint"

    /// Стабильный отпечаток установки — отдельный от криптографического
    /// device key (`loadOrCreate()`). Используется сервером как
    /// UX/дедупликация устройства (`ConfirmEmailCode.deviceFingerprint`,
    /// `DeviceInfo.Fingerprint` в GitHub OAuth flow, см.
    /// `internal/usecase/device_upsert.go`, `upsertDevice`).
    ///
    /// В отличие от device key это не криптографический материал — просто
    /// случайный UUID, сгенерированный один раз и переживающий переустановки
    /// в рамках того же Keychain (но НЕ привязанный к Noise identity: если
    /// два разных device key используют один и тот же fingerprint, сервер
    /// матчит по fingerprint первым — см. `upsertDevice`).
    public static func fingerprint() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: fingerprintKeychainService,
            kSecAttrAccount as String: fingerprintKeychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
                return try generateAndSaveFingerprint()
            }
            return value
        case errSecItemNotFound:
            return try generateAndSaveFingerprint()
        default:
            throw KeychainError.unhandled(status: status)
        }
    }

    private static func generateAndSaveFingerprint() throws -> String {
        let value = UUID().uuidString
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: fingerprintKeychainService,
            kSecAttrAccount as String: fingerprintKeychainAccount,
        ]
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = Data(value.utf8)
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status: status)
        }
        return value
    }
}

/// Хранит существующие `session_id` в Keychain macOS, привязанные к серверному
/// host'у (на случай нескольких окружений — dev/staging/prod с разными БД).
enum SessionStore {
    private static let keychainService = "com.airlance.client.session"

    static func load(host: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: host,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, let sessionID = String(data: data, encoding: .utf8) else { return nil }
            return sessionID
        case errSecItemNotFound:
            return nil
        default:
            throw DeviceIdentity.KeychainError.unhandled(status: status)
        }
    }

    static func save(host: String, sessionID: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: host,
        ]
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = Data(sessionID.utf8)
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceIdentity.KeychainError.unhandled(status: status)
        }
    }

    static func clear(host: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: host,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

enum HexCodec {
    static func decode(_ hex: String) throws -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw DecodeError.invalidHex
            }
            result.append(byte)
            index = next
        }
        return result
    }

    static func encode(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    enum DecodeError: Error { case invalidHex }
}
