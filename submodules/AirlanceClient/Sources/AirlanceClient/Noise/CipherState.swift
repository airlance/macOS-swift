import Foundation
import CryptoKit

/// `CipherState` из Noise spec §5.1, специализированный под ChaChaPoly.
///
/// ВАЖНО про nonce: Noise spec задаёт nonce как 8-байтовый счётчик,
/// который в проводном формате ChaCha20-Poly1305 кодируется как
/// 4 нулевых байта + 8 байт little-endian counter (см. Noise spec §5.1,
/// "ChaChaPoly" cipher functions: "the 96-bit nonce is formed by encoding
/// 32 bits of zeros followed by little-endian encoding of n"). Это
/// совпадает с тем, что делает `flynn/noise` (и его зависимость
/// `golang.org/x/crypto/chacha20poly1305`), поэтому нужно точно повторить
/// эту раскладку — CryptoKit-шный `ChaChaPoly.Nonce(data:)` принимает
/// произвольные 12 байт, раскладку строим вручную.
final class CipherState {
    private var key: SymmetricKey?
    private var nonce: UInt64 = 0

    init(key: SymmetricKey? = nil) {
        self.key = key
    }

    var hasKey: Bool { key != nil }

    func initializeKey(_ key: SymmetricKey) {
        self.key = key
        self.nonce = 0
    }

    /// Encrypt with associated data. Если ключ не установлен, по Noise spec
    /// EncryptWithAd возвращает plaintext как есть (используется до первого MixKey).
    func encryptWithAd(_ ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        guard let key else { return plaintext }
        let nonceBytes = Self.encodeNonce(nonce)
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: ChaChaPoly.Nonce(data: nonceBytes),
            authenticating: ad
        )
        nonce += 1
        // Combined представление: ciphertext || tag (без nonce — он у нас implicit/counter-based)
        return [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)
    }

    func decryptWithAd(_ ad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard let key else { return ciphertext }
        guard ciphertext.count >= 16 else {
            throw NoiseError.decryptionFailed
        }
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let nonceBytes = Self.encodeNonce(nonce)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonceBytes),
            ciphertext: ct,
            tag: tag
        )
        let plaintext: [UInt8]
        do {
            plaintext = [UInt8](try ChaChaPoly.open(sealedBox, using: key, authenticating: ad))
        } catch {
            throw NoiseError.decryptionFailed
        }
        nonce += 1
        return plaintext
    }

    /// nonce (uint64 counter) -> 12-байтовый ChaCha20-Poly1305 nonce:
    /// 4 нулевых байта + 8 байт little-endian counter.
    private static func encodeNonce(_ n: UInt64) -> Data {
        var data = Data(count: 12)
        data.replaceSubrange(0..<4, with: [0, 0, 0, 0])
        withUnsafeBytes(of: n.littleEndian) { raw in
            data.replaceSubrange(4..<12, with: raw)
        }
        return data
    }
}

enum NoiseError: Error, CustomStringConvertible {
    case decryptionFailed
    case handshakeFailed(String)
    case invalidPublicKey

    var description: String {
        switch self {
        case .decryptionFailed:
            return "noiseik: frame decryption failed (tampered frame or wrong session key)"
        case .handshakeFailed(let reason):
            return "noiseik: handshake failed: \(reason)"
        case .invalidPublicKey:
            return "noiseik: invalid public key"
        }
    }
}
