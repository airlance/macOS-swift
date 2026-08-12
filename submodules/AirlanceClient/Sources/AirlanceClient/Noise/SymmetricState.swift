import Foundation
import CryptoKit

/// `SymmetricState` из Noise spec §5.2, для `Noise_IK_25519_ChaChaPoly_SHA256`.
/// HASHLEN = 32 (SHA256).
final class SymmetricState {
    private var ck: [UInt8] // chaining key, 32 bytes
    private var h: [UInt8]  // hash, 32 bytes
    let cipherState = CipherState()
    private var hasKeyFlag = false

    /// InitializeSymmetric(protocol_name)
    init(protocolName: String) {
        let nameBytes = [UInt8](protocolName.utf8)
        if nameBytes.count <= 32 {
            var padded = nameBytes
            padded.append(contentsOf: [UInt8](repeating: 0, count: 32 - nameBytes.count))
            self.h = padded
        } else {
            self.h = [UInt8](SHA256.hash(data: nameBytes))
        }
        self.ck = self.h
    }

    var handshakeHash: [UInt8] { h }

    func mixHash(_ data: [UInt8]) {
        h = [UInt8](SHA256.hash(data: h + data))
    }

    /// MixKey(input_key_material): HKDF(ck, ikm) -> new ck, temp_k; sets CipherState key.
    func mixKey(_ ikm: [UInt8]) {
        let (newCk, tempK) = hkdf2(chainingKey: ck, ikm: ikm)
        ck = newCk
        let key = truncateOrHashKey(tempK)
        cipherState.initializeKey(SymmetricKey(data: key))
        hasKeyFlag = true
    }

    func mixKeyAndHash(_ ikm: [UInt8]) {
        let (newCk, tempH, tempK) = hkdf3(chainingKey: ck, ikm: ikm)
        ck = newCk
        mixHash(tempH)
        let key = truncateOrHashKey(tempK)
        cipherState.initializeKey(SymmetricKey(data: key))
        hasKeyFlag = true
    }

    func encryptAndHash(_ plaintext: [UInt8]) throws -> [UInt8] {
        let ciphertext = try cipherState.encryptWithAd(h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: [UInt8]) throws -> [UInt8] {
        let plaintext = try cipherState.decryptWithAd(h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    /// Split(): возвращает пару CipherState для send/recv (до определения ролей — cs1, cs2).
    func split() -> (CipherState, CipherState) {
        let (tempK1, tempK2) = hkdf2(chainingKey: ck, ikm: [])
        let cs1 = CipherState()
        cs1.initializeKey(SymmetricKey(data: truncateOrHashKey(tempK1)))
        let cs2 = CipherState()
        cs2.initializeKey(SymmetricKey(data: truncateOrHashKey(tempK2)))
        return (cs1, cs2)
    }

    // MARK: - HKDF per Noise spec §4.3 (HMAC-based, 2 or 3 outputs)

    private func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let hmacKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: hmacKey)
        return [UInt8](mac)
    }

    private func hkdf2(chainingKey: [UInt8], ikm: [UInt8]) -> ([UInt8], [UInt8]) {
        let tempKey = hmacSHA256(key: chainingKey, data: ikm)
        let output1 = hmacSHA256(key: tempKey, data: [0x01])
        let output2 = hmacSHA256(key: tempKey, data: output1 + [0x02])
        return (output1, output2)
    }

    private func hkdf3(chainingKey: [UInt8], ikm: [UInt8]) -> ([UInt8], [UInt8], [UInt8]) {
        let tempKey = hmacSHA256(key: chainingKey, data: ikm)
        let output1 = hmacSHA256(key: tempKey, data: [0x01])
        let output2 = hmacSHA256(key: tempKey, data: output1 + [0x02])
        let output3 = hmacSHA256(key: tempKey, data: output2 + [0x03])
        return (output1, output2, output3)
    }

    /// Noise spec §5.2 MixKey: "If HASHLEN is 64, then truncates temp_k to 32 bytes".
    /// SHA256 -> HASHLEN=32, temp_k уже 32 байта, так что это no-op здесь,
    /// но оставлено явно на случай смены хэша.
    private func truncateOrHashKey(_ tempK: [UInt8]) -> [UInt8] {
        if tempK.count == 32 { return tempK }
        return Array(tempK.prefix(32))
    }
}
