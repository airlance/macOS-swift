import CryptoKit
import Foundation
import Security

/// Seals/opens individual AEAD records. Mirrors Go's `encryptRecord` /
/// `decryptRecord` in aead.go exactly:
///
///   record BODY = seq(8, BE) || nonce(12) || ciphertext+tag
///
/// AAD is the 8-byte big-endian seq — NOT the nonce, NOT the record_len
/// prefix (that prefix is transport framing added one layer up, see
/// `WireAuthChannelHandler`).
enum WireAuthAEAD {

    /// Seals `plaintext` into one record body (no record_len prefix —
    /// the caller adds that). `seq` must be unique per (key, direction);
    /// the caller is responsible for a strictly monotonic counter.
    static func encryptRecord(key: SymmetricKey, seq: UInt64, plaintext: Data) throws -> Data {
        let seqData = ByteOrder.uint64BigEndian(seq)

        let nonceBytes = randomBytes(count: WireAuthProtocol.gcmNonceSize)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)

        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: seqData)
        } catch {
            throw WireAuthError.handshakeFailed("AES-GCM seal failed: \(error)")
        }

        // ciphertext+tag as one contiguous blob, matching Go's cipher.AEAD.Seal
        // output layout (ciphertext immediately followed by the 16-byte tag).
        var record = Data(capacity: WireAuthProtocol.seqFieldSize + WireAuthProtocol.gcmNonceSize + sealed.ciphertext.count + WireAuthProtocol.gcmTagSize)
        record.append(seqData)
        record.append(nonceBytes)
        record.append(sealed.ciphertext)
        record.append(sealed.tag)
        return record
    }

    /// Opens a record body produced by `encryptRecord`. Returns the
    /// decrypted plaintext and the seq embedded in the record so the
    /// caller can enforce strict per-direction monotonicity (see
    /// `SecureRecordStream`).
    static func decryptRecord(key: SymmetricKey, record: Data) throws -> (plaintext: Data, seq: UInt64) {
        guard record.count >= WireAuthProtocol.minRecordBodySize else {
            throw WireAuthError.recordTooShort
        }

        let seqRange = 0..<WireAuthProtocol.seqFieldSize
        let nonceRange = WireAuthProtocol.seqFieldSize..<(WireAuthProtocol.seqFieldSize + WireAuthProtocol.gcmNonceSize)
        let cipherRange = (WireAuthProtocol.seqFieldSize + WireAuthProtocol.gcmNonceSize)..<record.count

        let seqData = record.subdata(in: seqRange)
        let seq = ByteOrder.readUInt64BigEndian(seqData)

        let nonceData = record.subdata(in: nonceRange)
        let cipherAndTag = record.subdata(in: cipherRange)

        guard cipherAndTag.count >= WireAuthProtocol.gcmTagSize else {
            throw WireAuthError.recordTooShort
        }
        let tagStart = cipherAndTag.count - WireAuthProtocol.gcmTagSize
        let ciphertext = cipherAndTag.subdata(in: 0..<tagStart)
        let tag = cipherAndTag.subdata(in: tagStart..<cipherAndTag.count)

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: seqData)
            return (plaintext, seq)
        } catch {
            throw WireAuthError.decryptionFailed
        }
    }

    private static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
        return Data(bytes)
    }
}