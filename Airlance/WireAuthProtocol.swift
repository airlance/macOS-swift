import Foundation

/// Wire protocol constants mirroring the Go implementation exactly.
///
/// Source of truth: `internal/infrastructure/wireauthgrpc/protocol.go` in
/// the airlance server repo. These values are a **frozen contract** — do
/// not change any of them without a corresponding change on the server
/// side, or every handshake / AEAD open will fail silently on a mismatch.
///
/// Protocol layout (see server's README.md "Protocol invariants"):
///
/// Stage 1 — client -> server:
///   offset 0, size 4  : cmd            (u32 LE, always cmd1)
///   offset 4, size 16 : client_nonce   (random)
/// Stage 1 — server -> client:
///   offset 0, size 16  : server_nonce  (random)
///   offset 16, size 256: signature     (RSA-PKCS1v15-SHA256 over client_nonce||server_nonce)
///
/// Stage 2 — client -> server:
///   offset 0, size 4  : cmd            (u32 LE, always cmd2)
///   offset 4, size 65 : client_pubkey  (ECDH P-256 uncompressed, 0x04||X||Y)
/// Stage 2 — server -> client:
///   offset 0, size 65 : server_pubkey  (same format)
///
/// KDF: session_key = SHA256(shared_secret || client_nonce || server_nonce)
///
/// AEAD record (post-handshake, either direction):
///   offset 0, size 4   : record_len    (u32 BE) — length of everything after this field
///   offset 4, size 8   : seq           (u64 BE)
///   offset 12, size 12 : nonce         (random, per-record)
///   offset 24, size N  : ciphertext+tag (AES-256-GCM, AAD = seq bytes, NOT record_len)
enum WireAuthProtocol {
    static let cmd1: UInt32 = 1
    static let cmd2: UInt32 = 2

    static let nonceSize = 16          // client_nonce / server_nonce
    static let rsaSigSize = 256        // RSA-2048 PKCS1v15 signature
    static let ecdhPubKeySize = 65     // uncompressed P-256 point: 0x04 || X(32) || Y(32)
    static let aesKeySize = 32         // AES-256
    static let gcmNonceSize = 12
    static let gcmTagSize = 16
    static let seqFieldSize = 8
    static let cmdFieldSize = 4
    static let lenFieldSize = 4        // record_len prefix on the wire

    /// Bounds record_len to reject obviously-bogus or hostile length
    /// prefixes before allocating a buffer for them. Must stay >=
    /// maxRecordPlaintext + GCM overhead.
    static let maxRecordLen = 1 << 20  // 1 MiB

    static let stage1ClientMsgSize = cmdFieldSize + nonceSize          // 20
    static let stage1ServerMsgSize = nonceSize + rsaSigSize            // 272
    static let stage2ClientMsgSize = cmdFieldSize + ecdhPubKeySize     // 69
    static let stage2ServerMsgSize = ecdhPubKeySize                    // 65

    /// seq + nonce + tag, with zero-length plaintext — the minimum
    /// possible value of record_len (everything after the 4-byte length
    /// prefix).
    static let minRecordBodySize = seqFieldSize + gcmNonceSize + gcmTagSize

    /// Bounds a single AEAD record's plaintext size; large writes from
    /// the layer above are chunked into records no bigger than this,
    /// matching the Go side's `maxRecordPlaintext` so record_len never
    /// approaches maxRecordLen in ordinary operation.
    static let maxRecordPlaintext = 16 * 1024  // 16 KiB
}

enum WireAuthError: Error, Equatable {
    case handshakeFailed(String)
    case unexpectedCommand(got: UInt32, want: UInt32)
    case signatureInvalid(String)
    case invalidPeerPublicKey(String)
    case decryptionFailed
    case recordTooShort
    case recordLengthOutOfBounds(got: UInt32)
    case seqMismatch(got: UInt64, want: UInt64)
    case seqOverflow
    case connectionClosed
}