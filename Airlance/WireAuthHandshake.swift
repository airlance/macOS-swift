import CryptoKit // swift-crypto (CryptoKit-compatible API), needed for P256 ECDH on non-Apple-only targets; on Apple platforms this re-exports CryptoKit types.
import Foundation
import Security

/// Result of a completed handshake: everything the AEAD record layer
/// needs. `aesKey` must be handled like any other secret — never logged.
struct WireAuthHandshakeResult {
    let aesKey: SymmetricKey       // 32 bytes, AES-256-GCM key
    let serverNonce: Data          // 16 bytes
    let clientNonce: Data          // 16 bytes
}

/// Runs the client side of the wireauthgrpc handshake over a raw byte
/// stream. `write`/`readExactly` are injected so this same logic can run
/// either directly against a socket (for standalone testing) or against
/// the NIO channel via `WireAuthChannelHandler` (see that file for how
/// handshake I/O is bridged into NIO's promise-based writes and buffered
/// reads).
///
/// This mirrors Go's `clientHandshake` / `clientStage1` / `clientStage2`
/// in handshake.go byte-for-byte. Any deviation in field order, sizes, or
/// the KDF concatenation order breaks interop silently (the peer's GCM
/// `Open` just starts failing with no useful diagnostic).
enum WireAuthClientHandshake {

    /// Performs the full two-stage handshake and returns the derived
    /// session key. `serverPublicKey` must be the pinned RSA public key
    /// distributed with the app (see `RSAVerifier.loadPublicKey`).
    static func run(
        serverPublicKey: SecKey,
        write: @escaping (Data) async throws -> Void,
        readExactly: @escaping (Int) async throws -> Data
    ) async throws -> WireAuthHandshakeResult {
        let (clientNonce, serverNonce) = try await stage1(
            serverPublicKey: serverPublicKey,
            write: write,
            readExactly: readExactly
        )
        let aesKey = try await stage2(
            clientNonce: clientNonce,
            serverNonce: serverNonce,
            write: write,
            readExactly: readExactly
        )
        return WireAuthHandshakeResult(aesKey: aesKey, serverNonce: serverNonce, clientNonce: clientNonce)
    }

    // MARK: - Stage 1: RSA challenge/response

    private static func stage1(
        serverPublicKey: SecKey,
        write: @escaping (Data) async throws -> Void,
        readExactly: @escaping (Int) async throws -> Data
    ) async throws -> (clientNonce: Data, serverNonce: Data) {
        let clientNonce = randomBytes(count: WireAuthProtocol.nonceSize)

        // offset 0, size 4  : cmd (u32 LE, = cmd1)
        // offset 4, size 16 : client_nonce
        var msg = Data(capacity: WireAuthProtocol.stage1ClientMsgSize)
        msg.append(ByteOrder.uint32LittleEndian(WireAuthProtocol.cmd1))
        msg.append(clientNonce)
        try await write(msg)

        // offset 0, size 16  : server_nonce
        // offset 16, size 256: signature
        let resp = try await readExactly(WireAuthProtocol.stage1ServerMsgSize)
        let serverNonce = resp.subdata(in: 0..<WireAuthProtocol.nonceSize)
        let signature = resp.subdata(in: WireAuthProtocol.nonceSize..<resp.count)

        try RSAVerifier.verify(
            publicKey: serverPublicKey,
            clientNonce: clientNonce,
            serverNonce: serverNonce,
            signature: signature
        )

        return (clientNonce, serverNonce)
    }

    // MARK: - Stage 2: ECDH key exchange

    private static func stage2(
        clientNonce: Data,
        serverNonce: Data,
        write: @escaping (Data) async throws -> Void,
        readExactly: @escaping (Int) async throws -> Data
    ) async throws -> SymmetricKey {
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        // x963Representation is the uncompressed point format: 0x04 || X || Y (65 bytes) — matches Go's ecdh.PublicKey.Bytes() for P-256.
        let clientPublicBytes = clientPrivateKey.publicKey.x963Representation
        precondition(clientPublicBytes.count == WireAuthProtocol.ecdhPubKeySize)

        // offset 0, size 4  : cmd (u32 LE, = cmd2)
        // offset 4, size 65 : client_pubkey (uncompressed P-256 point)
        var msg = Data(capacity: WireAuthProtocol.stage2ClientMsgSize)
        msg.append(ByteOrder.uint32LittleEndian(WireAuthProtocol.cmd2))
        msg.append(clientPublicBytes)
        try await write(msg)

        // offset 0, size 65: server_pubkey (same format)
        let resp = try await readExactly(WireAuthProtocol.stage2ServerMsgSize)

        let serverPublicKey: P256.KeyAgreement.PublicKey
        do {
            serverPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: resp)
        } catch {
            throw WireAuthError.invalidPeerPublicKey("server ECDH public key: \(error)")
        }

        let sharedSecret: SharedSecret
        do {
            sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        } catch {
            throw WireAuthError.handshakeFailed("ECDH failed: \(error)")
        }

        return deriveSessionKey(sharedSecret: sharedSecret, clientNonce: clientNonce, serverNonce: serverNonce)
    }

    // MARK: - KDF

    /// session_key = SHA256(shared_secret || client_nonce || server_nonce)
    ///
    /// Concatenation order is part of the frozen wire contract — do not
    /// reorder these without a matching server-side change.
    private static func deriveSessionKey(sharedSecret: SharedSecret, clientNonce: Data, serverNonce: Data) -> SymmetricKey {
        var data = Data()
        sharedSecret.withUnsafeBytes { rawBuf in
            data.append(contentsOf: rawBuf)
        }
        data.append(clientNonce)
        data.append(serverNonce)
        let digest = SHA256.hash(data: data)
        return SymmetricKey(data: Data(digest))
    }

    // MARK: - Helpers

    private static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        // SecRandomCopyBytes is the standard CSPRNG source on Apple platforms.
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
        return Data(bytes)
    }
}