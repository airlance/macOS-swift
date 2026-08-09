import Foundation
import Security

/// Verifies RSA-PKCS1v15-SHA256 signatures against a pinned server public
/// key. CryptoKit has no RSA support, so this uses the Security framework
/// directly — mirrors Go's `rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sig)`.
enum RSAVerifier {

    /// Loads an RSA public key from a DER-encoded SubjectPublicKeyInfo
    /// blob (i.e. what you get from an `openssl rsa -pubout -outform DER`
    /// export, or by stripping the PEM armor and base64-decoding).
    ///
    /// Distribute this key to the app out of band (bundled resource,
    /// pinned config) — same trust model as the Go client's
    /// `loadRSAPublicKey`. Never derive it from the connection itself.
    static func loadPublicKey(derData: Data) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(derData as CFData, attributes as CFDictionary, &error) else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown SecKey error"
            throw WireAuthError.invalidPeerPublicKey("failed to load RSA public key: \(message)")
        }
        return key
    }

    /// Loads an RSA public key from a PEM string (```-----BEGIN PUBLIC
    /// KEY----- ... -----END PUBLIC KEY-----```, SubjectPublicKeyInfo /
    /// PKCS#8 public form — the standard `openssl rsa -pubout` output).
    static func loadPublicKey(pem: String) throws -> SecKey {
        let lines = pem
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64 = lines.joined()
        guard let der = Data(base64Encoded: base64) else {
            throw WireAuthError.invalidPeerPublicKey("PEM did not decode as base64")
        }
        return try loadPublicKey(derData: der)
    }

    /// Verifies `signature` (RSA-PKCS1v15 over SHA-256(clientNonce ||
    /// serverNonce)) against `publicKey`. Throws `.signatureInvalid` on
    /// any failure — treat that as a fatal, non-retryable handshake
    /// failure (do not fall back to an unauthenticated channel).
    static func verify(
        publicKey: SecKey,
        clientNonce: Data,
        serverNonce: Data,
        signature: Data
    ) throws {
        var message = Data()
        message.append(clientNonce)
        message.append(serverNonce)

        var error: Unmanaged<CFError>?
        let ok = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            signature as CFData,
            &error
        )

        if !ok {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "signature verification failed"
            throw WireAuthError.signatureInvalid(message)
        }
    }
}