import Foundation
import CryptoKit

/// `HandshakeState` из Noise spec §5.3, специализированный под паттерн `IK`
/// с ролью initiator (наш клиент). Токены (Noise spec §7.5, паттерн IK):
///
/// ```
/// IK:
///   <- s
///   ...
///   -> e, es, s, ss
///   <- e, ee, se
/// ```
///
/// Сервер уже знает свой pre-message static key внутри протокола — на клиенте
/// это pinned `serverStaticPublicKey`, передаваемый через init.
/// Зеркало Go: `internal/noiseik/noiseik.go` (`ClientHandshake`), которое использует
/// `github.com/flynn/noise` с `noise.HandshakeIK`.
final class HandshakeState {
    private let symmetricState: SymmetricState
    private let staticKeypair: Curve25519.KeyAgreement.PrivateKey
    private var localEphemeral: Curve25519.KeyAgreement.PrivateKey?
    private let remoteStaticPublicKey: Curve25519.KeyAgreement.PublicKey

    /// `Noise_IK_25519_ChaChaPoly_SHA256` — 24 байта до паддинга нулями до 32,
    /// см. `SymmetricState.init(protocolName:)`.
    private static let protocolName = "Noise_IK_25519_ChaChaPoly_SHA256"

    init(staticKeypair: Curve25519.KeyAgreement.PrivateKey, remoteStaticPublicKey: Curve25519.KeyAgreement.PublicKey) {
        self.symmetricState = SymmetricState(protocolName: Self.protocolName)
        self.staticKeypair = staticKeypair
        self.remoteStaticPublicKey = remoteStaticPublicKey

        // Pre-message: initiator знает responder static key ("<- s" в нотации выше).
        // MixHash(rs.public_key) — как того требует Noise spec §5.3 для pre-message.
        symmetricState.mixHash([])
        symmetricState.mixHash([UInt8](remoteStaticPublicKey.rawRepresentation))
    }

    /// Формирует message 1 (initiator -> responder): e, es, s, ss.
    /// Возвращает сырые байты handshake-сообщения (payload всегда nil/пустой,
    /// как и в серверной реализации — 0-RTT payload сознательно не используется).
    func writeMessage1() throws -> [UInt8] {
        var message: [UInt8] = []

        // Token: e
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        localEphemeral = ephemeral
        let ePub = [UInt8](ephemeral.publicKey.rawRepresentation)
        message.append(contentsOf: ePub)
        symmetricState.mixHash(ePub)
        print("DEBUG ephemeral.rawRepresentation (private):", ephemeral.rawRepresentation.map { String(format: "%02x", $0) }.joined())
        print("DEBUG ephemeral.publicKey:", ePub.map { String(format: "%02x", $0) }.joined())

        // Token: es — DH(e, rs)
        let esShared = try ephemeral.sharedSecretFromKeyAgreement(with: remoteStaticPublicKey)
        print("DEBUG esShared:", esShared.rawBytes.map { String(format: "%02x", $0) }.joined())
        symmetricState.mixKey(esShared.rawBytes)

        // Token: s — encrypted static key
        let sPub = [UInt8](staticKeypair.publicKey.rawRepresentation)
        let encryptedS = try symmetricState.encryptAndHash(sPub)
        message.append(contentsOf: encryptedS)
        print("DEBUG staticKeypair.rawRepresentation (private):", staticKeypair.rawRepresentation.map { String(format: "%02x", $0) }.joined())

        // Token: ss — DH(s, rs)
        let ssShared = try staticKeypair.sharedSecretFromKeyAgreement(with: remoteStaticPublicKey)
        print("DEBUG ssShared:", ssShared.rawBytes.map { String(format: "%02x", $0) }.joined())
        symmetricState.mixKey(ssShared.rawBytes)

        // Empty payload
        let encryptedPayload = try symmetricState.encryptAndHash([])
        message.append(contentsOf: encryptedPayload)

        return message
    }

    /// Обрабатывает message 2 (responder -> initiator): e, ee, se.
    /// По завершении вызывающий код должен вызвать `split()`.
    func readMessage2(_ message: [UInt8]) throws {
        guard let ephemeral = localEphemeral else {
            throw NoiseError.handshakeFailed("writeMessage1 must be called before readMessage2")
        }

        var offset = 0

        // Token: e — remote ephemeral, 32 bytes raw (unencrypted per Noise spec)
        guard message.count >= offset + 32 else {
            throw NoiseError.handshakeFailed("message 2 too short for e")
        }
        let rePubBytes = Array(message[offset..<offset + 32])
        offset += 32
        let rePub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePubBytes)
        symmetricState.mixHash(rePubBytes)

        // Token: ee — DH(e, re)
        let eeShared = try ephemeral.sharedSecretFromKeyAgreement(with: rePub)
        symmetricState.mixKey(eeShared.rawBytes)

        // Token: se — DH(s, re) [initiator static, responder ephemeral]
        let seShared = try staticKeypair.sharedSecretFromKeyAgreement(with: rePub)
        symmetricState.mixKey(seShared.rawBytes)

        // Remaining bytes: encrypted (empty) payload with 16-byte auth tag.
        let remaining = Array(message[offset...])
        guard remaining.count >= 16 else {
            throw NoiseError.handshakeFailed("message 2 payload ciphertext too short")
        }
        _ = try symmetricState.decryptAndHash(remaining)
    }

    /// Split() — вызывать один раз после успешного readMessage2.
    /// Возвращает (cs1, cs2) как в Noise spec; splitByRole определяет send/recv
    /// на стороне вызывающего кода (initiator: send=cs1, recv=cs2 — см. NoiseIKHandshake).
    func split() -> (CipherState, CipherState) {
        symmetricState.split()
    }

    var handshakeHash: [UInt8] { symmetricState.handshakeHash }
}

private extension SharedSecret {
    var rawBytes: [UInt8] {
        withUnsafeBytes { Array($0) }
    }
}
