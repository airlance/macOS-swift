import Foundation
import CryptoKit

/// Зеркало `internal/noiseik/conn.go`: прозрачно шифрует/расшифровывает каждый
/// фрейм поверх уже установленного `TCPConnection`. Верхний код (протокольный
/// слой Envelope/FlatBuffers) работает с этим так же, как с сырым TCP,
/// ничего не зная про Noise.
final class NoiseConn {
    private let raw: TCPConnection
    private let sendCipher: CipherState
    private let recvCipher: CipherState
    let remoteStaticKey: [UInt8]
    let handshakeHash: [UInt8]

    fileprivate init(raw: TCPConnection, send: CipherState, recv: CipherState, remoteStaticKey: [UInt8], handshakeHash: [UInt8]) {
        self.raw = raw
        self.sendCipher = send
        self.recvCipher = recv
        self.remoteStaticKey = remoteStaticKey
        self.handshakeHash = handshakeHash
    }

    func writeFrame(_ plaintext: [UInt8]) async throws {
        // Noise transport messages используют пустой AD (Noise spec §5.1 / §5.4
        // transport phase: EncryptWithAd(nil ad, plaintext)).
        let ciphertext = try sendCipher.encryptWithAd([], plaintext: plaintext)
        try await raw.writeFrame(ciphertext)
    }

    func readFrame() async throws -> [UInt8] {
        let ciphertext = try await raw.readFrame()
        return try recvCipher.decryptWithAd([], ciphertext: ciphertext)
    }

    func close() {
        raw.close()
    }
}

enum NoiseIKHandshake {
    /// Выполняет клиентский Noise IK handshake поверх уже подключённого `TCPConnection`.
    /// Зеркало `noiseik.ClientHandshake` из Go-кода:
    /// 1. msg1 = e, es, s, ss  -> отправляем как обычный (незашифрованный на уровне
    ///    TCP framing) фрейм через `raw.writeFrame`.
    /// 2. msg2 = e, ee, se     <- читаем ответ сервера.
    /// 3. Split() -> (cs1, cs2); для initiator send=cs1, recv=cs2.
    ///
    /// `serverStaticPublicKeyHex` — pinned publicKey сервера из `server-key.json`
    /// (`public_key_hex`). Несовпадение ключа проявится как провал handshake
    /// (AEAD-проверка на шаге ss/se упадёт), а не как явная ошибка "wrong key" —
    /// это осознанное поведение протокола, см. `TestHandshake_WrongPinnedServerKeyFails`
    /// в серверных тестах.
    static func clientHandshake(
        connection: TCPConnection,
        serverStaticPublicKey: Curve25519.KeyAgreement.PublicKey,
        clientStaticKeypair: Curve25519.KeyAgreement.PrivateKey
    ) async throws -> NoiseConn {
        let hs = HandshakeState(staticKeypair: clientStaticKeypair, remoteStaticPublicKey: serverStaticPublicKey)

        let rawServerKey = [UInt8](serverStaticPublicKey.rawRepresentation)
        print("RUNNING CLIENT WITH SERVER KEY:", rawServerKey.map { String(format: "%02x", $0) }.joined())
        
        let msg1 = try hs.writeMessage1()
        print("DEBUG msg1 (\(msg1.count) bytes):", msg1.map { String(format: "%02x", $0) }.joined())
        print("DEBUG serverStaticPublicKey used:", [UInt8](serverStaticPublicKey.rawRepresentation).map { String(format: "%02x", $0) }.joined())
        print("DEBUG clientStaticKeypair.publicKey used:", [UInt8](clientStaticKeypair.publicKey.rawRepresentation).map { String(format: "%02x", $0) }.joined())
        try await connection.writeFrame(msg1)

        let msg2 = try await connection.readFrame()
        print("DEBUG msg2 (\(msg2.count) bytes):", msg2.map { String(format: "%02x", $0) }.joined())
        try hs.readMessage2(msg2)

        let (cs1, cs2) = hs.split()
        // initiator: send = cs1, recv = cs2 (см. splitByRole(initiator: true, ...) в Go)
        return NoiseConn(
            raw: connection,
            send: cs1,
            recv: cs2,
            remoteStaticKey: [UInt8](serverStaticPublicKey.rawRepresentation),
            handshakeHash: hs.handshakeHash
        )
    }
}
