import Foundation
import FlatBuffers

/// Общие ошибки протокольного слоя (несовпадающий bodyType, отсутствующее тело,
/// фрейм ошибки от сервера) — аналог `gen.Error`/`writeError` на сервере.
public enum ProtocolError: Error, CustomStringConvertible {
    case unexpectedBodyType(expected: Protocol__Body, got: Protocol__Body)
    case missingBody(Protocol__Body)
    case serverError(code: Protocol__ErrorCode, message: String)
    case notConnected

    public var description: String {
        switch self {
        case .unexpectedBodyType(let expected, let got):
            return "airlance: expected body type \(expected), got \(got)"
        case .missingBody(let type):
            return "airlance: envelope declared body type \(type) but union payload was missing"
        case .serverError(let code, let message):
            return "airlance: server returned error \(code): \(message)"
        case .notConnected:
            return "airlance: connect() must succeed before this call"
        }
    }
}

/// Простой монотонный генератор `request_id` для Envelope — по одному на клиент,
/// как сервер использует `env.RequestId()` просто для корреляции запрос/ответ
/// (сервер её не валидирует, только эхает обратно в ack).
final class RequestIDGenerator {
    private var next: UInt64 = 1
    private let lock = NSLock()

    func nextID() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let id = next
        next += 1
        return id
    }
}

/// Encode/decode helpers для email OTP auth flow (`RegisterAccount` -> `RegisterAccountAck`
/// -> `ConfirmEmailCode` -> `ConfirmEmailCodeAck`), плюс `NewSession`/`ResumeSession`/`Ping`
/// как минимально необходимые для установления сессии после handshake.
/// Один-в-один зеркалит `write*Ack` функции в `internal/transport/cli/serve.go`,
/// только в обратную сторону (клиент пишет запрос, читает ack).
enum ProtocolCodec {

    // MARK: - Encoding (client -> server)

    static func encodeRegisterAccount(requestID: UInt64, email: String, firstName: String, lastName: String) -> [UInt8] {
        var builder = FlatBufferBuilder(initialSize: 256)
        let emailOffset = builder.create(string: email)
        let firstNameOffset = builder.create(string: firstName)
        let lastNameOffset = builder.create(string: lastName)

        let bodyOffset = Protocol__RegisterAccount.createRegisterAccount(
            &builder,
            emailOffset: emailOffset,
            firstNameOffset: firstNameOffset,
            lastNameOffset: lastNameOffset
        )

        return finishEnvelope(&builder, requestID: requestID, bodyType: .registeraccount, body: bodyOffset)
    }

    static func encodeConfirmEmailCode(
        requestID: UInt64,
        accountID: UInt64,
        code: String,
        deviceFingerprint: String,
        deviceName: String,
        platform: String,
        osVersion: String,
        appVersion: String
    ) -> [UInt8] {
        var builder = FlatBufferBuilder(initialSize: 512)
        let codeOffset = builder.create(string: code)
        let fingerprintOffset = builder.create(string: deviceFingerprint)
        let deviceNameOffset = builder.create(string: deviceName)
        let platformOffset = builder.create(string: platform)
        let osVersionOffset = builder.create(string: osVersion)
        let appVersionOffset = builder.create(string: appVersion)

        let bodyOffset = Protocol__ConfirmEmailCode.createConfirmEmailCode(
            &builder,
            accountId: accountID,
            codeOffset: codeOffset,
            deviceFingerprintOffset: fingerprintOffset,
            deviceNameOffset: deviceNameOffset,
            platformOffset: platformOffset,
            osVersionOffset: osVersionOffset,
            appVersionOffset: appVersionOffset
        )

        return finishEnvelope(&builder, requestID: requestID, bodyType: .confirmemailcode, body: bodyOffset)
    }

    static func encodeNewSession(requestID: UInt64, deviceID: UInt64) -> [UInt8] {
        var builder = FlatBufferBuilder(initialSize: 64)
        let bodyOffset = Protocol__NewSession.createNewSession(&builder, deviceId: deviceID)
        return finishEnvelope(&builder, requestID: requestID, bodyType: .newsession, body: bodyOffset)
    }

    static func encodeResumeSession(requestID: UInt64, sessionID: String) -> [UInt8] {
        var builder = FlatBufferBuilder(initialSize: 128)
        let sessionIDOffset = builder.create(string: sessionID)
        let bodyOffset = Protocol__ResumeSession.createResumeSession(&builder, sessionIdOffset: sessionIDOffset)
        return finishEnvelope(&builder, requestID: requestID, bodyType: .resumesession, body: bodyOffset)
    }

    static func encodePing(requestID: UInt64, timestamp: Int64) -> [UInt8] {
        var builder = FlatBufferBuilder(initialSize: 64)
        let bodyOffset = Protocol__Ping.createPing(&builder, timestamp: timestamp)
        return finishEnvelope(&builder, requestID: requestID, bodyType: .ping, body: bodyOffset)
    }

    private static func finishEnvelope(
        _ builder: inout FlatBufferBuilder,
        requestID: UInt64,
        bodyType: Protocol__Body,
        body: Offset
    ) -> [UInt8] {
        let envelopeOffset = Protocol__Envelope.createEnvelope(
            &builder,
            requestId: requestID,
            bodyType: bodyType,
            bodyOffset: body
        )
        builder.finish(offset: envelopeOffset)
        return builder.sizedByteArray
    }

    // MARK: - Decoding (server -> client)

    /// Парсит сырой (уже расшифрованный Noise-слоем) фрейм в `Envelope` и
    /// возвращает его bodyType вместе с самим envelope для дальнейшего чтения
    /// конкретной union-таблицы через `envelope.body(type:)`.
    static func decodeEnvelope(_ frame: [UInt8]) throws -> Protocol__Envelope {
        var buffer = ByteBuffer(bytes: frame)
        return try getCheckedRoot(byteBuffer: &buffer)
    }

    /// Достаёт конкретный union-payload из envelope, либо бросает
    /// `ProtocolError.serverError` если сервер прислал `Error`-фрейм вместо
    /// ожидаемого ack'а (см. `writeError` в router.go — сервер шлёт Error
    /// вместо, а не в дополнение к специфичному ack).
    static func expectBody<T: FlatbuffersInitializable>(
        _ envelope: Protocol__Envelope,
        as expected: Protocol__Body,
        type: T.Type
    ) throws -> T {
        if envelope.bodyType == .error {
            let err: Protocol__Error? = envelope.body(type: Protocol__Error.self)
            let code = err?.code ?? .unknown
            let message = err?.message ?? "(no message)"
            throw ProtocolError.serverError(code: code, message: message)
        }
        guard envelope.bodyType == expected else {
            throw ProtocolError.unexpectedBodyType(expected: expected, got: envelope.bodyType)
        }
        guard let body = envelope.body(type: T.self) else {
            throw ProtocolError.missingBody(expected)
        }
        return body
    }
}
