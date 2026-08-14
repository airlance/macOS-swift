import Foundation
import FlatBuffers

/// Результат успешной аутентификации — то, что сервер прислал в `ConfirmEmailCodeAck`.
public struct AuthSession {
    public let sessionID: String
    public let deviceID: UInt64
    public let currentSeq: Int64
}

/// Минимальный email OTP auth flow поверх уже установленного `NoiseTransport`:
/// `RegisterAccount` -> `RegisterAccountAck` (запрашивает код на email),
/// затем `ConfirmEmailCode` -> `ConfirmEmailCodeAck` (подтверждает код,
/// заводит сессию и устройство).
///
/// Зеркало серверной части: `internal/transport/cli/serve.go`, case
/// `gen.BodyRegisterAccount` / `gen.BodyConfirmEmailCode`, и
/// `usecase.EmailAuthUseCase` (`RequestCode`/`ConfirmCode`).
public final class AuthClient {
    private let noiseConn: NoiseTransport
    private let requestIDs = RequestIDGenerator()

    init(noiseConn: NoiseTransport) {
        self.noiseConn = noiseConn
    }

    /// Шаг 1: запрашивает email OTP код. Сервер создаёт (или переиспользует)
    /// аккаунт по email и отправляет код на почту (см. `EmailAuthUseCase.RequestCode`).
    /// Возвращает `account_id`, который дальше нужен для `confirmEmailCode`.
    public func registerAccount(email: String, firstName: String, lastName: String) async throws -> UInt64 {
        let requestID = requestIDs.nextID()
        let frame = ProtocolCodec.encodeRegisterAccount(
            requestID: requestID,
            email: email,
            firstName: firstName,
            lastName: lastName
        )
        let envelope = try await noiseConn.request(frame, expecting: requestID)
        let ack = try ProtocolCodec.expectBody(envelope, as: .registeraccountack, type: Protocol__RegisterAccountAck.self)
        return ack.accountId
    }

    /// Шаг 2: подтверждает код из письма. При успехе сервер создаёт/находит
    /// устройство по `device.PublicKey` (device static key из Noise handshake —
    /// см. `conn.RemoteStaticKey()` на сервере), заводит сессию и возвращает её.
    ///
    /// `deviceFingerprint` — стабильный отпечаток железа/установки, отдельный
    /// от криптографического device key; используется сервером для UX
    /// ("это устройство уже входило") и уведомлений о новом устройстве.
    public func confirmEmailCode(
        accountID: UInt64,
        code: String,
        deviceFingerprint: String,
        deviceName: String,
        platform: String = "macOS",
        osVersion: String,
        appVersion: String
    ) async throws -> AuthSession {
        let requestID = requestIDs.nextID()
        let frame = ProtocolCodec.encodeConfirmEmailCode(
            requestID: requestID,
            accountID: accountID,
            code: code,
            deviceFingerprint: deviceFingerprint,
            deviceName: deviceName,
            platform: platform,
            osVersion: osVersion,
            appVersion: appVersion
        )
        let envelope = try await noiseConn.request(frame, expecting: requestID)
        let ack = try ProtocolCodec.expectBody(envelope, as: .confirmemailcodeack, type: Protocol__ConfirmEmailCodeAck.self)

        guard let sessionID = ack.sessionId else {
            throw ProtocolError.missingBody(.confirmemailcodeack)
        }
        return AuthSession(sessionID: sessionID, deviceID: ack.deviceId, currentSeq: ack.currentSeq)
    }

    /// Восстанавливает существующую сессию по `session_id` (без email OTP) —
    /// используется на последующих запусках приложения после первого логина.
    /// Зеркало `gen.BodyResumeSession` в router.go.
    /// Примечание: `ResumeSessionAck` в схеме не содержит `device_id` (в отличие
    /// от `ConfirmEmailCodeAck`), поэтому здесь он всегда 0 — это ограничение
    /// текущей схемы (`proto/schema.fbs`), не баг клиента.
    public func resumeSession(sessionID: String) async throws -> AuthSession {
        let requestID = requestIDs.nextID()
        let frame = ProtocolCodec.encodeResumeSession(requestID: requestID, sessionID: sessionID)
        let envelope = try await noiseConn.request(frame, expecting: requestID)
        let ack = try ProtocolCodec.expectBody(envelope, as: .resumesessionack, type: Protocol__ResumeSessionAck.self)

        guard let ackSessionID = ack.sessionId else {
            throw ProtocolError.missingBody(.resumesessionack)
        }
        return AuthSession(sessionID: ackSessionID, deviceID: 0, currentSeq: ack.currentSeq)
    }

    /// Заводит новую сессию для уже известного серверу устройства (device key
    /// привязан к аккаунту после предыдущего `ConfirmEmailCode`), без повторного
    /// прохождения email OTP. Используется когда `session_id` локально утерян,
    /// но устройство уже зарегистрировано — в отличие от `resumeSession`,
    /// не требует сохранённого `session_id`.
    /// Зеркало `gen.BodyNewSession` в router.go / `SessionUseCase.NewSession`.
    ///
    /// Примечание: `deviceID` в `NewSession`-фрейме сервер сейчас не читает —
    /// устройство определяется по Noise static key соединения
    /// (`conn.RemoteStaticKey()`), см. `router.go` case `BodyNewSession`.
    /// Параметр оставлен для соответствия схеме на случай, если сервер
    /// начнёт его использовать; сейчас можно не передавать.
    public func newSession(deviceID: UInt64 = 0) async throws -> AuthSession {
        let requestID = requestIDs.nextID()
        let frame = ProtocolCodec.encodeNewSession(requestID: requestID, deviceID: deviceID)
        let envelope = try await noiseConn.request(frame, expecting: requestID)
        let ack = try ProtocolCodec.expectBody(envelope, as: .newsessionack, type: Protocol__NewSessionAck.self)

        guard let sessionID = ack.sessionId else {
            throw ProtocolError.missingBody(.newsessionack)
        }
        // NewSessionAck не содержит device_id в схеме (в отличие от
        // ConfirmEmailCodeAck) — возвращаем 0, как и resumeSession.
        return AuthSession(sessionID: sessionID, deviceID: 0, currentSeq: ack.currentSeq)
    }
}
