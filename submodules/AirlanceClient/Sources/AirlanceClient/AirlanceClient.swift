import Foundation
import CryptoKit

public struct AirlanceClientConfig {
    public let host: String
    public let port: UInt16
    /// `public_key_hex` из `server-key.json` — pinned static key сервера.
    public let serverStaticPublicKeyHex: String

    public init(host: String, port: UInt16, serverStaticPublicKeyHex: String) {
        self.host = host
        self.port = port
        self.serverStaticPublicKeyHex = serverStaticPublicKeyHex
    }
}

/// Верхнеуровневый клиент: устанавливает TCP-соединение, проходит Noise IK
/// handshake (через `NoiseTransport`, actor), дальше отдаёт его протокольному слою.
///
/// Протокольный слой (Envelope/RegisterAccount/ConfirmEmailCode и т.д. из
/// `proto/schema.fbs`) подключается поверх `transport.writeFrame`/`readFrame`,
/// по образцу серверных `write*Ack` функций в `internal/transport/cli/serve.go`.
public final class AirlanceClient {
    private let config: AirlanceClientConfig
    // NOT an actor: facade остаётся обычным классом, чтобы синхронные геттеры
    // (devicePublicKeyHex, deviceFingerprint) не требовали await без необходимости.
    // Крипто-состояние изолировано внутри NoiseTransport (actor) — см. AGENTS.md §4.
    private var transport: NoiseTransport?
    private let githubAuthCoordinator = GithubAuthCoordinator()

    public init(config: AirlanceClientConfig) {
        self.config = config
    }

    /// Подключается и проходит Noise IK handshake. После успеха `transport`
    /// готов для отправки/чтения зашифрованных application-фреймов.
    public func connect() async throws {
        let serverKeyBytes = try HexCodec.decode(config.serverStaticPublicKeyHex)
        let serverStaticKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyBytes)
        let deviceKey = try DeviceIdentity.loadOrCreate()

        let transport = NoiseTransport(
            host: config.host,
            port: config.port,
            serverStaticPublicKey: serverStaticKey,
            clientStaticKeypair: deviceKey
        )
        try await transport.connect()
        self.transport = transport
    }

    /// Закрывает соединение. Не async (facade синхронный по дизайну), поэтому
    /// фактическое закрытие сокета внутри actor-изолированного `NoiseTransport`
    /// происходит fire-and-forget через отдельный `Task` — вызывающий код не должен
    /// полагаться на то, что сокет закрыт немедленно к моменту возврата `close()`,
    /// только на то, что `transport`/`auth` сразу становятся `nil` для новых вызовов.
    public func close() {
        Task { [transport] in
            await transport?.close()
        }
        transport = nil
    }

    /// Публичный ключ устройства (device key) в hex — то, что сервер увидит как
    /// `RemoteStaticKey()` и что используется как `device.PublicKey` при
    /// `ConfirmEmailCode`.
    public func devicePublicKeyHex() throws -> String {
        let key = try DeviceIdentity.loadOrCreate()
        return HexCodec.encode([UInt8](key.publicKey.rawRepresentation))
    }

    /// Стабильный идентификатор установки, общий для email OTP и GitHub OAuth.
    /// Оба auth-flow должны передавать серверу один и тот же fingerprint,
    /// иначе одна и та же машина будет зарегистрирована как два устройства.
    public func deviceFingerprint() throws -> String {
        try DeviceIdentity.fingerprint()
    }

    /// Auth-клиент (email OTP flow) поверх текущего `transport`. `nil` пока
    /// `connect()` не был вызван успешно.
    public var auth: AuthClient? {
        guard let transport else { return nil }
        return AuthClient(noiseConn: transport)
    }

    /// Поток входящих push-событий с сервера (сообщения, обновления QR-кодов и т.д.).
    /// Доступен после `connect()`.
    public var incomingEvents: AsyncStream<IncomingEvent>? {
        transport?.incomingEvents
    }

    /// Поток изменений состояния сетевого подключения.
    /// Доступен после `connect()`.
    public var connectionState: AsyncStream<ConnectionState>? {
        transport?.connectionState
    }

    /// Единая точка входа для "уже был здесь" сценария: после `connect()`
    /// пытается восстановить активную сессию без email OTP, в порядке:
    ///
    /// 1. Если в Keychain есть сохранённый `session_id` для этого хоста —
    ///    пробует `ResumeSession`.
    /// 2. Если `session_id` нет, или resume упал с `SESSION_NOT_FOUND`
    ///    (сессия истекла/отозвана, но устройство всё ещё привязано к
    ///    аккаунту) — пробует `NewSession` (сервер узнаёт device по
    ///    Noise static key).
    /// 3. Если и это падает с `SESSION_NOT_FOUND` (устройство ещё не
    ///    зарегистрировано — первый запуск на этой машине/ключе) —
    ///    возвращает `nil`: вызывающий код должен провести email OTP
    ///    через `auth.registerAccount`/`confirmEmailCode`.
    ///
    /// В любом успешном случае (resume или new) сохраняет свежий
    /// `session_id` в Keychain.
    public func establishSession() async throws -> AuthSession? {
        guard let auth else {
            throw ProtocolError.notConnected
        }

        if let savedSessionID = try SessionStore.load(host: config.host) {
            do {
                let session = try await auth.resumeSession(sessionID: savedSessionID)
                try SessionStore.save(host: config.host, sessionID: session.sessionID)
                return session
            } catch ProtocolError.serverError(let code, _) where code == .sessionNotFound {
                SessionStore.clear(host: config.host)
                // falls through to NewSession attempt below
            }
        }

        do {
            let session = try await auth.newSession()
            try SessionStore.save(host: config.host, sessionID: session.sessionID)
            return session
        } catch ProtocolError.serverError(let code, _) where code == .sessionNotFound {
            // Устройство ещё не привязано ни к одному аккаунту — нужен email OTP.
            return nil
        }
    }

    /// Сохраняет `session_id`, полученный из `AuthClient.confirmEmailCode`,
    /// в Keychain — чтобы следующий запуск мог сразу вызвать `establishSession()`
    /// вместо повторного email OTP. Вызывать сразу после успешного
    /// `confirmEmailCode`.
    public func persistSession(_ session: AuthSession) throws {
        try SessionStore.save(host: config.host, sessionID: session.sessionID)
    }

    /// Стирает сохранённый `session_id` (например, после явного logout).
    public func forgetSession() {
        SessionStore.clear(host: config.host)
    }

    #if os(macOS)
    /// GitHub OAuth flow целиком: открывает системный браузер на
    /// `/auth/github/start`, ждёт `airlance://auth/callback` (см.
    /// `GithubAuthCoordinator`), затем сразу подтверждает полученный
    /// `session_id` через `resumeSession` на уже установленном Noise-канале
    /// и сохраняет сессию в Keychain.
    ///
    /// **Важно**: требует, чтобы `connect()` уже был вызван успешно — GitHub
    /// OAuth создаёт устройство на сервере без Noise static key (HTTP-запрос
    /// не несёт Noise identity, см. `internal/transport/http/oauth_handler.go`),
    /// поэтому `newSession()` для этого устройства работать не будет:
    /// единственный путь восстановления сессии на этом устройстве —
    /// `resumeSession(sessionID:)` с session_id, который вернул именно этот
    /// OAuth-запрос (сохранённый после в Keychain через `SessionStore`).
    ///
    /// - Parameters:
    ///   - httpScheme: "https" в проде, "http" для локальной разработки.
    ///   - httpPort: порт HTTP-сервера (`cfg.HTTP.Addr`), если отдельный от
    ///     стандартного 80/443 и от TCP/Noise порта в `config.port`.
    ///   - osVersion, appVersion: передаются как есть в query `/auth/github/start`
    ///     и попадают в `DeviceInfo` на сервере как метаданные устройства.
    public func signInWithGithub(
        httpScheme: String = "https",
        httpPort: UInt16? = nil,
        osVersion: String,
        appVersion: String
    ) async throws -> AuthSession {
        guard auth != nil else {
            throw ProtocolError.notConnected
        }

        let fingerprint = try DeviceIdentity.fingerprint()
        let callback = try await githubAuthCoordinator.beginAuth(
            host: config.host,
            httpScheme: httpScheme,
            httpPort: httpPort,
            deviceFingerprint: fingerprint,
            osVersion: osVersion,
            appVersion: appVersion
        )

        let session = try await auth!.resumeSession(sessionID: callback.sessionID)
        try SessionStore.save(host: config.host, sessionID: session.sessionID)
        return session
    }

    /// Прокидывается из `AppDelegate.application(_:open:)` для каждого
    /// открытого URL. Безопасно вызывать с URL любой другой схемы — будет
    /// проигнорирован.
    public func handleOpenURL(_ url: URL) async {
        await githubAuthCoordinator.handleCallback(url: url)
    }

    /// Отменяет незавершённый `signInWithGithub`, если пользователь закрыл
    /// окно браузера сам или сработал UI-таймаут ожидания.
    public func cancelGithubAuth() async {
        await githubAuthCoordinator.cancel()
    }
    #endif
}
