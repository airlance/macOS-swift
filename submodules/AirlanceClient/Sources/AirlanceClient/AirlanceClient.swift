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
/// handshake, дальше отдаёт `NoiseConn` протокольному слою.
///
/// Протокольный слой (Envelope/RegisterAccount/ConfirmEmailCode и т.д. из
/// `proto/schema.fbs`) сюда пока не добавлен — как только будет Swift-код от
/// `flatc`, подключаем его поверх `noiseConn.writeFrame`/`readFrame`, по образцу
/// серверных `write*Ack` функций в `internal/transport/cli/serve.go`.
public final class AirlanceClient {
    private let config: AirlanceClientConfig
    private var tcpConnection: TCPConnection?
    private(set) var noiseConn: NoiseConn?
    private let githubAuthCoordinator = GithubAuthCoordinator()

    public init(config: AirlanceClientConfig) {
        self.config = config
    }

    /// Подключается и проходит Noise IK handshake. После успеха `noiseConn`
    /// готов для отправки/чтения зашифрованных application-фреймов.
    public func connect() async throws {
        let serverKeyBytes = try HexCodec.decode(config.serverStaticPublicKeyHex)
        let serverStaticKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyBytes)
        let deviceKey = try DeviceIdentity.loadOrCreate()

        let tcp = TCPConnection(host: config.host, port: config.port)
        try await tcp.connect()
        self.tcpConnection = tcp

        let conn = try await NoiseIKHandshake.clientHandshake(
            connection: tcp,
            serverStaticPublicKey: serverStaticKey,
            clientStaticKeypair: deviceKey
        )
        self.noiseConn = conn
    }

    public func close() {
        noiseConn?.close()
        tcpConnection = nil
        noiseConn = nil
    }

    /// Публичный ключ устройства (device key) в hex — то, что сервер увидит как
    /// `RemoteStaticKey()` и что используется как `device.PublicKey` при
    /// `ConfirmEmailCode`.
    public func devicePublicKeyHex() throws -> String {
        let key = try DeviceIdentity.loadOrCreate()
        return HexCodec.encode([UInt8](key.publicKey.rawRepresentation))
    }

    /// Auth-клиент (email OTP flow) поверх текущего `noiseConn`. `nil` пока
    /// `connect()` не был вызван успешно.
    public var auth: AuthClient? {
        guard let noiseConn else { return nil }
        return AuthClient(noiseConn: noiseConn)
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
