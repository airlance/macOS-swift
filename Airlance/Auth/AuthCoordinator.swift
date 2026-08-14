import AirlanceClient
import Foundation
import os

/// Состояние, которое показывает окно логина в данный момент.
enum AuthStep {
    /// Стартовый экран: подключение и восстановление сессии ещё выполняются.
    case loading
    /// Шаг 1: ввод email (+ имя/фамилия) или кнопка "Sign in with GitHub".
    case emailEntry
    /// Шаг 2: ввод OTP-кода, присланного на `email`. `accountID` нужен
    /// дальше для `confirmEmailCode`.
    case otpEntry(email: String, accountID: UInt64)
    /// GitHub OAuth в процессе — ждём deep-link колбэк в системном браузере.
    case githubInFlight
    /// Успешный вход — есть сессия.
    case authenticated(AuthSession)
}

/// Ошибки auth-флоу в терминах, которые UI показывает напрямую пользователю
/// (без утечки деталей протокола/сети).
enum AuthUIError: Error {
    case notConnected
    case emailAlreadyExists
    case invalidCode
    case expiredCode
    case tooManyAttempts
    case rateLimited
    case githubCancelled
    case githubFailed(String)
    case network(String)

    var message: String {
        switch self {
        case .notConnected:
            return "Нет соединения с сервером. Проверьте, что сервер запущен, и попробуйте снова."
        case .emailAlreadyExists:
            return "Аккаунт с этим email уже существует. Мы всё равно отправили код — введите его."
        case .invalidCode:
            return "Неверный код. Проверьте письмо и попробуйте ещё раз."
        case .expiredCode:
            return "Код истёк. Запросите новый."
        case .tooManyAttempts:
            return "Слишком много попыток. Подождите немного и запросите код заново."
        case .rateLimited:
            return "Слишком много запросов. Попробуйте позже."
        case .githubCancelled:
            return "Вход через GitHub отменён."
        case .githubFailed(let detail):
            return "Не удалось войти через GitHub: \(detail)"
        case .network(let detail):
            return "Ошибка сети: \(detail)"
        }
    }
}

/// Связывает уже готовый auth-слой из `AirlanceClient` (SDK) с AppKit UI.
/// Ничего не знает про NSViewController — только состояние + async-методы,
/// которые View-слой дёргает из своих @IBAction/кнопок.
@MainActor
final class AuthCoordinator {
    private let logger = Logger(subsystem: "com.airlance.app", category: "AuthCoordinator")
    private let client: AirlanceClient
    private let osVersion: String
    private let appVersion: String
    private let githubHTTPScheme: String
    private let githubHTTPPort: UInt16?

    /// Вызывается при каждой смене шага — View-слой подписывается и
    /// перерисовывает соответствующий экран.
    var onStepChanged: ((AuthStep) -> Void)?

    private(set) var step: AuthStep = .loading {
        didSet { onStepChanged?(step) }
    }

    /// Кешируем email последнего запроса кода — нужен для "запросить код
    /// заново" и для конструирования шага confirmEmailCode без повторного
    /// ввода пользователем.
    private var lastRegisteredEmail: String?
    private var lastRegisteredAccountID: UInt64?
    private var lastRegisteredFirstName = ""
    private var lastRegisteredLastName = ""

    init(
        client: AirlanceClient,
        osVersion: String,
        appVersion: String,
        githubHTTPScheme: String = "http",
        githubHTTPPort: UInt16? = nil
    ) {
        self.client = client
        self.osVersion = osVersion
        self.appVersion = appVersion
        self.githubHTTPScheme = githubHTTPScheme
        self.githubHTTPPort = githubHTTPPort
    }

    /// Вызывается один раз при старте окна: пытается тихо восстановить
    /// сессию (resume/new session) без показа формы логина вообще.
    /// Возвращает true, если удалось восстановить (UI может сразу закрыть
    /// окно логина); false — нужно показать `emailEntry`.
    func tryRestoreSession() async -> Bool {
        do {
            if let session = try await client.establishSession() {
                step = .authenticated(session)
                return true
            }
        } catch {
            logger.error("Session restore failed: \(String(describing: error), privacy: .public)")
            // Молча падаем на форму логина — establishSession уже покрывает
            // ожидаемые случаи (SESSION_NOT_FOUND), остальное — сетевые
            // проблемы, которые пользователь увидит повторно при попытке войти.
        }
        step = .emailEntry
        return false
    }

    // MARK: - Email OTP flow

    /// Шаг 1 -> запрашивает код на email. При успехе переключает UI на
    /// экран ввода OTP.
    func requestEmailCode(email: String, firstName: String, lastName: String) async throws {
        guard let auth = client.auth else {
            logger.error("Email code request rejected: client is not connected")
            throw AuthUIError.notConnected
        }
        do {
            let accountID = try await auth.registerAccount(email: email, firstName: firstName, lastName: lastName)
            lastRegisteredEmail = email
            lastRegisteredAccountID = accountID
            lastRegisteredFirstName = firstName
            lastRegisteredLastName = lastName
            step = .otpEntry(email: email, accountID: accountID)
        } catch {
            logger.error("Email code request failed: \(String(describing: error), privacy: .public)")
            throw Self.mapError(error)
        }
    }

    /// Повторно запрашивает код для email текущего шага `otpEntry`, не
    /// покидая экран ввода кода.
    func resendCode() async throws {
        guard let email = lastRegisteredEmail else {
            throw AuthUIError.notConnected
        }
        try await requestEmailCode(
            email: email,
            firstName: lastRegisteredFirstName,
            lastName: lastRegisteredLastName
        )
    }

    /// Шаг 2 -> подтверждает введённый код. При успехе сохраняет сессию в
    /// Keychain и переключает UI на `authenticated`.
    func confirmCode(_ code: String, deviceName: String) async throws {
        guard let auth = client.auth else { throw AuthUIError.notConnected }
        guard case .otpEntry(_, let accountID) = step else { return }

        do {
            let fingerprint = try client.deviceFingerprint()
            let session = try await auth.confirmEmailCode(
                accountID: accountID,
                code: code,
                deviceFingerprint: fingerprint,
                deviceName: deviceName,
                osVersion: osVersion,
                appVersion: appVersion
            )
            try client.persistSession(session)
            step = .authenticated(session)
        } catch {
            throw Self.mapError(error)
        }
    }

    /// Возврат с шага OTP на шаг email (пользователь ввёл не тот адрес).
    func backToEmailEntry() {
        lastRegisteredEmail = nil
        lastRegisteredAccountID = nil
        lastRegisteredFirstName = ""
        lastRegisteredLastName = ""
        step = .emailEntry
    }

    // MARK: - GitHub flow

    func signInWithGithub() async throws {
        step = .githubInFlight
        do {
            let session = try await client.signInWithGithub(
                httpScheme: githubHTTPScheme,
                httpPort: githubHTTPPort,
                osVersion: osVersion,
                appVersion: appVersion
            )
            step = .authenticated(session)
        } catch {
            step = .emailEntry
            throw Self.mapError(error)
        }
    }

    /// Прокидывается из `AppDelegate.application(_:open:)`.
    func handleOpenURL(_ url: URL) async {
        await client.handleOpenURL(url)
    }

    func cancelGithub() async {
        await client.cancelGithubAuth()
        step = .emailEntry
    }

    // MARK: - Error mapping

    private static func mapError(_ error: Error) -> AuthUIError {
        if let protocolError = error as? ProtocolError {
            switch protocolError {
            case .notConnected, .alreadyConnectingOrConnected:
                return .notConnected
            case .serverError(let code, let message):
                switch code {
                case .emailAlreadyExists: return .emailAlreadyExists
                case .invalidCode: return .invalidCode
                case .expiredCode: return .expiredCode
                case .tooManyAttempts: return .tooManyAttempts
                case .rateLimitExceeded: return .rateLimited
                default: return .network(message)
                }
            case .unexpectedBodyType, .missingBody:
                return .network(protocolError.description)
            }
        }
        if let githubError = error as? GithubAuthError {
            switch githubError {
            case .cancelled: return .githubCancelled
            default: return .githubFailed(githubError.description)
            }
        }
        return .network(String(describing: error))
    }
}
