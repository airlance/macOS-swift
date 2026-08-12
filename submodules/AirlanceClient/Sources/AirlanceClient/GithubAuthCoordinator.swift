import Foundation
import AppKit

/// Данные, извлечённые из `airlance://auth/callback?...` после успешного
/// GitHub OAuth на сервере (см. `internal/transport/http/oauth_handler.go`,
/// `HandleCallback`).
public struct GithubOAuthCallback {
    public let sessionID: String
    public let deviceID: UInt64
    public let accountID: UInt64
}

public enum GithubAuthError: Error, CustomStringConvertible {
    /// `state` пришедший в deep-link не совпал с тем, что мы сгенерировали
    /// перед открытием браузера — либо подмена колбэка, либо это ответ на
    /// устаревший/повторный запрос.
    case stateMismatch
    /// Сервер прислал колбэк без `session_id` (сервер сообщил об ошибке через
    /// `http.Error` до редиректа — маловероятно долетит как наш deep-link,
    /// но на всякий случай).
    case missingSessionID
    /// `NSWorkspace.shared.open` не смог открыть URL (нет браузера по умолчанию и т.п.)
    case cannotOpenBrowser
    /// Пользователь отменил флоу (например, закрыл окно) — сейчас не
    /// детектируется автоматически, доступно только через `cancel()`.
    case cancelled

    public var description: String {
        switch self {
        case .stateMismatch: return "airlance: oauth callback state mismatch"
        case .missingSessionID: return "airlance: oauth callback missing session_id"
        case .cannotOpenBrowser: return "airlance: failed to open system browser"
        case .cancelled: return "airlance: oauth flow was cancelled"
        }
    }
}

/// Мост между "открыли системный браузер на /auth/github/start" и
/// "поймали airlance://auth/callback в AppDelegate" — оборачивает это
/// ожидание в единственный async вызов.
///
/// Один координатор поддерживает один одновременный in-flight запрос.
/// Второй `beginAuth` до завершения первого — программерская ошибка
/// (fatalError), а не то, что стоит тихо проглатывать.
///
/// Зеркало серверной части: `r.Route("/auth/github", ...)` в
/// `internal/transport/http/server.go`.
public actor GithubAuthCoordinator {
    private var pendingContinuation: CheckedContinuation<GithubOAuthCallback, Error>?
    private var expectedState: String?

    public init() {}

    /// Шаг 1+2: открывает `/auth/github/start` в системном браузере и
    /// асинхронно ждёт, пока `handleCallback(url:)` не будет вызван из
    /// `AppDelegate` с соответствующим deep-link.
    ///
    /// - Parameters:
    ///   - host: тот же host, что в `AirlanceClientConfig` (используется
    ///     только для построения HTTP(S) URL; TCP/Noise порт тут ни при чём —
    ///     OAuth целиком идёт через HTTP-сервер, см. `cfg.HTTP.Addr`).
    ///   - httpScheme: "https" в проде, "http" для локальной разработки.
    ///   - httpPort: порт HTTP-сервера (`internal/config/config.go`, `HTTP.Addr`),
    ///     если он отличается от стандартного 80/443.
    ///   - deviceFingerprint: стабильный fingerprint устройства — сервер
    ///     матчит device по нему при GitHub OAuth (см. `upsertDevice` /
    ///     `DeviceInfo.Fingerprint` в `internal/usecase/device_upsert.go`).
    ///     **Важно**: GitHub OAuth не привязывает Noise static key к device
    ///     (HTTP-запрос не несёт Noise identity), поэтому после этого флоу
    ///     `client.auth.newSession()` для данного устройства работать не
    ///     будет — только `resumeSession(sessionID:)` с полученным session_id.
    public func beginAuth(
        host: String,
        httpScheme: String = "https",
        httpPort: UInt16? = nil,
        deviceFingerprint: String,
        platform: String = "macOS",
        osVersion: String,
        appVersion: String
    ) async throws -> GithubOAuthCallback {
        precondition(pendingContinuation == nil, "GithubAuthCoordinator: beginAuth called while another auth is in flight")

        let clientState = UUID().uuidString
        expectedState = clientState

        var components = URLComponents()
        components.scheme = httpScheme
        components.host = host
        components.port = httpPort.map { Int($0) }
        components.path = "/auth/github/start"
        components.queryItems = [
            URLQueryItem(name: "client_state", value: clientState),
            URLQueryItem(name: "fingerprint", value: deviceFingerprint),
            URLQueryItem(name: "platform", value: platform),
            URLQueryItem(name: "os_version", value: osVersion),
            URLQueryItem(name: "app_version", value: appVersion),
        ]

        guard let url = components.url else {
            throw GithubAuthError.cannotOpenBrowser
        }

        // NSWorkspace.open не сообщает об ошибке синхронно если браузер по
        // умолчанию просто не задан — считаем, что открытие всегда "успешно"
        // на уровне API; реальная ошибка (если будет) придёт как таймаут
        // ожидания колбэка на стороне вызывающего кода.
        guard NSWorkspace.shared.open(url) else {
            expectedState = nil
            throw GithubAuthError.cannotOpenBrowser
        }

        return try await withCheckedThrowingContinuation { continuation in
            self.pendingContinuation = continuation
        }
    }

    /// Вызывается из `AppDelegate.application(_:open:)` для каждого URL с
    /// нашей custom-схемой. Безопасно вызывать с "чужими" URL — они будут
    /// проигнорированы (просто вернёт управление, ничего не резолвя).
    public func handleCallback(url: URL) {
        guard url.scheme == "airlance", url.host == "auth", url.path == "/callback" else {
            return
        }
        guard let continuation = pendingContinuation else {
            // Колбэк пришёл, когда никто не ждёт (двойной клик по ссылке,
            // повторный редирект и т.п.) — молча игнорируем.
            return
        }

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems else {
            finish(continuation, .failure(GithubAuthError.missingSessionID))
            return
        }
        let params = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })

        guard params["client_state"] == expectedState else {
            finish(continuation, .failure(GithubAuthError.stateMismatch))
            return
        }
        guard let sessionID = params["session_id"], !sessionID.isEmpty else {
            finish(continuation, .failure(GithubAuthError.missingSessionID))
            return
        }

        let callback = GithubOAuthCallback(
            sessionID: sessionID,
            deviceID: params["device_id"].flatMap(UInt64.init) ?? 0,
            accountID: params["account_id"].flatMap(UInt64.init) ?? 0
        )
        finish(continuation, .success(callback))
    }

    /// Отменяет ожидающий `beginAuth`, если пользователь закрыл окно
    /// браузера сам, или UI-таймаут решил не ждать дальше. Безопасно
    /// вызывать, даже если ничего не ждёт.
    public func cancel() {
        guard let continuation = pendingContinuation else { return }
        finish(continuation, .failure(GithubAuthError.cancelled))
    }

    private func finish(
        _ continuation: CheckedContinuation<GithubOAuthCallback, Error>,
        _ result: Result<GithubOAuthCallback, Error>
    ) {
        pendingContinuation = nil
        expectedState = nil
        continuation.resume(with: result)
    }
}
