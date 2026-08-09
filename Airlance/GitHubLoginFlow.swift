import AuthenticationServices
import Cocoa
import Foundation

/// Drives the GitHub sign-in flow end to end using
/// `ASWebAuthenticationSession` — the system browser sheet API, not a
/// hand-rolled `NSAppleEventManager`/`application(_:open:)` URL handler.
/// `ASWebAuthenticationSession` registers its own one-shot callback
/// listener for the given `callbackURLScheme` and tears it down as soon
/// as the session completes, so nothing else in the app needs to know
/// about `airlance://` at all.
///
/// Flow:
///  1. This class builds `https://github.com/login/oauth/authorize`
///     itself, with this app's own OAuth `client_id` (public by design —
///     GitHub client IDs aren't secret, only `client_secret` is, and
///     that stays server-side in `githuboauth.Client`) plus a freshly
///     generated `state`, and opens it in the system browser sheet.
///  2. User authorizes on GitHub's own pages.
///  3. GitHub redirects to the server's `GET /auth/github/callback`
///     (an https:// URL, since GitHub can't redirect to a custom
///     scheme). That handler does NOT exchange the code — see
///     `github_callback.go` — it only forwards `code`/`state`/`error`
///     onward.
///  4. The server redirects to
///     `airlance://oauth-callback?code=<GITHUB_CODE>&state=<STATE>` —
///     this `code` is the real, unexchanged GitHub OAuth code. The
///     server never sees or touches it at this HTTP layer; the actual
///     code->token->profile exchange happens later, server-side, inside
///     `LoginByGithubRPC` once the client calls it over gRPC.
///  5. `ASWebAuthenticationSession` intercepts that redirect (matching
///     `callbackURLScheme: "airlance"`), the sheet closes, and this
///     class extracts `code` from the callback URL's query — after
///     confirming `state` matches what it generated in step 1, to rule
///     out a forged/replayed callback.
///  6. Caller takes that code and calls `AirlanceClient.loginByGithub(code:clientCtx:)`.
@MainActor
final class GitHubLoginFlow: NSObject {
    enum GitHubAuthError: Error {
        case cancelled
        case missingCode
        case stateMismatch
        case serverError(String)
        case sessionFailed(Error)
    }

    /// This app's GitHub OAuth App client ID. Not a secret — it's
    /// visible in every authorize URL GitHub itself redirects through,
    /// so shipping it in the client binary reveals nothing an attacker
    /// couldn't already read off the network. `client_secret` is the
    /// half that must never leave the server (see `githuboauth.Client`).
    private let clientID: String

    /// The server's callback bridge — GitHub redirects here (must be
    /// https://), and this handler forwards the result on to
    /// `callbackURLScheme` via a second redirect. Must match
    /// `GITHUB_REDIRECT_URI` in the server's config exactly, since
    /// GitHub validates the callback's `redirect_uri` against what was
    /// registered for the OAuth App.
    private let redirectURI: URL

    /// Must match the URL scheme registered in Info.plist's
    /// `CFBundleURLTypes` (see AirlanceApp's Package.swift/Info.plist
    /// notes) — "airlance" here corresponds to `airlance://oauth-callback`.
    private let callbackURLScheme = "airlance"

    private var activeSession: ASWebAuthenticationSession?
    private weak var presentationWindow: NSWindow?

    init(clientID: String, redirectURI: URL) {
        self.clientID = clientID
        self.redirectURI = redirectURI
    }

    /// Presents the system sign-in sheet and suspends until the user
    /// either completes or cancels it. Returns the real GitHub OAuth
    /// code (destined for `LoginByGithubRequest.code`, unexchanged) on
    /// success.
    ///
    /// `presentationAnchor` must be a real, currently-visible `NSWindow`
    /// — typically `view.window` from the calling view controller. It's
    /// retained weakly for the lifetime of the sign-in sheet only.
    func signIn(presentationAnchor: NSWindow) async throws -> String {
        self.presentationWindow = presentationAnchor

        let state = Self.generateState()
        let authorizeURL = buildAuthorizeURL(state: state)

        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authorizeURL,
                callbackURLScheme: callbackURLScheme
            ) { callbackURL, error in
                if let error {
                    if case ASWebAuthenticationSessionError.canceledLogin = error {
                        continuation.resume(throwing: GitHubAuthError.cancelled)
                    } else {
                        continuation.resume(throwing: GitHubAuthError.sessionFailed(error))
                    }
                    return
                }

                guard let callbackURL else {
                    continuation.resume(throwing: GitHubAuthError.missingCode)
                    return
                }

                let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []

                if let serverError = items.first(where: { $0.name == "error" })?.value {
                    continuation.resume(throwing: GitHubAuthError.serverError(serverError))
                    return
                }

                guard let returnedState = items.first(where: { $0.name == "state" })?.value,
                      returnedState == state
                else {
                    continuation.resume(throwing: GitHubAuthError.stateMismatch)
                    return
                }

                guard let code = items.first(where: { $0.name == "code" })?.value else {
                    continuation.resume(throwing: GitHubAuthError.missingCode)
                    return
                }

                continuation.resume(returning: code)
            }

            session.presentationContextProvider = self
            // Ephemeral: don't persist GitHub's own session/cookies in
            // the shared web view store. Each sign-in attempt starts
            // from a clean slate — avoids silently reusing a previously
            // authorized GitHub session the user might not expect on a
            // shared machine, and avoids leaving artifacts behind.
            session.prefersEphemeralWebBrowserSession = true

            self.activeSession = session

            guard session.start() else {
                continuation.resume(throwing: GitHubAuthError.sessionFailed(
                    NSError(domain: "GitHubLoginFlow", code: -1, userInfo: [NSLocalizedDescriptionKey: "ASWebAuthenticationSession failed to start"])
                ))
                return
            }
        }
    }

    /// Builds `https://github.com/login/oauth/authorize?...` directly —
    /// no server round-trip needed to start the flow, since none of
    /// these parameters are secret.
    private func buildAuthorizeURL(state: String) -> URL {
        var components = URLComponents(string: "https://github.com/login/oauth/authorize")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: "read:user user:email"),
            URLQueryItem(name: "state", value: state),
        ]
        return components.url!
    }

    /// A fresh, unguessable per-attempt token, sent as `state` and
    /// checked against what comes back on the callback — standard OAuth
    /// CSRF protection against a forged or replayed callback URL.
    private static func generateState() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(result == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension GitHubLoginFlow: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // Falls back to any key window only if the originally-passed
        // window has since been deallocated/closed mid-flow (e.g. the
        // app is quitting) — that's a degraded-but-non-crashing outcome,
        // not the expected path.
        presentationWindow ?? NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first ?? NSWindow()
    }
}