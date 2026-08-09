import Cocoa
import NIOPosix

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet var window: NSWindow!

    private let serverHost = "REPLACE_WITH_SERVER_HOST"
    private let serverPort = 9090
    private let githubClientID = "REPLACE_WITH_GITHUB_OAUTH_CLIENT_ID"
    private let githubRedirectURI = URL(string: "https://REPLACE_WITH_SERVER_HOST/auth/github/callback")!

    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var airlanceClient: AirlanceClient?
    private var loginViewController: LoginViewController?

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        Task { @MainActor in
            await presentLoginFlow()
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        try? eventLoopGroup.syncShutdownGracefully()
    }

    @MainActor
    private func presentLoginFlow() async {
        guard let serverPublicKey = loadServerPublicKey() else {
            presentFatalConfigError("Couldn't load wireauth_server_public_key.pem from the bundle. Replace its placeholder contents with the real server key before running.")
            return
        }

        let client = AirlanceClient(
            eventLoopGroup: eventLoopGroup,
            serverPublicKey: serverPublicKey,
            host: serverHost,
            port: serverPort
        )
        self.airlanceClient = client

        let gitHubLoginFlow = GitHubLoginFlow(clientID: githubClientID, redirectURI: githubRedirectURI)

        let loginVC = LoginViewController(client: client, gitHubLoginFlow: gitHubLoginFlow)
        loginVC.onLoginSucceeded = { [weak self] session in
            self?.handleLoginSucceeded(session)
        }
        self.loginViewController = loginVC

        window.contentViewController = loginVC
        window.makeKeyAndOrderFront(nil)

        do {
            try await client.connect()
        } catch {
            presentFatalConfigError("Couldn't connect to the server: \(error)")
        }
    }

    /// Loads wireauth_server_public_key.pem, bundled the same way
    /// test.png is (a plain resource file, not an Assets.xcassets
    /// entry) — see RSAVerifier.loadPublicKey(pem:)'s doc comment on
    /// why this is pinned config rather than fetched over the wire.
    private func loadServerPublicKey() -> SecKey? {
        guard let path = Bundle.main.path(forResource: "wireauth_server_public_key", ofType: "pem"),
              let pem = try? String(contentsOfFile: path, encoding: .utf8)
        else {
            return nil
        }
        return try? RSAVerifier.loadPublicKey(pem: pem)
    }

    /// Session persistence (Keychain) and the transition to the
    /// signed-in UI are intentionally not implemented here — this is
    /// just the minimal wiring to get the GitHub/QR login flow on
    /// screen and calling the server. See `LoginSession`'s doc comment
    /// for what a real caller is expected to do with the result.
    private func handleLoginSucceeded(_ session: LoginSession) {
        print("Login succeeded: userID=\(session.userID) authKeyID=\(session.authKeyID)")
    }

    @MainActor
    private func presentFatalConfigError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Configuration error"
        alert.informativeText = message
        alert.alertStyle = .critical
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }
}
