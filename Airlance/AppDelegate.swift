import AirlanceClient
import Cocoa
import os

@main
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let logger = Logger(subsystem: "com.airlance.app", category: "AppDelegate")
    // Outlet остаётся совместимым с существующим MainMenu.xib.
    @IBOutlet private var window: NSWindow!

    private let client = AirlanceClient(config: .init(
        // The macOS app runs outside Docker, so Docker's `api` service name
        // is not resolvable here. Port 8080 is published to the host by
        // docker-compose.
        host: "localhost",
        port: 8080,
        serverStaticPublicKeyHex: "527b8c49e9639ba7b0d2b95a623645d5e8bf55c845cff2ad206075754060db48"
    ))

    private var authCoordinator: AuthCoordinator!
    private var authWindowController: AuthWindowController?
    private var mainWindowController: NSWindowController?

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window?.orderOut(nil)

        authCoordinator = AuthCoordinator(
            client: client,
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            appVersion: appVersion,
            githubHTTPScheme: "http", // В production заменить на https.
            githubHTTPPort: 8081
        )

        let authWindow = AuthWindowController(coordinator: authCoordinator)
        authWindow.onAuthenticated = { [weak self] session in
            self?.showAuthenticatedApp(session: session)
        }
        authWindowController = authWindow
        authWindow.showWindow(nil)
        authWindow.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        Task { [weak self] in
            guard let self else { return }
            do {
                logger.info("Connecting to Airlance server host=localhost port=8080")
                try await client.connect()
                logger.info("Server connection and Noise handshake succeeded")
                _ = await authCoordinator.tryRestoreSession()
            } catch {
                logger.error("Server connection failed: \(String(describing: error), privacy: .public)")
                authWindow.showConnectionError(Self.connectionMessage(for: error))
            }
        }
    }

    /// Получает callback `airlance://auth/callback` от системного браузера.
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            Task { await client.handleOpenURL(url) }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        client.close()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    private func showAuthenticatedApp(session: AuthSession) {
        authWindowController?.close()

        let viewController = AuthenticatedViewController(session: session, client: client)
        viewController.onLogout = { [weak self] in
            self?.logout()
        }

        let mainWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 320),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        mainWindow.title = "Airlance"
        mainWindow.contentViewController = viewController
        mainWindow.center()
        mainWindowController = NSWindowController(window: mainWindow)
        mainWindowController?.showWindow(nil)
        mainWindow.makeKeyAndOrderFront(nil)
    }

    private func logout() {
        client.forgetSession()
        mainWindowController?.close()
        mainWindowController = nil
        authCoordinator.backToEmailEntry()
        authWindowController?.showWindow(nil)
    }

    private static func connectionMessage(for error: Error) -> String {
        "Не удалось подключиться к серверу: \(error.localizedDescription)"
    }
}
