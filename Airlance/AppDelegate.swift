import AirlanceClient
import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet var window: NSWindow!

    let client = AirlanceClient(config: .init(
        host: "localhost", port: 8080,
        serverStaticPublicKeyHex: "ad4fa9c11c2d35f17e56a5101cd57c782415cac6cbfddc65a91ede97252de127"
    ))

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        Task {
            do {
                try await client.connect()
                print("connected ok")

                if let session = try await client.establishSession() {
                    print("resumed:", session.sessionID)
                    return
                }

                // Ничего не сохранено локально — устройство ещё не привязано
                // ни к одному аккаунту. Тут можно предложить пользователю
                // выбор: email OTP или "Sign in with GitHub".
                //
                // GitHub-ветка:
                let session = try await client.signInWithGithub(
                    httpScheme: "http",       // "https" в проде
                    httpPort: 8081,           // порт HTTP-сервера (cfg.HTTP.Addr), если не 80/443
                    osVersion: "15.1",
                    appVersion: "0.1.0"
                )
                print("signed in via github:", session.sessionID)

                // Email OTP-ветка (как было раньше) — альтернативный путь:
                // let accountID = try await client.auth!.registerAccount(
                //     email: "you@example.com", firstName: "Yura", lastName: "K"
                // )
                // let session = try await client.auth!.confirmEmailCode(
                //     accountID: accountID, code: "123456",
                //     deviceFingerprint: "unique-per-install-id",
                //     deviceName: "Yura's Mac", osVersion: "15.1", appVersion: "0.1.0"
                // )
                // try client.persistSession(session)
            } catch {
                print("airlance error:", error)
                print("airlance error (debug):", String(reflecting: error))
            }
        }
    }

    /// Ловит `airlance://auth/callback?...` после того, как GitHub OAuth
    /// в системном браузере завершился редиректом на наш custom URL scheme.
    /// Требует регистрации `CFBundleURLTypes` в Info.plist (см. ниже).
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            Task { await client.handleOpenURL(url) }
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }

}
