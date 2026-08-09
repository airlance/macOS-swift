import Cocoa

/// The app's entry screen: shows a QR code the user scans with their
/// phone (macOS acts as the "waiter" — `GenerateQRLogin` +
/// `WaitQRLoginResult`, see auth.fbs's doc comments on those RPCs), with
/// "Sign in with GitHub" as a parallel option.
///
/// Adapted from the visual design of the old (pre-gRPC/flatbuffers)
/// `LoginViewController` — same card layout, countdown timer, and
/// confirm-overlay pattern — but driven by `AirlanceClient` instead of
/// `SecureSocket`, and using the real generated flatbuffers types
/// instead of a hand-written wire protocol.
final class LoginViewController: NSViewController {

    /// Called once a login (QR or GitHub) succeeds, with the resulting
    /// session. The caller (typically an app-level coordinator) is
    /// responsible for persisting `resumeSecret` (e.g. into Keychain —
    /// see the note on `LoginSession` below) and transitioning to the
    /// signed-in UI.
    var onLoginSucceeded: ((LoginSession) -> Void)?

    private let client: AirlanceClient
    private let gitHubLoginFlow: GitHubLoginFlow

    private var qrExpiryTimer: Timer?
    private var qrCountdownTimer: Timer?
    private var qrExpiresAtMs: Int64?

    /// Tracks the in-flight WaitQRLoginResult stream so a QR refresh
    /// (new GenerateQRLogin call) can cancel the previous wait rather
    /// than leaving it running against a now-stale token.
    private var waitQRTask: Task<Void, Never>?

    // MARK: - Left column: copy + steps

    private let titleLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "Log in with\nyour phone")
        label.font = .systemFont(ofSize: 44, weight: .heavy)
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let subtitleLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "Scan the QR code with the Airlance app on your phone to sign in instantly — no password required.")
        label.font = .systemFont(ofSize: 14)
        label.textColor = .secondaryLabelColor
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    // MARK: - Right column: QR card

    private let qrCardTitle: NSTextField = {
        let label = NSTextField(labelWithString: "Scan to sign in")
        label.font = .systemFont(ofSize: 15, weight: .semibold)
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let qrCardSubtitle: NSTextField = {
        let label = NSTextField(labelWithString: "")
        label.font = .systemFont(ofSize: 12)
        label.textColor = .secondaryLabelColor
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let refreshQRButton: NSButton = {
        let button = NSButton(image: NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: "Refresh code") ?? NSImage(), target: nil, action: nil)
        button.bezelStyle = .circular
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    private let qrWhitePanel: NSView = {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.white.cgColor
        view.layer?.cornerRadius = 14
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    private let qrCodeView = QRCodeImageView()

    private let confirmOverlay: NSView = {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.72).cgColor
        view.layer?.cornerRadius = 14
        view.isHidden = true
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    private let confirmSpinner: NSProgressIndicator = {
        let indicator = NSProgressIndicator()
        indicator.style = .spinning
        indicator.isDisplayedWhenStopped = false
        indicator.translatesAutoresizingMaskIntoConstraints = false
        return indicator
    }()

    private let confirmLabel: NSTextField = {
        let label = NSTextField(labelWithString: "Confirm on your phone\u{2026}")
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.textColor = .white
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let statusLabel: NSTextField = {
        let label = NSTextField(labelWithString: "")
        label.font = .systemFont(ofSize: 12, weight: .medium)
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    // MARK: - GitHub sign-in

    private let gitHubButton: NSButton = {
        let button = NSButton(title: "Sign in with GitHub", target: nil, action: nil)
        button.bezelStyle = .rounded
        button.controlSize = .large
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    // MARK: - Init

    init(client: AirlanceClient, gitHubLoginFlow: GitHubLoginFlow) {
        self.client = client
        self.gitHubLoginFlow = gitHubLoginFlow
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not used — this app builds its UI programmatically.")
    }

    // MARK: - Lifecycle

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 820, height: 460))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setUpLayout()
        setUpActions()
        startQRLoginFlow()
    }

    deinit {
        qrExpiryTimer?.invalidate()
        qrCountdownTimer?.invalidate()
        waitQRTask?.cancel()
    }

    // MARK: - QR login flow

    /// Requests a fresh QR token and starts waiting for it to be
    /// scanned+confirmed. Cancels any previous in-flight wait first —
    /// calling this twice in quick succession (e.g. user mashing
    /// refresh) must not leave two competing WaitQRLoginResult streams
    /// racing to call `onLoginSucceeded` with different sessions.
    private func startQRLoginFlow() {
        waitQRTask?.cancel()
        qrExpiryTimer?.invalidate()
        qrCountdownTimer?.invalidate()
        confirmOverlay.isHidden = true
        qrCodeView.value = nil
        setQRStatus("Preparing QR code…")
        setDeviceStatus("Waiting for scan…")

        waitQRTask = Task { [weak self] in
            guard let self else { return }
            await self.runQRLoginFlow()
        }
    }

    private func runQRLoginFlow() async {
        do {
            let response = try await client.generateQRLogin(clientCtx: currentClientContext())
            if Task.isCancelled { return }

            qrCodeView.value = response.token
            setQRStatus("Ready to scan")
            scheduleExpiryTimer(expiresAtMs: response.expiresAtMs)

            // `runQRLoginFlow` is already MainActor-isolated (it's an
            // instance method on an NSViewController), so `for try
            // await` resumes back on MainActor after every suspension —
            // no manual `Task { @MainActor in ... }` hop needed the way
            // the old per-event callback required, since that callback
            // was invoked from AirlanceClient's NIO event-loop thread,
            // outside Swift Concurrency's isolation tracking entirely.
            let events = await client.waitQRLoginResult(token: response.token ?? "")
            for try await event in events {
                if Task.isCancelled { break }
                handleQRLoginEvent(event)
            }
        } catch is CancellationError {
            // A refresh (or view teardown) cancelled this flow — the
            // next startQRLoginFlow() call (or nothing, if the view is
            // going away) owns what happens next, not this one.
        } catch {
            if Task.isCancelled { return }
            setQRStatus("Couldn't reach the server")
            setDeviceStatus("Error")
            presentError("Failed to prepare QR sign-in: \(error)")
        }
    }

    /// `payload` is a flatbuffers union — see qrlogin_generated's
    /// `authv1_QRLoginEventPayloadUnion` and the Generated/README.md note
    /// on it. Confirmed and Expired/Rejected are the only two variants
    /// the schema defines; `.none_`/an unset payload is treated as a
    /// no-op rather than a crash, since a defensively-written client
    /// shouldn't trust a server to never send a degenerate event.
    private func handleQRLoginEvent(_ event: authv1_QRLoginEventT) {
        guard let payload = event.payload else {
            setQRStatus("Unexpected response from server")
            return
        }

        switch payload.type {
        case .qrloginconfirmed:
            guard let confirmed = payload.value as? authv1_QRLoginConfirmedT else { return }
            confirmOverlay.isHidden = false
            setDeviceStatus("Confirmed")
            let session = LoginSession(
                authKeyID: confirmed.authKeyId,
                userID: confirmed.userId,
                resumeSecret: confirmed.resumeSecret ?? ""
            )
            onLoginSucceeded?(session)

        case .qrloginexpiredorrejected:
            guard let expiredOrRejected = payload.value as? authv1_QRLoginExpiredOrRejectedT else { return }
            qrExpiryTimer?.invalidate()
            qrCountdownTimer?.invalidate()
            setQRStatus(message(for: expiredOrRejected.reason))
            setDeviceStatus("Not signed in")

        case .none_:
            break
        }
    }

    private func message(for reason: authv1_QRLoginFailReason) -> String {
        switch reason {
        case .tokenexpired: return "Code expired — refresh to try again"
        case .alreadyused: return "This code was already used"
        case .notfound: return "Code not found — refresh to try again"
        case .unknown: return "Sign-in was not completed"
        }
    }

    /// What this client identifies itself as to the server on every
    /// call that doesn't yet have a session — see auth.fbs's
    /// `ClientContext` doc comment ("server derives IPAddress from the
    /// peer connection, not from this table").
    private func currentClientContext() -> authv1_ClientContextT {
        let ctx = authv1_ClientContextT()
        ctx.platform = .macos
        ctx.os = ProcessInfo.processInfo.operatingSystemVersionString
        ctx.deviceName = Host.current().localizedName
        ctx.userAgent = "Airlance-macOS/1.0"
        return ctx
    }

    // MARK: - GitHub sign-in

    @objc private func handleGitHubSignIn() {
        guard let window = view.window else { return }
        gitHubButton.isEnabled = false

        Task { [weak self] in
            guard let self else { return }
            defer { self.gitHubButton.isEnabled = true }

            do {
                let code = try await self.gitHubLoginFlow.signIn(presentationAnchor: window)
                let response = try await self.client.loginByGithub(code: code, clientCtx: self.currentClientContext())
                let session = LoginSession(
                    authKeyID: response.authKeyId,
                    userID: response.userId,
                    resumeSecret: response.resumeSecret ?? ""
                )
                self.onLoginSucceeded?(session)
            } catch GitHubLoginFlow.GitHubAuthError.cancelled {
                // user dismissed the auth sheet — nothing to show
            } catch {
                self.presentError("Failed to sign in with GitHub: \(error)")
            }
        }
    }

    // MARK: - Layout

    private func setUpLayout() {
        let leftStack = NSStackView(views: [titleLabel, subtitleLabel, gitHubButton])
        leftStack.orientation = .vertical
        leftStack.alignment = .leading
        leftStack.spacing = 16
        leftStack.setCustomSpacing(28, after: subtitleLabel)
        leftStack.translatesAutoresizingMaskIntoConstraints = false

        let qrHeaderStack = NSStackView(views: [qrCardTitle, qrCardSubtitle])
        qrHeaderStack.orientation = .vertical
        qrHeaderStack.spacing = 2
        qrHeaderStack.alignment = .leading
        qrHeaderStack.translatesAutoresizingMaskIntoConstraints = false

        qrWhitePanel.addSubview(qrCodeView)
        qrCodeView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            qrCodeView.centerXAnchor.constraint(equalTo: qrWhitePanel.centerXAnchor),
            qrCodeView.centerYAnchor.constraint(equalTo: qrWhitePanel.centerYAnchor),
            qrCodeView.widthAnchor.constraint(equalToConstant: 200),
            qrCodeView.heightAnchor.constraint(equalToConstant: 200),
        ])

        qrWhitePanel.addSubview(confirmOverlay)
        let overlayStack = NSStackView(views: [confirmSpinner, confirmLabel])
        overlayStack.orientation = .vertical
        overlayStack.spacing = 10
        overlayStack.alignment = .centerX
        overlayStack.translatesAutoresizingMaskIntoConstraints = false
        confirmOverlay.addSubview(overlayStack)
        NSLayoutConstraint.activate([
            confirmOverlay.leadingAnchor.constraint(equalTo: qrWhitePanel.leadingAnchor),
            confirmOverlay.trailingAnchor.constraint(equalTo: qrWhitePanel.trailingAnchor),
            confirmOverlay.topAnchor.constraint(equalTo: qrWhitePanel.topAnchor),
            confirmOverlay.bottomAnchor.constraint(equalTo: qrWhitePanel.bottomAnchor),
            overlayStack.centerXAnchor.constraint(equalTo: confirmOverlay.centerXAnchor),
            overlayStack.centerYAnchor.constraint(equalTo: confirmOverlay.centerYAnchor),
        ])

        let cardStack = NSStackView(views: [qrHeaderStack, qrWhitePanel, statusLabel])
        cardStack.orientation = .vertical
        cardStack.spacing = 14
        cardStack.alignment = .centerX
        cardStack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(leftStack)
        view.addSubview(cardStack)
        view.addSubview(refreshQRButton)

        NSLayoutConstraint.activate([
            leftStack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            leftStack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            leftStack.widthAnchor.constraint(equalToConstant: 340),

            cardStack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            cardStack.centerYAnchor.constraint(equalTo: view.centerYAnchor),

            refreshQRButton.centerYAnchor.constraint(equalTo: qrHeaderStack.centerYAnchor),
            refreshQRButton.trailingAnchor.constraint(equalTo: cardStack.trailingAnchor),
            refreshQRButton.widthAnchor.constraint(equalToConstant: 28),
            refreshQRButton.heightAnchor.constraint(equalToConstant: 28),

            qrWhitePanel.widthAnchor.constraint(equalToConstant: 300),
            qrWhitePanel.heightAnchor.constraint(equalToConstant: 300),
        ])
    }

    private func setUpActions() {
        refreshQRButton.target = self
        refreshQRButton.action = #selector(handleRefreshQR)
        gitHubButton.target = self
        gitHubButton.action = #selector(handleGitHubSignIn)
    }

    @objc private func handleRefreshQR() {
        startQRLoginFlow()
    }

    // MARK: - Status helpers

    private func setQRStatus(_ text: String) {
        qrCardSubtitle.stringValue = text
    }

    private func setDeviceStatus(_ text: String) {
        statusLabel.stringValue = text
    }

    private func scheduleExpiryTimer(expiresAtMs: Int64) {
        qrExpiryTimer?.invalidate()
        qrCountdownTimer?.invalidate()
        qrExpiresAtMs = expiresAtMs

        let msLeft = Double(expiresAtMs) - Date().timeIntervalSince1970 * 1000
        guard msLeft > 0 else { return }

        qrExpiryTimer = Timer.scheduledTimer(withTimeInterval: msLeft / 1000, repeats: false) { [weak self] _ in
            self?.setQRStatus("Code expired")
            self?.setDeviceStatus("Code expired")
        }

        updateCountdownLabel()
        qrCountdownTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.updateCountdownLabel()
        }
    }

    private func updateCountdownLabel() {
        guard let qrExpiresAtMs else { return }
        let msLeft = Double(qrExpiresAtMs) - Date().timeIntervalSince1970 * 1000
        guard msLeft > 0 else {
            qrCountdownTimer?.invalidate()
            return
        }
        let totalSeconds = Int(msLeft / 1000)
        let minutes = totalSeconds / 60
        let seconds = totalSeconds % 60
        setQRStatus(String(format: "Expires in %02d:%02d", minutes, seconds))
    }

    private func presentError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Error"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.alertStyle = .warning
        if let window = view.window {
            alert.beginSheetModal(for: window)
        } else {
            alert.runModal()
        }
    }
}

/// The result of a successful login (QR or GitHub), independent of which
/// path produced it. `resumeSecret` is what `ResumeSession` needs on a
/// later launch — the caller is responsible for storing it securely
/// (Keychain, not UserDefaults) and never logging it.
struct LoginSession {
    let authKeyID: UInt64
    let userID: Int32
    let resumeSecret: String
}