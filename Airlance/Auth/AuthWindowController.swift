import AirlanceClient
import Cocoa

/// Окно логина целиком в коде (AppKit, без xib/storyboard). Держит один
/// `NSWindow` и переключает содержимое между экранами email/OTP/GitHub в
/// зависимости от `AuthCoordinator.step`.
@MainActor
final class AuthWindowController: NSWindowController {
    private let coordinator: AuthCoordinator

    private let emailStep = EmailStepViewController()
    private let otpStep = OTPStepViewController()
    private let githubStep = GithubWaitingViewController()

    /// Вызывается один раз, когда координатор перешёл в `.authenticated`.
    var onAuthenticated: ((AuthSession) -> Void)?

    init(coordinator: AuthCoordinator) {
        self.coordinator = coordinator

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 380, height: 360),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "Airlance"
        window.center()
        window.isReleasedWhenClosed = false

        super.init(window: window)

        wireCallbacks()
        coordinator.onStepChanged = { [weak self] step in
            self?.render(step)
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func wireCallbacks() {
        emailStep.onSubmitEmail = { [weak self] email, firstName, lastName in
            self?.submitEmail(email: email, firstName: firstName, lastName: lastName)
        }
        emailStep.onSignInWithGithub = { [weak self] in
            self?.startGithub()
        }

        otpStep.onSubmitCode = { [weak self] code in
            self?.submitCode(code)
        }
        otpStep.onResend = { [weak self] in
            self?.resendCode()
        }
        otpStep.onBack = { [weak self] in
            self?.coordinator.backToEmailEntry()
        }

        githubStep.onCancel = { [weak self] in
            Task { await self?.coordinator.cancelGithub() }
        }
    }

    private func render(_ step: AuthStep) {
        switch step {
        case .emailEntry:
            window?.contentViewController = emailStep
        case .otpEntry(let email, _):
            otpStep.configure(email: email)
            window?.contentViewController = otpStep
        case .githubInFlight:
            window?.contentViewController = githubStep
        case .authenticated(let session):
            onAuthenticated?(session)
        }
    }

    // MARK: - Actions

    private func submitEmail(email: String, firstName: String, lastName: String) {
        emailStep.setLoading(true)
        Task {
            do {
                try await coordinator.requestEmailCode(email: email, firstName: firstName, lastName: lastName)
            } catch let error as AuthUIError {
                emailStep.showError(error.message)
            } catch {
                emailStep.showError(String(describing: error))
            }
            emailStep.setLoading(false)
        }
    }

    private func startGithub() {
        emailStep.setLoading(true)
        Task {
            do {
                try await coordinator.signInWithGithub()
            } catch let error as AuthUIError {
                emailStep.setLoading(false)
                emailStep.showError(error.message)
            } catch {
                emailStep.setLoading(false)
                emailStep.showError(String(describing: error))
            }
        }
    }

    private func submitCode(_ code: String) {
        otpStep.setLoading(true)
        Task {
            do {
                let deviceName = Host.current().localizedName ?? "Mac"
                try await coordinator.confirmCode(code, deviceName: deviceName)
            } catch let error as AuthUIError {
                otpStep.showError(error.message)
            } catch {
                otpStep.showError(String(describing: error))
            }
            otpStep.setLoading(false)
        }
    }

    private func resendCode() {
        otpStep.setLoading(true)
        Task {
            do {
                try await coordinator.resendCode(firstName: "", lastName: "")
            } catch let error as AuthUIError {
                otpStep.showError(error.message)
            } catch {
                otpStep.showError(String(describing: error))
            }
            otpStep.setLoading(false)
        }
    }
}
