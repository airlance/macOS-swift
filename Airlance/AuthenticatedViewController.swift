import AirlanceClient
import Cocoa

/// Минимальный экран приложения после завершения auth flow.
/// Его можно заменить рабочим root-контроллером приложения, не меняя auth-слой.
@MainActor
final class AuthenticatedViewController: NSViewController {
    private let session: AuthSession
    var onLogout: (() -> Void)?

    init(session: AuthSession) {
        self.session = session
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 520, height: 320))
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        let title = NSTextField(labelWithString: "Вы вошли в Airlance")
        title.font = .systemFont(ofSize: 22, weight: .semibold)

        let detail = NSTextField(labelWithString: "Сессия: \(session.sessionID)")
        detail.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingMiddle

        let logout = NSButton(title: "Выйти", target: self, action: #selector(logout))
        logout.bezelStyle = .rounded

        let stack = NSStackView(views: [title, detail, logout])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            detail.widthAnchor.constraint(lessThanOrEqualToConstant: 440),
        ])
    }

    @objc private func logout() {
        onLogout?()
    }
}
