import AirlanceClient
import Cocoa

/// Минимальный экран приложения после завершения auth flow.
/// Его можно заменить рабочим root-контроллером приложения, не меняя auth-слой.
@MainActor
final class AuthenticatedViewController: NSViewController {
    private let session: AuthSession
    private let client: AirlanceClient
    private var connectionStateTask: Task<Void, Never>?
    private var incomingEventsTask: Task<Void, Never>?

    private let statusLabel = NSTextField(labelWithString: "Подключено")

    var onLogout: (() -> Void)?

    init(session: AuthSession, client: AirlanceClient) {
        self.session = session
        self.client = client
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        connectionStateTask?.cancel()
        incomingEventsTask?.cancel()
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

        statusLabel.font = .systemFont(ofSize: 12, weight: .medium)
        statusLabel.textColor = .systemGreen

        let logout = NSButton(title: "Выйти", target: self, action: #selector(logout))
        logout.bezelStyle = .rounded

        let stack = NSStackView(views: [title, detail, statusLabel, logout])
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

        startMonitoringStreams()
    }

    override func viewWillDisappear() {
        super.viewWillDisappear()
        connectionStateTask?.cancel()
        connectionStateTask = nil
        incomingEventsTask?.cancel()
        incomingEventsTask = nil
    }

    private func startMonitoringStreams() {
        if let connectionState = client.connectionState {
            connectionStateTask = Task { [weak self] in
                for await state in connectionState {
                    guard !Task.isCancelled, let self else { break }
                    self.updateConnectionStateUI(state)
                }
            }
        }

        if let incomingEvents = client.incomingEvents {
            incomingEventsTask = Task { [weak self] in
                for await event in incomingEvents {
                    guard !Task.isCancelled, let self else { break }
                    self.handleIncomingEvent(event)
                }
            }
        }
    }

    private func updateConnectionStateUI(_ state: ConnectionState) {
        switch state {
        case .connected:
            statusLabel.stringValue = "Соединение активно"
            statusLabel.textColor = .systemGreen
        case .connecting:
            statusLabel.stringValue = "Подключение..."
            statusLabel.textColor = .systemOrange
        case .reconnecting(let attempt):
            statusLabel.stringValue = "Переподключение (попытка \(attempt))..."
            statusLabel.textColor = .systemOrange
        case .disconnected:
            statusLabel.stringValue = "Отключено"
            statusLabel.textColor = .systemRed
        case .failed(let message):
            statusLabel.stringValue = "Ошибка: \(message)"
            statusLabel.textColor = .systemRed
        }
    }

    private func handleIncomingEvent(_ event: IncomingEvent) {
        switch event {
        case .messageUpdate(_, _, let text, _, _):
            statusLabel.stringValue = "Новое сообщение: \(text)"
        case .qrTicketStatusUpdate(let ticketID, let status):
            statusLabel.stringValue = "QR \(ticketID): \(status)"
        case .custom(let bodyType):
            statusLabel.stringValue = "Событие: \(bodyType)"
        }
    }

    @objc private func logout() {
        onLogout?()
    }
}
