import Cocoa

/// Показывается, пока пользователь авторизуется в системном браузере
/// (ждём deep-link `airlance://auth/callback`).
final class GithubWaitingViewController: NSViewController {
    var onCancel: (() -> Void)?

    private let titleLabel = NSTextField(labelWithString: "Ожидаем подтверждение в браузере…")
    private let subtitleLabel = NSTextField(
        labelWithString: "Завершите вход в GitHub во вкладке браузера, которая только что открылась."
    )
    private let spinner = NSProgressIndicator()
    private let cancelButton = NSButton(title: "Отмена", target: nil, action: nil)

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 200))
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        titleLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        titleLabel.alignment = .center
        titleLabel.maximumNumberOfLines = 2
        titleLabel.lineBreakMode = .byWordWrapping

        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.alignment = .center
        subtitleLabel.maximumNumberOfLines = 3
        subtitleLabel.lineBreakMode = .byWordWrapping

        spinner.style = .spinning
        spinner.controlSize = .regular
        spinner.startAnimation(nil)

        cancelButton.bezelStyle = .rounded
        cancelButton.target = self
        cancelButton.action = #selector(handleCancel)

        let stack = NSStackView(views: [spinner, titleLabel, subtitleLabel, cancelButton])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            titleLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            subtitleLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    @objc private func handleCancel() {
        onCancel?()
    }
}
