import Cocoa

/// Шаг 2: ввод 6-значного OTP-кода, присланного на email из шага 1.
final class OTPStepViewController: NSViewController {
    var onSubmitCode: ((_ code: String) -> Void)?
    var onResend: (() -> Void)?
    var onBack: (() -> Void)?

    private let titleLabel = NSTextField(labelWithString: "Введите код")
    private let subtitleLabel = NSTextField(labelWithString: "")

    private let codeField = NSTextField()
    private let errorLabel = NSTextField(labelWithString: "")
    private let confirmButton = NSButton(title: "Подтвердить", target: nil, action: nil)
    private let spinner = NSProgressIndicator()
    private let resendButton = NSButton(title: "Отправить код ещё раз", target: nil, action: nil)
    private let backButton = NSButton(title: "Назад", target: nil, action: nil)

    private var email: String = ""

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 300))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setupLayout()
    }

    /// Обновляет подпись под заголовком с email, на который отправлен код.
    /// Вызывать перед показом этого VC.
    func configure(email: String) {
        self.email = email
        subtitleLabel.stringValue = "Мы отправили код на \(email)"
        codeField.stringValue = ""
        hideError()
    }

    private func setupLayout() {
        titleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.lineBreakMode = .byWordWrapping

        codeField.placeholderString = "123456"
        codeField.bezelStyle = .roundedBezel
        codeField.font = .monospacedDigitSystemFont(ofSize: 18, weight: .regular)
        codeField.alignment = .center
        codeField.target = self
        codeField.action = #selector(handleConfirm)

        errorLabel.font = .systemFont(ofSize: 11)
        errorLabel.textColor = .systemRed
        errorLabel.isHidden = true
        errorLabel.maximumNumberOfLines = 3
        errorLabel.lineBreakMode = .byWordWrapping

        confirmButton.bezelStyle = .rounded
        confirmButton.keyEquivalent = "\r"
        confirmButton.target = self
        confirmButton.action = #selector(handleConfirm)

        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false

        resendButton.bezelStyle = .inline
        resendButton.isBordered = false
        resendButton.contentTintColor = .linkColor
        resendButton.target = self
        resendButton.action = #selector(handleResend)

        backButton.bezelStyle = .inline
        backButton.isBordered = false
        backButton.contentTintColor = .secondaryLabelColor
        backButton.target = self
        backButton.action = #selector(handleBack)

        let confirmRow = NSStackView(views: [confirmButton, spinner])
        confirmRow.orientation = .horizontal
        confirmRow.spacing = 8

        let footerRow = NSStackView(views: [backButton, resendButton])
        footerRow.orientation = .horizontal
        footerRow.spacing = 16

        let stack = NSStackView(views: [
            titleLabel,
            subtitleLabel,
            codeField,
            errorLabel,
            confirmRow,
            footerRow,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.setCustomSpacing(20, after: subtitleLabel)
        stack.setCustomSpacing(4, after: codeField)
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 24),

            codeField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            errorLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    @objc private func handleConfirm() {
        let code = codeField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else {
            showError("Введите код из письма")
            return
        }
        hideError()
        onSubmitCode?(code)
    }

    @objc private func handleResend() {
        hideError()
        onResend?()
    }

    @objc private func handleBack() {
        hideError()
        onBack?()
    }

    func setLoading(_ loading: Bool) {
        confirmButton.isEnabled = !loading
        resendButton.isEnabled = !loading
        backButton.isEnabled = !loading
        if loading {
            spinner.startAnimation(nil)
        } else {
            spinner.stopAnimation(nil)
        }
    }

    func showError(_ message: String) {
        errorLabel.stringValue = message
        errorLabel.isHidden = false
    }

    func hideError() {
        errorLabel.isHidden = true
    }
}
