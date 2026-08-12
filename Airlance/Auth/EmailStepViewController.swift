import Cocoa

/// Шаг 1: email + имя/фамилия, плюс кнопка "Sign in with GitHub".
/// Полностью в коде — без xib/storyboard.
final class EmailStepViewController: NSViewController {
    var onSubmitEmail: ((_ email: String, _ firstName: String, _ lastName: String) -> Void)?
    var onSignInWithGithub: (() -> Void)?

    private let titleLabel = NSTextField(labelWithString: "Войти в Airlance")
    private let subtitleLabel = NSTextField(labelWithString: "Введите email, чтобы получить код подтверждения")

    private let firstNameField = NSTextField()
    private let lastNameField = NSTextField()
    private let emailField = NSTextField()

    private let errorLabel = NSTextField(labelWithString: "")
    private let continueButton = NSButton(title: "Продолжить", target: nil, action: nil)
    private let githubButton = NSButton(title: "Войти через GitHub", target: nil, action: nil)
    private let spinner = NSProgressIndicator()

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 360))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setupLayout()
    }

    private func setupLayout() {
        titleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor

        firstNameField.placeholderString = "Имя"
        lastNameField.placeholderString = "Фамилия"
        emailField.placeholderString = "you@example.com"

        for field in [firstNameField, lastNameField, emailField] {
            field.bezelStyle = .roundedBezel
            field.target = self
            field.action = #selector(handleSubmit)
        }

        errorLabel.font = .systemFont(ofSize: 11)
        errorLabel.textColor = .systemRed
        errorLabel.isHidden = true
        errorLabel.maximumNumberOfLines = 3
        errorLabel.lineBreakMode = .byWordWrapping

        continueButton.bezelStyle = .rounded
        continueButton.keyEquivalent = "\r"
        continueButton.target = self
        continueButton.action = #selector(handleSubmit)

        githubButton.bezelStyle = .rounded
        githubButton.target = self
        githubButton.action = #selector(handleGithub)

        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false

        let nameStack = NSStackView(views: [firstNameField, lastNameField])
        nameStack.orientation = .horizontal
        nameStack.distribution = .fillEqually
        nameStack.spacing = 8

        let buttonRow = NSStackView(views: [continueButton, spinner])
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 8

        let separatorLabel = NSTextField(labelWithString: "или")
        separatorLabel.font = .systemFont(ofSize: 11)
        separatorLabel.textColor = .tertiaryLabelColor
        separatorLabel.alignment = .center

        let stack = NSStackView(views: [
            titleLabel,
            subtitleLabel,
            nameStack,
            emailField,
            errorLabel,
            buttonRow,
            separatorLabel,
            githubButton,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.setCustomSpacing(20, after: subtitleLabel)
        stack.setCustomSpacing(4, after: emailField)
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 24),

            nameStack.widthAnchor.constraint(equalTo: stack.widthAnchor),
            emailField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            errorLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            separatorLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            githubButton.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    @objc private func handleSubmit() {
        let email = emailField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidEmail(email) else {
            showError("Введите корректный email")
            return
        }
        hideError()
        onSubmitEmail?(
            email,
            firstNameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            lastNameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    @objc private func handleGithub() {
        hideError()
        onSignInWithGithub?()
    }

    func setLoading(_ loading: Bool) {
        continueButton.isEnabled = !loading
        githubButton.isEnabled = !loading
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

    private func isValidEmail(_ email: String) -> Bool {
        guard !email.isEmpty, let atIndex = email.firstIndex(of: "@") else { return false }
        let domain = email[email.index(after: atIndex)...]
        return domain.contains(".") && !domain.hasPrefix(".") && !email.hasSuffix(".")
    }
}
