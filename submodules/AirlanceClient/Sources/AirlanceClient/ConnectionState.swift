import Foundation

/// Состояние сетевого подключения к серверу Airlance.
public enum ConnectionState: Sendable, Equatable {
    /// Соединение не установлено / разорвано.
    case disconnected
    /// В процессе подключения / выполнения Noise handshake.
    case connecting
    /// Соединение установлено и готово к обмену данными.
    case connected
    /// Попытка восстановления соединения после разрыва.
    case reconnecting(attempt: Int)
    /// Ошибка подключения / критический сбой.
    case failed(String)
}
