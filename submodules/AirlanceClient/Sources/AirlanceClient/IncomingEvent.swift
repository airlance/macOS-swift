import Foundation

extension Protocol__Body: @unchecked Sendable {}
extension Protocol__QRTicketStatus: @unchecked Sendable {}
extension Protocol__ErrorCode: @unchecked Sendable {}

/// Серверные push-события (расшифрованные application-фреймы после handshake,
/// не являющиеся ack на прямой запрос и не являющиеся служебными Ping/Pong).
public enum IncomingEvent: Sendable {
    /// Новое входящее сообщение из чата.
    case messageUpdate(
        serverMsgID: String,
        senderAccountID: UInt64,
        text: String,
        createdAt: Int64,
        seqNo: Int64
    )

    /// Обновление статуса QR-кода при QR-авторизации.
    case qrTicketStatusUpdate(
        ticketID: String,
        status: Protocol__QRTicketStatus
    )

    /// Обобщённый push для других типов событий из union Body.
    case custom(bodyType: Protocol__Body)
}
