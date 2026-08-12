import Foundation

/// Зеркало `internal/transport/framing.go`: 4-байтовый big-endian length prefix,
/// затем тело фрейма. MaxFrameSize совпадает с серверным лимитом — если когда-нибудь
/// изменится на сервере, поменяй и здесь.
enum Framing {
    static let lengthPrefixSize = 4
    static let maxFrameSize = 1 << 20 // 1 MiB, как MaxFrameSize в framing.go

    enum FramingError: Error, CustomStringConvertible {
        case frameTooLarge(size: Int)
        case connectionClosed

        var description: String {
            switch self {
            case .frameTooLarge(let size):
                return "airlance: frame exceeds max size (\(size) > \(Framing.maxFrameSize))"
            case .connectionClosed:
                return "airlance: connection closed while reading frame"
            }
        }
    }

    /// Кодирует payload как [4-byte BE length][payload], готово к записи в сокет.
    static func encode(_ payload: [UInt8]) throws -> [UInt8] {
        guard payload.count <= maxFrameSize else {
            throw FramingError.frameTooLarge(size: payload.count)
        }
        var lengthPrefix = withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Array($0) }
        lengthPrefix.append(contentsOf: payload)
        return lengthPrefix
    }

    /// Парсит length prefix из первых 4 байт. Не аллоцирует тело — вызывающий код
    /// сам решает, сколько байт ждать дальше (см. TCPConnection.readFrame).
    static func decodeLength(_ prefix: [UInt8]) throws -> Int {
        precondition(prefix.count == lengthPrefixSize)
        let length = prefix.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard length <= UInt32(maxFrameSize) else {
            throw FramingError.frameTooLarge(size: Int(length))
        }
        return Int(length)
    }
}
