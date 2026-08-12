import Foundation
import Network

/// Тонкая обёртка над `NWConnection` с async API `readFrame()`/`writeFrame()`,
/// зеркало `transport.Connection` (internal/transport/connection.go) на клиенте.
/// Осознанно без внутреннего буфера сообщений — вызывающий код (handshake, потом
/// протокольный слой) сам решает свою модель конкуррентности, как и на сервере.
final class TCPConnection {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "airlance.tcpconnection")

    init(host: String, port: UInt16) {
        let nwHost = NWEndpoint.Host(host)
        let nwPort = NWEndpoint.Port(rawValue: port)!
        // Отключаем Nagle — протокол request/response с мелкими фреймами,
        // задержка ACK нам не нужна.
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let tcpParams = NWParameters(tls: nil, tcp: tcpOptions)
        self.connection = NWConnection(host: nwHost, port: nwPort, using: tcpParams)
    }

    func connect() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.connection.stateUpdateHandler = nil
                    continuation.resume()
                case .failed(let error):
                    self?.connection.stateUpdateHandler = nil
                    continuation.resume(throwing: error)
                case .cancelled:
                    self?.connection.stateUpdateHandler = nil
                    continuation.resume(throwing: Framing.FramingError.connectionClosed)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    /// Пишет один фрейм: [4-byte BE length][payload].
    func writeFrame(_ payload: [UInt8]) async throws {
        let framed = try Framing.encode(payload)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(framed), completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Читает ровно один фрейм: 4-байтовый length prefix, затем тело.
    func readFrame() async throws -> [UInt8] {
        let prefix = try await readExactly(Framing.lengthPrefixSize)
        let length = try Framing.decodeLength(prefix)
        if length == 0 {
            return []
        }
        return try await readExactly(length)
    }

    private func readExactly(_ count: Int) async throws -> [UInt8] {
        var buffer = [UInt8]()
        buffer.reserveCapacity(count)
        while buffer.count < count {
            let remaining = count - buffer.count
            let chunk = try await receive(minimumLength: 1, maximumLength: remaining)
            buffer.append(contentsOf: chunk)
        }
        return buffer
    }

    private func receive(minimumLength: Int, maximumLength: Int) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
            connection.receive(minimumIncompleteLength: minimumLength, maximumLength: maximumLength) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if let data, !data.isEmpty {
                    continuation.resume(returning: [UInt8](data))
                    return
                }
                if isComplete {
                    continuation.resume(throwing: Framing.FramingError.connectionClosed)
                    return
                }
                continuation.resume(returning: [])
            }
        }
    }

    func close() {
        connection.cancel()
    }
}
