import Foundation
import CryptoKit
import os

/// Состояние подключения `NoiseTransport`. Используется как internal guard против
/// повторного параллельного `connect()` — actor isolation защищает только от гонки
/// *данных*, не от гонки *логики*: без явного guard'а второй вызов `connect()` во
/// время уже идущего handshake проскочит между await-точками (actor reentrancy) и
/// запустит второй handshake поверх первого. См. AGENTS.md §4.
enum NoiseTransportState {
    case idle
    case connecting
    case connected
    case closed
}

/// Единственный владелец send/recv `CipherState` и TCP-соединения. Зеркало
/// `internal/noiseik/conn.go` на сервере.
///
/// Выполнен как `actor` — крипто-состояние (в первую очередь monotonic nonce counter
/// внутри `CipherState`) строго изолировано.
///
/// Фазы 2 и 3:
/// - Единый `readLoopTask` непрерывно читает фреймы, расшифровывает и демультиплексирует:
///   Ping/Pong -> heartbeat handler,
///   request_id -> ожидающая continuation (request/response),
///   server push -> `incomingEvents: AsyncStream<IncomingEvent>`.
/// - `connectionState: AsyncStream<ConnectionState>` передаёт изменения статуса подключения.
/// - Фоновый Heartbeat (Ping/Pong) следит за активностью соединения.
actor NoiseTransport {
    private let logger = Logger(subsystem: "com.airlance.client", category: "NoiseTransport")
    private(set) var state: NoiseTransportState = .idle

    // CipherState/TCPConnection не Sendable, но это безопасно: оба создаются внутри
    // connect() (actor-isolated) и никогда не покидают NoiseTransport — не пересекают
    // границу actor'а наружу, поэтому Sendable-конформанс им не требуется.
    private var raw: TCPConnection?
    private var sendCipher: CipherState?
    private var recvCipher: CipherState?

    private(set) var remoteStaticKey: [UInt8] = []
    private(set) var handshakeHash: [UInt8] = []

    private let host: String
    private let port: UInt16
    private let serverStaticPublicKey: Curve25519.KeyAgreement.PublicKey
    private let clientStaticKeypair: Curve25519.KeyAgreement.PrivateKey

    // Push events stream
    nonisolated let incomingEvents: AsyncStream<IncomingEvent>
    private let incomingContinuation: AsyncStream<IncomingEvent>.Continuation

    // Connection lifecycle stream
    nonisolated let connectionState: AsyncStream<ConnectionState>
    private let connectionContinuation: AsyncStream<ConnectionState>.Continuation

    // Request/Response continuations by request_id
    private var pendingRequests: [UInt64: CheckedContinuation<Protocol__Envelope, Error>] = [:]

    // Background tasks
    private var readLoopTask: Task<Void, Never>?
    private var heartbeatTask: Task<Void, Never>?
    private var missedHeartbeats: Int = 0

    init(
        host: String,
        port: UInt16,
        serverStaticPublicKey: Curve25519.KeyAgreement.PublicKey,
        clientStaticKeypair: Curve25519.KeyAgreement.PrivateKey
    ) {
        self.host = host
        self.port = port
        self.serverStaticPublicKey = serverStaticPublicKey
        self.clientStaticKeypair = clientStaticKeypair

        let (incomingStream, incomingContinuation) = AsyncStream<IncomingEvent>.makeStream()
        self.incomingEvents = incomingStream
        self.incomingContinuation = incomingContinuation

        let (connStream, connContinuation) = AsyncStream<ConnectionState>.makeStream()
        self.connectionState = connStream
        self.connectionContinuation = connContinuation
    }

    /// Устанавливает TCP-соединение и проходит клиентский Noise IK handshake.
    /// После успешного handshake сразу запускает `readLoopTask` и `heartbeatTask`
    /// до возврата из `connect()`.
    func connect() async throws {
        guard state == .idle else {
            throw ProtocolError.alreadyConnectingOrConnected
        }
        state = .connecting
        connectionContinuation.yield(.connecting)
        logger.info("Connection started host=\(self.host, privacy: .public) port=\(self.port, privacy: .public)")

        do {
            let tcp = TCPConnection(host: host, port: port)
            try await tcp.connect()
            logger.info("TCP connected; starting Noise IK handshake")

            let hs = HandshakeState(
                staticKeypair: clientStaticKeypair,
                remoteStaticPublicKey: serverStaticPublicKey
            )

            let msg1 = try hs.writeMessage1()
            try await tcp.writeFrame(msg1)
            logger.debug("Noise IK message 1 sent")

            let msg2 = try await tcp.readFrame()
            logger.debug("Noise IK message 2 received")
            try hs.readMessage2(msg2)

            let (cs1, cs2) = hs.split()
            // initiator: send = cs1, recv = cs2 (см. splitByRole(initiator: true, ...) в Go)
            self.raw = tcp
            self.sendCipher = cs1
            self.recvCipher = cs2
            self.remoteStaticKey = [UInt8](serverStaticPublicKey.rawRepresentation)
            self.handshakeHash = hs.handshakeHash
            self.state = .connected
            self.missedHeartbeats = 0

            connectionContinuation.yield(.connected)

            startReadLoop()
            startHeartbeat()
            logger.info("Connection established")
        } catch {
            state = .idle
            connectionContinuation.yield(.failed(error.localizedDescription))
            logger.error("Connection failed: \(String(describing: error), privacy: .public)")
            throw error
        }
    }

    /// Отправляет фрейм с ожиданием ack-ответа по `requestID`.
    /// Регистрирует continuation в `pendingRequests` ДО записи в сокет,
    /// чтобы исключить race condition при быстром ответе сервера.
    func request(_ frame: [UInt8], expecting requestID: UInt64) async throws -> Protocol__Envelope {
        guard state == .connected, let raw, let sendCipher else {
            throw ProtocolError.notConnected
        }
        let ciphertext = try sendCipher.encryptWithAd([], plaintext: frame)
        return try await withCheckedThrowingContinuation { continuation in
            self.pendingRequests[requestID] = continuation
            Task {
                do {
                    try await raw.writeFrame(ciphertext)
                } catch {
                    self.failPendingRequest(requestID: requestID, error: error)
                }
            }
        }
    }

    private func failPendingRequest(requestID: UInt64, error: Error) {
        if let pending = pendingRequests.removeValue(forKey: requestID) {
            pending.resume(throwing: error)
        }
    }

    /// Пишет один application-фрейм (например, pong или служебное сообщение).
    func writeFrame(_ plaintext: [UInt8]) async throws {
        guard state == .connected, let raw, let sendCipher else {
            throw ProtocolError.notConnected
        }
        let ciphertext = try sendCipher.encryptWithAd([], plaintext: plaintext)
        try await raw.writeFrame(ciphertext)
    }

    /// Основной цикл чтения сокета: непрерывно читает фреймы, расшифровывает
    /// и диспетчеризирует их.
    private func startReadLoop() {
        readLoopTask?.cancel()
        readLoopTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { break }
                do {
                    let frame = try await self.readAndDecryptNextFrame()
                    await self.handleIncomingFrame(frame)
                } catch {
                    if !Task.isCancelled {
                        await self.handleReadError(error)
                    }
                    break
                }
            }
        }
    }

    private func readAndDecryptNextFrame() async throws -> [UInt8] {
        guard state == .connected, let raw, let recvCipher else {
            throw ProtocolError.notConnected
        }
        let ciphertext = try await raw.readFrame()
        return try recvCipher.decryptWithAd([], ciphertext: ciphertext)
    }

    private func handleIncomingFrame(_ frame: [UInt8]) async {
        guard let envelope = try? ProtocolCodec.decodeEnvelope(frame) else {
            return
        }

        // 1. Heartbeat Ping -> отвечаем Pong
        if envelope.bodyType == .ping {
            let ping: Protocol__Ping? = envelope.body(type: Protocol__Ping.self)
            let timestamp = ping?.timestamp ?? 0
            let pongFrame = ProtocolCodec.encodePong(requestID: envelope.requestId, timestamp: timestamp)
            try? await writeFrame(pongFrame)
            return
        }

        // 2. Heartbeat Pong -> сбрасываем счётчик пропущенных
        if envelope.bodyType == .pong {
            missedHeartbeats = 0
            return
        }

        // 3. Request/Response ack
        if let pending = pendingRequests.removeValue(forKey: envelope.requestId) {
            pending.resume(returning: envelope)
            return
        }

        // 4. Server-push событие
        if let event = mapToIncomingEvent(envelope) {
            incomingContinuation.yield(event)
        }
    }

    private func mapToIncomingEvent(_ envelope: Protocol__Envelope) -> IncomingEvent? {
        switch envelope.bodyType {
        case .messageupdate:
            guard let update: Protocol__MessageUpdate = envelope.body(type: Protocol__MessageUpdate.self) else {
                return nil
            }
            return .messageUpdate(
                serverMsgID: update.serverMsgId ?? "",
                senderAccountID: update.senderAccountId,
                text: update.text ?? "",
                createdAt: update.createdAt,
                seqNo: update.seqNo
            )
        case .qrticketstatusupdate:
            guard let update: Protocol__QRTicketStatusUpdate = envelope.body(type: Protocol__QRTicketStatusUpdate.self) else {
                return nil
            }
            return .qrTicketStatusUpdate(
                ticketID: update.ticketId ?? "",
                status: update.status
            )
        case .none_, .ping, .pong:
            return nil
        default:
            return .custom(bodyType: envelope.bodyType)
        }
    }

    private func handleReadError(_ error: Error) {
        heartbeatTask?.cancel()
        heartbeatTask = nil

        // Резолвим все висящие запросы ошибкой
        for (_, continuation) in pendingRequests {
            continuation.resume(throwing: error)
        }
        pendingRequests.removeAll()

        raw?.close()
        raw = nil
        sendCipher = nil
        recvCipher = nil

        if state != .closed {
            state = .idle
            connectionContinuation.yield(.failed(error.localizedDescription))
            connectionContinuation.yield(.disconnected)
            incomingContinuation.finish()
        }
    }

    /// Фоновый Heartbeat таймер (каждые 15 секунд).
    private func startHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                guard !Task.isCancelled, let self else { break }
                let shouldContinue = await self.tickHeartbeat()
                if !shouldContinue { break }
            }
        }
    }

    private func tickHeartbeat() async -> Bool {
        guard state == .connected else { return false }
        if missedHeartbeats >= 3 {
            // Порог пропущенных heartbeat достигнут — считаем соединение потерянным
            connectionContinuation.yield(.reconnecting(attempt: 1))
            handleReadError(ProtocolError.notConnected)
            return false
        }
        missedHeartbeats += 1
        let pingFrame = ProtocolCodec.encodePing(requestID: 0, timestamp: Int64(Date().timeIntervalSince1970 * 1000))
        try? await writeFrame(pingFrame)
        return true
    }

    func close() {
        state = .closed
        readLoopTask?.cancel()
        readLoopTask = nil
        heartbeatTask?.cancel()
        heartbeatTask = nil

        for (_, continuation) in pendingRequests {
            continuation.resume(throwing: ProtocolError.notConnected)
        }
        pendingRequests.removeAll()

        raw?.close()
        raw = nil
        sendCipher = nil
        recvCipher = nil

        connectionContinuation.yield(.disconnected)
        incomingContinuation.finish()
    }
}
