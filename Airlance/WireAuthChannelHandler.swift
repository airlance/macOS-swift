import CryptoKit
import NIOCore
import NIOFoundationCompat
import Security
import Foundation

/// A NIO `ChannelDuplexHandler` that sits directly on top of the raw TCP
/// socket, below grpc-swift's HTTP/2 handlers, and does exactly what
/// `credentials.NewTLS(...)` would do for a normal grpc-go client — except
/// the handshake here is wireauthgrpc's RSA/ECDH/AES-GCM protocol instead
/// of TLS.
///
/// Lifecycle:
///  1. `channelActive`: kick off the two-stage handshake. Every byte
///     written to the socket and read from it during this phase goes
///     through `handshakeWrite`/`handshakeRead`, NOT the AEAD record
///     framing — the handshake messages are fixed-size and unencrypted
///     by design (see WireAuthProtocol doc comments).
///  2. On handshake success: `state` flips to `.secure`, and a
///     `WireAuthHandshakeCompletePromise`-style user event fires so
///     `AirlanceChannelBootstrap` can let grpc-swift's own HTTP/2
///     handlers start writing (they've been buffered until now — see
///     `pendingWrites`).
///  3. Every subsequent `write` from above (i.e. from grpc-swift's HTTP/2
///     handler) is sealed into one or more length-prefixed AEAD records
///     and sent down to the socket. Every `channelRead` from the socket
///     is fed through a length-prefixed record parser, decrypted, and the
///     resulting plaintext bytes are the ONLY thing forwarded up to
///     grpc-swift's HTTP/2 handler — from its perspective this looks
///     exactly like reading a plaintext (or TLS-terminated) stream.
///
/// This handler does not decide *whether* the connection succeeded at
/// the gRPC level — it only establishes the secure byte channel HTTP/2
/// then runs on top of. A handshake failure fires
/// `channelInboundEventTriggered` with a `WireAuthHandshakeFailed` event
/// which `AirlanceChannelBootstrap` turns into a connection-level error
/// so grpc-swift's `ClientConnection` reports it the same way it would
/// report a TLS handshake failure.
public final class WireAuthChannelHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private enum State {
        case idle
        case handshaking
        case secure(SymmetricKey)
        case failed(Error)
    }

    /// Fired as a user inbound event once the handshake completes
    /// successfully. `AirlanceChannelBootstrap` waits for this before
    /// telling grpc-swift the connection is ready.
    public struct HandshakeComplete {
        public let serverNonce: [UInt8]
        public let establishedAt: Date
    }

    /// Fired as a user inbound event if the handshake fails for any
    /// reason. The channel is closed immediately after this fires.
    public struct HandshakeFailed {
        public let error: Error
    }

    private let serverPublicKey: SecKey

    private var state: State = .idle

    // Accumulates raw bytes read from the socket until a full handshake
    // message, or a full length-prefixed AEAD record, is available.
    private var inboundAccumulator = ByteBuffer()

    // Buffers HTTP/2 writes issued by grpc-swift's handlers while the
    // handshake is still in flight, so nothing is silently dropped —
    // flushed the moment the handshake completes.
    private var pendingOutbound: [(ByteBuffer, EventLoopPromise<Void>?)] = []

    private var writeSeq: UInt64 = 0
    private var expectReadSeq: UInt64 = 0

    // Set while a handshake read is outstanding, so channelRead knows to
    // route incoming bytes to the handshake continuation instead of the
    // AEAD record parser.
    private var handshakeReadContinuation: ((Result<ByteBuffer, Error>) -> Void)?
    private var handshakeReadTargetLength = 0

    public init(serverPublicKey: SecKey) {
        self.serverPublicKey = serverPublicKey
    }

    public func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
        beginHandshake(context: context)
    }

    // MARK: - Handshake orchestration

    private func beginHandshake(context: ChannelHandlerContext) {
        state = .handshaking
        let loop = context.eventLoop

        // WireAuthClientHandshake.run is async; bridge it onto the NIO
        // event loop via a Task, funneling all socket I/O back through
        // this handler's write/read primitives so everything still runs
        // on `loop` (NIO channels are not thread-safe to touch off-loop).
        Task {
            do {
                let result = try await WireAuthClientHandshake.run(
                    serverPublicKey: self.serverPublicKey,
                    write: { data in
                        try await self.handshakeWrite(context: context, loop: loop, data: data)
                    },
                    readExactly: { length in
                        try await self.handshakeRead(context: context, loop: loop, length: length)
                    }
                )
                loop.execute {
                    self.completeHandshake(context: context, result: result)
                }
            } catch {
                loop.execute {
                    self.failSecureChannel(context: context, error: error)
                }
            }
        }
    }

    /// Writes raw (unencrypted-by-this-layer) handshake bytes directly to
    /// the socket, hopping onto the event loop to touch the channel
    /// safely from the async Task above.
    private func handshakeWrite(context: ChannelHandlerContext, loop: EventLoop, data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loop.execute {
                var buffer = context.channel.allocator.buffer(capacity: data.count)
                buffer.writeBytes(data)
                context.writeAndFlush(self.wrapOutboundOut(buffer)).whenComplete { result in
                    switch result {
                    case .success:
                        continuation.resume()
                    case .failure(let error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }

    /// Reads exactly `length` raw bytes from the socket for the
    /// handshake. Bytes may arrive split across multiple `channelRead`
    /// calls (TCP has no message boundaries), so this waits on
    /// `inboundAccumulator` filling up via the continuation stashed in
    /// `handshakeReadContinuation`.
    private func handshakeRead(context: ChannelHandlerContext, loop: EventLoop, length: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            loop.execute {
                if let ready = self.tryDrainHandshakeBytes(length: length) {
                    continuation.resume(returning: ready)
                    return
                }
                self.handshakeReadTargetLength = length
                self.handshakeReadContinuation = { result in
                    switch result {
                    case .success(let buffer):
                        var buffer = buffer
                        let bytes = buffer.readData(length: buffer.readableBytes) ?? Data()
                        continuation.resume(returning: bytes)
                    case .failure(let error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }

    /// If `inboundAccumulator` already has >= length bytes buffered
    /// (e.g. the server's response arrived in the same TCP segment as a
    /// previous message, or channelRead ran before this async call
    /// resumed), drains and returns them synchronously instead of
    /// suspending.
    private func tryDrainHandshakeBytes(length: Int) -> Data? {
        guard inboundAccumulator.readableBytes >= length else { return nil }
        return inboundAccumulator.readData(length: length)
    }

    private func completeHandshake(context: ChannelHandlerContext, result: WireAuthHandshakeResult) {
        state = .secure(result.aesKey)

        let event = HandshakeComplete(
            serverNonce: [UInt8](result.serverNonce),
            establishedAt: Date()
        )
        context.fireUserInboundEventTriggered(event)

        flushPendingOutbound(context: context)

        // Any bytes already buffered past the handshake boundary belong
        // to the first AEAD record(s) — re-run the record parser now
        // that we're in `.secure` state.
        drainAvailableRecords(context: context)
    }

    /// Called both for an actual handshake-phase failure and for any
    /// fatal error on an already-established secure channel (bad record
    /// length, seq mismatch/replay, GCM decryption failure). Both cases
    /// are unrecoverable — the connection is closed either way — so they
    /// share this path and both surface as `HandshakeFailed` upward.
    /// `AirlanceChannelBootstrap` treats it purely as "this connection is
    /// dead, report an error", so the reused event name doesn't need a
    /// second case; split it out if a caller ever needs to distinguish
    /// "handshake never completed" from "secure channel was torn down".
    private func failSecureChannel(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        context.fireUserInboundEventTriggered(HandshakeFailed(error: error))
        for (_, promise) in pendingOutbound {
            promise?.fail(error)
        }
        pendingOutbound.removeAll()
        context.close(promise: nil)
    }

    // MARK: - Outbound (write path)

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)

        switch state {
        case .secure(let key):
            do {
                try sealAndWrite(context: context, key: key, buffer: buffer, promise: promise)
            } catch {
                promise?.fail(error)
                context.close(promise: nil)
            }
        case .idle, .handshaking:
            // grpc-swift's HTTP/2 handler may start writing its connection
            // preface immediately on channelActive, before our handshake
            // finishes. Buffer it — flushed in completeHandshake.
            pendingOutbound.append((buffer, promise))
        case .failed(let error):
            promise?.fail(error)
        }
    }

    private func flushPendingOutbound(context: ChannelHandlerContext) {
        guard case .secure(let key) = state else { return }
        let queued = pendingOutbound
        pendingOutbound.removeAll()
        for (buffer, promise) in queued {
            do {
                try sealAndWrite(context: context, key: key, buffer: buffer, promise: promise)
            } catch {
                promise?.fail(error)
                context.close(promise: nil)
                return
            }
        }
    }

    /// Encrypts `buffer` as one or more length-prefixed AEAD records
    /// (chunked at `maxRecordPlaintext`, matching the Go side's
    /// `secureConn.Write`) and writes the framed bytes downstream.
    private func sealAndWrite(context: ChannelHandlerContext, key: SymmetricKey, buffer: ByteBuffer, promise: EventLoopPromise<Void>?) throws {
        var buffer = buffer
        var out = context.channel.allocator.buffer(capacity: buffer.readableBytes + 64)

        while buffer.readableBytes > 0 {
            let chunkSize = min(buffer.readableBytes, WireAuthProtocol.maxRecordPlaintext)
            guard let chunk = buffer.readData(length: chunkSize) else { break }

            guard writeSeq != UInt64.max else {
                throw WireAuthError.seqOverflow
            }
            let seq = writeSeq
            writeSeq += 1

            let body = try WireAuthAEAD.encryptRecord(key: key, seq: seq, plaintext: chunk)

            out.writeBytes(ByteOrder.uint32BigEndian(UInt32(body.count)))
            out.writeBytes(body)
        }

        context.write(wrapOutboundOut(out), promise: promise)
        context.flush()
    }

    // MARK: - Inbound (read path)

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        inboundAccumulator.writeBuffer(&incoming)

        switch state {
        case .idle, .handshaking:
            deliverBufferedHandshakeBytesIfWaiting()
        case .secure:
            drainAvailableRecords(context: context)
        case .failed:
            break
        }
    }

    private func deliverBufferedHandshakeBytesIfWaiting() {
        guard let continuation = handshakeReadContinuation else { return }
        guard inboundAccumulator.readableBytes >= handshakeReadTargetLength else { return }

        guard let bytes = inboundAccumulator.readSlice(length: handshakeReadTargetLength) else { return }
        handshakeReadContinuation = nil
        continuation(.success(bytes))
    }

    /// Parses as many complete length-prefixed AEAD records as are
    /// currently buffered, decrypts each, enforces strict seq
    /// monotonicity (matching Go's `secureConn.fillReadBuf`), and
    /// forwards the decrypted plaintext upward to grpc-swift's HTTP/2
    /// handler.
    private func drainAvailableRecords(context: ChannelHandlerContext) {
        guard case .secure(let key) = state else { return }

        while true {
            guard inboundAccumulator.readableBytes >= WireAuthProtocol.lenFieldSize else { return }

            let lengthBytes = inboundAccumulator.getSlice(
                at: inboundAccumulator.readerIndex,
                length: WireAuthProtocol.lenFieldSize
            )!
            let bodyLength = Int(ByteOrder.readUInt32BigEndian(Data(buffer: lengthBytes)))

            guard bodyLength >= WireAuthProtocol.minRecordBodySize, bodyLength <= WireAuthProtocol.maxRecordLen else {
                failSecureChannel(context: context, error: WireAuthError.recordLengthOutOfBounds(got: UInt32(bodyLength)))
                return
            }

            let totalNeeded = WireAuthProtocol.lenFieldSize + bodyLength
            guard inboundAccumulator.readableBytes >= totalNeeded else { return } // wait for more bytes

            inboundAccumulator.moveReaderIndex(forwardBy: WireAuthProtocol.lenFieldSize)
            let bodySlice = inboundAccumulator.readSlice(length: bodyLength)!
            let bodyData = Data(buffer: bodySlice)

            do {
                let (plaintext, seq) = try WireAuthAEAD.decryptRecord(key: key, record: bodyData)
                guard seq == expectReadSeq else {
                    throw WireAuthError.seqMismatch(got: seq, want: expectReadSeq)
                }
                expectReadSeq += 1

                var out = context.channel.allocator.buffer(capacity: plaintext.count)
                out.writeBytes(plaintext)
                context.fireChannelRead(wrapInboundOut(out))
            } catch {
                failSecureChannel(context: context, error: error)
                return
            }
        }
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        if case .secure = state {
            state = .failed(error)
        }
        context.fireErrorCaught(error)
    }
}