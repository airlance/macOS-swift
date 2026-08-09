import Foundation
import NIOCore
import NIOConcurrencyHelpers
import NIOHTTP2
import NIOPosix
import Security

/// Errors an `AirlanceClient` call can throw. Wraps `GRPCStatus` (the
/// wire-level gRPC failure) plus this layer's own connection-lifecycle
/// failures.
public enum AirlanceClientError: Error {
    case notConnected
    case grpc(GRPCStatus)
    /// The server sent zero messages before closing the stream with an
    /// .ok status — shouldn't happen for any AuthService unary RPC (each
    /// always sends exactly one response message on success), so this
    /// indicates a protocol-level bug on one side or the other.
    case noResponseMessage
}

/// The full AuthService client: owns one wireauthgrpc-secured HTTP/2
/// connection and exposes one async method per RPC defined in
/// `fbs/auth/{login,session,qrlogin}.fbs`. Every method here corresponds
/// 1:1 to a handler in the Go server's
/// `internal/transport/grpc/authservice/server.go`.
///
/// Thread-safety: methods are safe to call concurrently (each opens its
/// own independent HTTP/2 stream via the shared multiplexer, which is
/// how HTTP/2 multiplexing is meant to be used) once `connect()` has
/// completed.
public actor AirlanceClient {
    private let bootstrap: AirlanceChannelBootstrap
    private let host: String
    private let port: Int
    /// Sent as the gRPC `:authority` pseudo-header on every request —
    /// conventionally host[:port], independent of what was used to
    /// physically dial the socket.
    private let authority: String

    private var channel: Channel?
    private var multiplexer: NIOHTTP2Handler.StreamMultiplexer?

    public init(eventLoopGroup: EventLoopGroup, serverPublicKey: SecKey, host: String, port: Int) {
        self.bootstrap = AirlanceChannelBootstrap(eventLoopGroup: eventLoopGroup, serverPublicKey: serverPublicKey)
        self.host = host
        self.port = port
        self.authority = "\(host):\(port)"
    }

    /// Establishes the connection, including the full wireauthgrpc
    /// handshake. Must complete before any RPC method is called.
    public func connect() async throws {
        let (channel, multiplexer) = try await bootstrap.connect(host: host, port: port).get()
        self.channel = channel
        self.multiplexer = multiplexer
    }

    public func close() async throws {
        guard let channel else { return }
        try await channel.close().get()
        self.channel = nil
        self.multiplexer = nil
    }

    // MARK: - LoginByGithub

    public func loginByGithub(code: String, clientCtx: authv1_ClientContextT?) async throws -> authv1_LoginByGithubResponseT {
        var value = authv1_LoginByGithubRequestT()
        value.code = code
        value.clientCtx = clientCtx
        let response: LoginByGithubResponse = try await unaryCall(
            path: "/authv1.AuthService/LoginByGithub",
            request: LoginByGithubRequest(value)
        )
        return try unwrap(response)
    }

    // MARK: - ResumeSession

    public func resumeSession(authKeyID: UInt64, resumeSecret: String) async throws -> authv1_ResumeSessionResponseT {
        var value = authv1_ResumeSessionRequestT()
        value.authKeyId = authKeyID
        value.resumeSecret = resumeSecret
        let response: ResumeSessionResponse = try await unaryCall(
            path: "/authv1.AuthService/ResumeSession",
            request: ResumeSessionRequest(value)
        )
        return try unwrap(response)
    }

    // MARK: - TerminateSession

    /// `authKeyID`/session identity travels via gRPC metadata (the
    /// `x-auth-key-id` header the server's UnaryAuth interceptor expects
    /// — see `performCall`), not as a request field — matches the Go
    /// server's handler, which reads it off `contextx.GetUser`.
    public func terminateSession(reason: String, authKeyID: UInt64) async throws -> authv1_TerminateSessionResponseT {
        var value = authv1_TerminateSessionRequestT()
        value.reason = reason
        let response: TerminateSessionResponse = try await unaryCall(
            path: "/authv1.AuthService/TerminateSession",
            request: TerminateSessionRequest(value),
            authKeyID: authKeyID
        )
        return try unwrap(response)
    }

    // MARK: - ListSessions

    /// Lists every active session belonging to the calling user — the
    /// session identity travels via gRPC metadata (`x-auth-key-id`),
    /// same as `terminateSession` — matches the Go server's
    /// `ListSessionsRPC`, which reads the caller off `contextx.GetUser`
    /// and flags whichever entry has the same auth_key_id as `isCurrent`.
    public func listSessions(authKeyID: UInt64) async throws -> authv1_ListSessionsResponseT {
        let value = authv1_ListSessionsRequestT()
        let response: ListSessionsResponse = try await unaryCall(
            path: "/authv1.AuthService/ListSessions",
            request: ListSessionsRequest(value),
            authKeyID: authKeyID
        )
        return try unwrap(response)
    }

    // MARK: - KillSession

    /// Revokes one of the calling user's OTHER sessions by
    /// `targetAuthKeyID` — e.g. "log out this device" from a device
    /// list. `authKeyID` is still the CALLER's own session (for the
    /// `x-auth-key-id` metadata / who-is-calling check), distinct from
    /// `targetAuthKeyID`, the session being killed. The server verifies
    /// the target belongs to the caller's user before revoking it —
    /// see the Go usecase's ownership check.
    public func killSession(targetAuthKeyID: UInt64, authKeyID: UInt64) async throws -> authv1_KillSessionResponseT {
        var value = authv1_KillSessionRequestT()
        value.authKeyId = targetAuthKeyID
        let response: KillSessionResponse = try await unaryCall(
            path: "/authv1.AuthService/KillSession",
            request: KillSessionRequest(value),
            authKeyID: authKeyID
        )
        return try unwrap(response)
    }

    // MARK: - QR login

    public func generateQRLogin(clientCtx: authv1_ClientContextT?) async throws -> authv1_GenerateQRLoginResponseT {
        var value = authv1_GenerateQRLoginRequestT()
        value.clientCtx = clientCtx
        let response: GenerateQRLoginResponse = try await unaryCall(
            path: "/authv1.AuthService/GenerateQRLogin",
            request: GenerateQRLoginRequest(value)
        )
        return try unwrap(response)
    }

    public func scanQRLogin(token: String) async throws -> authv1_ScanQRLoginResponseT {
        var value = authv1_ScanQRLoginRequestT()
        value.token = token
        let response: ScanQRLoginResponse = try await unaryCall(
            path: "/authv1.AuthService/ScanQRLogin",
            request: ScanQRLoginRequest(value)
        )
        return try unwrap(response)
    }

    /// `authKeyID` is the confirming device's OWN session — see the Go
    /// handler's extensive doc comment on why ConfirmQRLogin is exempt
    /// from the blanket auth interceptor but still authenticates the
    /// caller by hand via the same `x-auth-key-id` metadata key.
    public func confirmQRLogin(token: String, authKeyID: UInt64) async throws -> authv1_ConfirmQRLoginResponseT {
        var value = authv1_ConfirmQRLoginRequestT()
        value.token = token
        let response: ConfirmQRLoginResponse = try await unaryCall(
            path: "/authv1.AuthService/ConfirmQRLogin",
            request: ConfirmQRLoginRequest(value),
            authKeyID: authKeyID
        )
        return try unwrap(response)
    }

    public func rejectQRLogin(token: String) async throws -> authv1_RejectQRLoginResponseT {
        var value = authv1_RejectQRLoginRequestT()
        value.token = token
        let response: RejectQRLoginResponse = try await unaryCall(
            path: "/authv1.AuthService/RejectQRLogin",
            request: RejectQRLoginRequest(value)
        )
        return try unwrap(response)
    }

    /// Server-streaming: returns a stream that yields every
    /// `authv1_QRLoginEventT` the server sends, then finishes when the
    /// server closes the RPC. Matches the Go server's
    /// `WaitQRLoginResult`, which sends exactly one event before closing
    /// (Confirmed or ExpiredOrRejected) — but this doesn't assume that;
    /// it forwards every message it receives and finishes once the
    /// stream ends, whatever the final gRPC status.
    ///
    /// `event.payload` is a flatbuffers union
    /// (`authv1_QRLoginEventPayloadUnion`): switch on `event.payload?.type`
    /// (`.qrloginconfirmed` / `.qrloginexpiredorrejected`) and downcast
    /// `event.payload?.value` to `authv1_QRLoginConfirmedT` /
    /// `authv1_QRLoginExpiredOrRejectedT` accordingly.
    ///
    /// Fails only for a genuinely failed RPC (`grpc-status != OK` _and_
    /// no events were ever delivered) or a framing/connection error — a
    /// normal "stream ended after delivering the expected event"
    /// finishes cleanly instead.
    ///
    /// Cancelling the consuming `Task` (e.g. a QR refresh, or the caller
    /// simply stopping iteration / letting the stream go out of scope)
    /// closes the underlying HTTP/2 stream via `onTermination` — see
    /// `performCall`'s `withTaskCancellationHandler`. Without that, a
    /// cancelled wait would leak an open RPC on both client and server
    /// until the token's own expiry closed it.
    public func waitQRLoginResult(token: String) async -> AsyncThrowingStream<authv1_QRLoginEventT, Error> {
        var value = authv1_WaitQRLoginResultRequestT()
        value.token = token
        let request = WaitQRLoginResultRequest(value)

        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    try await self.streamingCall(
                        path: "/authv1.AuthService/WaitQRLoginResult",
                        request: request
                    ) { (event: QRLoginEvent) in
                        if let v = event.v {
                            continuation.yield(v)
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            // Fires when the consumer stops iterating for any reason —
            // `break`, an error thrown out of the `for try await` body,
            // or the stream/its Task simply being deallocated. Cancels
            // the underlying RPC `Task`, which `performCall`'s
            // `onCancel` handler turns into an actual channel close.
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Every response wrapper's `.v` is guaranteed non-nil here — decode
    /// only ever produces an `FBMsg` via `FBMsg.unmarshalFB`, which
    /// always sets `v` from the parsed root table — but `.v` is Optional
    /// at the type level (see `FBMsg`'s doc comment), so this turns "not
    /// nil in practice" into "not nil per the type system" at the one
    /// place per call it matters, instead of silently force-unwrapping
    /// at every call site.
    private func unwrap<T, Reader>(_ msg: FBMsg<T, Reader>) throws -> T {
        guard let v = msg.v else {
            throw AirlanceClientError.noResponseMessage
        }
        return v
    }

    // MARK: - Call machinery

    private func unaryCall<Req: FBMessage, Resp: FBMessage>(
        path: String,
        request: Req,
        authKeyID: UInt64? = nil
    ) async throws -> Resp {
        var result: Resp?
        try await performCall(path: path, request: request, authKeyID: authKeyID) { data in
            // A well-behaved unary RPC sends exactly one message; if the
            // server ever sent more, the last one wins rather than
            // throwing away work already done — matches typical unary
            // client leniency elsewhere (e.g. grpc-go's CallOption
            // handling).
            result = try FlatbuffersCodec.decode(data, as: Resp.self)
        }
        guard let result else {
            throw AirlanceClientError.noResponseMessage
        }
        return result
    }

    private func streamingCall<Req: FBMessage, Resp: FBMessage>(
        path: String,
        request: Req,
        onMessage: @escaping (Resp) -> Void
    ) async throws {
        try await performCall(path: path, request: request, authKeyID: nil) { data in
            let decoded = try FlatbuffersCodec.decode(data, as: Resp.self)
            onMessage(decoded)
        }
    }

    /// Mutable state shared between the NIO callback world (runs on
    /// `streamChannel.eventLoop`) and `withTaskCancellationHandler`'s
    /// `onCancel` closure (runs on whatever thread cancels the `Task` —
    /// no ordering guarantee relative to the NIO side), hence the
    /// `NIOLockedValueBox` wrapper below rather than plain captured
    /// `var`s. `continuation`/`streamChannel` are set once, early;
    /// `finished` guards `continuation.resume` being called more than
    /// once no matter which side (network event vs. cancellation) gets
    /// there first.
    private struct CallState {
        var continuation: CheckedContinuation<Void, Error>?
        var streamChannel: Channel?
        var receivedAnyMessage = false
        var finished = false
    }

    /// Resumes `state`'s continuation exactly once. Safe to call from
    /// any thread, any number of times — every call after the first is
    /// a no-op.
    private static func finish(_ state: NIOLockedValueBox<CallState>, throwing error: Error?) {
        let continuation: CheckedContinuation<Void, Error>? = state.withLockedValue { s in
            guard !s.finished else { return nil }
            s.finished = true
            return s.continuation
        }
        guard let continuation else { return }
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }

    /// Shared plumbing for both unary and server-streaming calls: opens
    /// an HTTP/2 stream, sends the request, and forwards every decoded
    /// message body to `onMessageData` until the stream ends — throwing
    /// on a non-OK final status only if no messages were ever delivered
    /// (a streaming call that got its one expected event and then a
    /// non-OK trailer, e.g. from a context cancellation racing the
    /// send, should not surface as a failure to the caller once the
    /// real payload already arrived).
    ///
    /// Wrapped in `withTaskCancellationHandler`: `withCheckedThrowingContinuation`
    /// on its own does NOT observe `Task` cancellation, so without this
    /// a cancelled caller (QR refresh, view teardown, a consumer that
    /// stops iterating `waitQRLoginResult`'s stream) would leave this
    /// HTTP/2 stream open indefinitely — on both client and server —
    /// until the RPC's own logic ends it. `onCancel` closes the child
    /// stream channel directly and resumes the continuation with
    /// `CancellationError`, so cancellation actually tears down the RPC
    /// instead of merely abandoning the `await`.
    private func performCall<Req: FBMessage>(
        path: String,
        request: Req,
        authKeyID: UInt64?,
        onMessageData: @escaping (Data) throws -> Void
    ) async throws {
        guard let channel, let multiplexer else {
            throw AirlanceClientError.notConnected
        }

        let framedBody = GRPCMessageFraming.frame(FlatbuffersCodec.encode(request))
        var bodyBuffer = channel.allocator.buffer(capacity: framedBody.count)
        bodyBuffer.writeBytes(framedBody)

        let requestHead = AirlanceStreamHandler.RequestHead(path: path, authority: authority)

        // x-auth-key-id is plain gRPC request metadata — see
        // interceptor/auth.go's authKeyIDFromContext on the server side,
        // which reads it back out of incoming HPACK headers the same way
        // any other metadata key works. Sent as a decimal string,
        // matching the server's `strconv.ParseUint(values[0], 10, 64)`.
        let extraMetadata: [(String, String)] = authKeyID.map { [("x-auth-key-id", String($0))] } ?? []

        let state = NIOLockedValueBox<CallState>(CallState())

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                state.withLockedValue { $0.continuation = continuation }

                multiplexer.createStreamChannel(promise: nil) { streamChannel in
                    state.withLockedValue { $0.streamChannel = streamChannel }
                    return streamChannel.eventLoop.makeCompletedFuture(Result {
                        let handler = AirlanceStreamHandler(
                            requestHead: requestHead,
                            extraMetadata: extraMetadata,
                            framedRequestBody: bodyBuffer
                        )
                        handler.setEventHandler { event in
                            switch event {
                            case .message(let data):
                                state.withLockedValue { $0.receivedAnyMessage = true }
                                do {
                                    try onMessageData(data)
                                } catch {
                                    Self.finish(state, throwing: error)
                                }
                            case .end(let status):
                                let receivedAnyMessage = state.withLockedValue { $0.receivedAnyMessage }
                                if status.code == .ok || receivedAnyMessage {
                                    Self.finish(state, throwing: nil)
                                } else {
                                    Self.finish(state, throwing: AirlanceClientError.grpc(status))
                                }
                            }
                        }
                        // addHandler triggers handlerAdded synchronously,
                        // which is what actually sends the HEADERS+DATA
                        // frames — see AirlanceStreamHandler.handlerAdded.
                        try streamChannel.pipeline.syncOperations.addHandler(handler)
                    })
                }
            }
        } onCancel: {
            state.withLockedValue { $0.streamChannel }?.close(promise: nil)
            Self.finish(state, throwing: CancellationError())
        }
    }
}