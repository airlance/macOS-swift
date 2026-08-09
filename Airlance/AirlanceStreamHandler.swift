import NIOCore
import NIOHPACK
import NIOHTTP2
import Foundation

/// The gRPC status codes relevant here, per
/// https://github.com/grpc/grpc/blob/master/doc/statuscodes.md — only
/// what AuthService's usecase-error mapping (`mapUsecaseErr` in the Go
/// server) actually produces today, plus the ones any gRPC call can
/// surface regardless of the service (deadline, unavailable, etc).
public enum GRPCStatusCode: Int, Error {
    case ok = 0
    case cancelled = 1
    case unknown = 2
    case invalidArgument = 3
    case deadlineExceeded = 4
    case notFound = 5
    case alreadyExists = 6
    case permissionDenied = 7
    case resourceExhausted = 8
    case failedPrecondition = 9
    case aborted = 10
    case outOfRange = 11
    case unimplemented = 12
    case internalError = 13
    case unavailable = 14
    case dataLoss = 15
    case unauthenticated = 16
}

public struct GRPCStatus: Error {
    public let code: GRPCStatusCode
    public let message: String?
}

/// Per-stream handler that speaks the gRPC-over-HTTP/2 wire protocol
/// (headers, length-prefixed DATA framing, trailers) directly in terms
/// of `HTTP2Frame.FramePayload` — the child-channel unit
/// `multiplexer.createStreamChannel` produces. This replaces grpc-swift's
/// own `_GRPCClientChannelHandler`, which is `internal` as of a fairly
/// early grpc-swift release and therefore unusable from outside the
/// module (see AirlanceChannelBootstrap.swift's doc comment for why this
/// project doesn't route through `ClientConnection` at all).
///
/// One instance handles exactly one RPC (one HTTP/2 stream), for both
/// unary and server-streaming calls — AuthService has no client-streaming
/// or bidi-streaming RPCs, so this doesn't need to support sending more
/// than one request message.
final class AirlanceStreamHandler: ChannelDuplexHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundIn = Never // driven by direct method calls, not a wrapped outbound type — see `sendRequest`
    typealias OutboundOut = HTTP2Frame.FramePayload

    struct RequestHead {
        let path: String
        let authority: String
    }

    /// One event per inbound gRPC message, delivered via `onMessage`.
    /// The `end` case's `status` is always present — even on `.ok` — so
    /// callers can distinguish a still-open stream from a definitively
    /// finished one without also inspecting `code == .ok`.
    enum Event {
        case message(Data)
        case end(status: GRPCStatus)
    }

    private let requestHead: RequestHead
    private let extraMetadata: [(String, String)]
    private let framedRequestBody: ByteBuffer
    private var onEvent: ((Event) -> Void)?
    private var headersSent = false

    init(requestHead: RequestHead, extraMetadata: [(String, String)], framedRequestBody: ByteBuffer) {
        self.requestHead = requestHead
        self.extraMetadata = extraMetadata
        self.framedRequestBody = framedRequestBody
    }

    /// Registers the callback that receives every inbound message and
    /// the final status. Must be set before the handler is added to a
    /// pipeline — `handlerAdded` sends the request immediately, so any
    /// same-event-loop-turn response (unlikely, but not impossible with
    /// a very fast local server) must not be able to arrive before a
    /// callback exists to receive it.
    func setEventHandler(_ handler: @escaping (Event) -> Void) {
        self.onEvent = handler
    }

    /// Sends the HEADERS + DATA request frames as soon as this handler
    /// is installed in the stream channel's pipeline. Doing this here —
    /// rather than via a separately-called method — means `context` is
    /// always the real, valid context for this handler's position in
    /// the pipeline; there is no window where a caller could hold onto
    /// a stale or wrongly-obtained `ChannelHandlerContext` (the earlier
    /// draft of this file used `syncOperations.context(handlerType:)`
    /// from outside the handler for this, which is both indirect and
    /// only valid if called back on the stream channel's own event loop
    /// — this removes that whole class of mistake).
    func handlerAdded(context: ChannelHandlerContext) {
        sendRequestHead(context: context, extraMetadata: extraMetadata, promise: nil)
        sendMessage(context: context, framedBody: framedRequestBody, promise: nil)
    }

    // MARK: - Outbound: request construction

    /// Sends the HTTP/2 HEADERS frame that opens the RPC. Call once,
    /// before `sendMessage`. `extraMetadata` carries call-specific gRPC
    /// metadata beyond the fixed pseudo-headers/content-type/te — e.g.
    /// `x-auth-key-id` for RPCs that authenticate by session rather than
    /// (or in addition to) a request field. Matches how the Go server's
    /// UnaryAuth/StreamAuth interceptors read that same key back out of
    /// incoming metadata (see interceptor/auth.go's `authKeyIDFromContext`).
    private func sendRequestHead(context: ChannelHandlerContext, extraMetadata: [(String, String)], promise: EventLoopPromise<Void>?) {
        precondition(!headersSent, "sendRequestHead called twice on the same AirlanceStreamHandler")
        headersSent = true

        var headers = HPACKHeaders()
        headers.add(name: ":method", value: "POST")
        headers.add(name: ":scheme", value: "http") // wireauthgrpc is the security layer; HTTP/2 itself runs in cleartext mode on top of it, same as h2c
        headers.add(name: ":path", value: requestHead.path)
        headers.add(name: ":authority", value: requestHead.authority)
        headers.add(name: "content-type", value: "application/grpc+flatbuffers") // matches flatcodec.Name ("flatbuffers") as the gRPC content-subtype
        headers.add(name: "te", value: "trailers") // required by the gRPC-over-HTTP/2 spec on every request
        for (name, value) in extraMetadata {
            headers.add(name: name, value: value)
        }

        let payload = HTTP2Frame.FramePayload.headers(.init(headers: headers, endStream: false))
        context.write(wrapOutboundOut(payload), promise: promise)
        context.flush()
    }

    /// Sends one gRPC message (already flatcodec+gRPC-framed — see
    /// `GRPCMessageFraming.frame` / `FlatbuffersCodec.encode`) as an
    /// HTTP/2 DATA frame. AuthService never streams more than one
    /// request message, so this also marks the request stream half-closed
    /// (`endStream: true`) — there is no separate "send end of request
    /// stream" call to make, unlike the Go server's grpc.ServiceDesc
    /// unary/streaming distinction: from the wire's perspective this
    /// client only ever does a single-message request half.
    private func sendMessage(context: ChannelHandlerContext, framedBody: ByteBuffer, promise: EventLoopPromise<Void>?) {
        let payload = HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(framedBody), endStream: true))
        context.write(wrapOutboundOut(payload), promise: promise)
        context.flush()
    }

    // MARK: - Inbound: response parsing

    private var messageAccumulator = ByteBuffer()

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let payload = unwrapInboundIn(data)

        switch payload {
        case .headers(let headersPayload):
            handleHeaders(headersPayload, context: context)
        case .data(let dataPayload):
            handleData(dataPayload, context: context)
        default:
            // RST_STREAM, WINDOW_UPDATE, etc. handled by NIOHTTP2Handler
            // itself below this handler in the pipeline — nothing
            // gRPC-semantic to do with them here.
            break
        }
    }

    private func handleHeaders(_ headersPayload: HTTP2Frame.FramePayload.Headers, context: ChannelHandlerContext) {
        let headers = headersPayload.headers

        // A "Trailers-Only" response (see PROTOCOL-HTTP2.md) carries
        // grpc-status directly on what would otherwise be the initial
        // response HEADERS — e.g. the RPC failed before any message was
        // ever sent. Treat that the same as a normal end-of-stream:
        // whether grpc-status showed up on the first HEADERS frame or a
        // later trailers-only HEADERS frame doesn't matter to the caller.
        if let statusValue = headers.first(name: "grpc-status") {
            let status = parseStatus(headers: headers, statusValue: statusValue)
            onEvent?(.end(status: status))
            return
        }

        // Otherwise this is the initial Response-Headers (HTTP-Status +
        // content-type + custom metadata) — nothing the caller needs
        // here; AirlanceClient surfaces failures via the final status,
        // not initial metadata.
    }

    private func handleData(_ dataPayload: HTTP2Frame.FramePayload.Data, context: ChannelHandlerContext) {
        guard case .byteBuffer(var buffer) = dataPayload.data else {
            preconditionFailure("Received DATA frame with non-ByteBuffer IOData")
        }
        messageAccumulator.writeBuffer(&buffer)

        do {
            let bodies = try GRPCMessageFraming.decodeAvailableMessages(from: &messageAccumulator)
            for body in bodies {
                onEvent?(.message(body))
            }
        } catch {
            onEvent?(.end(status: GRPCStatus(code: .internalError, message: "gRPC framing error: \(error)")))
            context.close(promise: nil)
            return
        }

        // A DATA frame with endStream set and no grpc-status in a
        // preceding/following HEADERS frame is a protocol violation per
        // spec ("Response-Headers *Length-Prefixed-Message Trailers") —
        // but be lenient and treat it as an aborted stream rather than
        // hanging forever, since a well-behaved server (this one) will
        // always send trailers with grpc-status.
        if dataPayload.endStream {
            onEvent?(.end(status: GRPCStatus(code: .internalError, message: "stream ended without trailers")))
        }
    }

    private func parseStatus(headers: HPACKHeaders, statusValue: String) -> GRPCStatus {
        guard let code = Int(statusValue).flatMap(GRPCStatusCode.init(rawValue:)) else {
            return GRPCStatus(code: .unknown, message: "unparseable grpc-status: \(statusValue)")
        }
        let message = headers.first(name: "grpc-message").map(percentDecodeGRPCMessage)
        return GRPCStatus(code: code, message: message)
    }

    /// `grpc-message` is percent-encoded per the gRPC spec (a restricted
    /// percent-encoding, not full URL percent-encoding) — decoding it
    /// properly means only unescaping %XX sequences, which
    /// `removingPercentEncoding` does correctly for this subset. Falls
    /// back to the raw value if decoding fails rather than losing the
    /// message entirely.
    private func percentDecodeGRPCMessage(_ raw: String) -> String {
        raw.removingPercentEncoding ?? raw
    }
}