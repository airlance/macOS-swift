import NIOCore
import NIOHTTP2
import NIOPosix
import Security

/// Establishes a raw TCP connection secured by wireauthgrpc, then layers
/// standard SwiftNIO HTTP/2 on top of it — bypassing grpc-swift's
/// `ClientConnection`/`GRPCChannelPool` entirely.
///
/// Why not use `ClientConnection`: as of grpc-swift v1 (now in
/// maintenance mode — see Package.swift comment), its public
/// `TransportSecurity` surface is `.plaintext` or `.tls(GRPCTLSConfiguration)`
/// (NIOSSL-backed) with no documented hook to splice an arbitrary
/// `ChannelHandler` below the HTTP/2 layer. wireauthgrpc's handshake
/// takes the place TLS would occupy, so there's no way to express it
/// through that surface. This bootstrap does what `ClientConnection`
/// does internally (per grpc-swift's own `GRPCClientChannelHandler.swift`
/// doc comment, which shows the same `HTTP2StreamMultiplexer` pattern
/// used here), minus the parts that assume NIOSSL.
///
/// Pipeline, bottom to top:
///   raw TCP
///   -> WireAuthChannelHandler   (RSA/ECDH/AES-GCM, replaces TLS)
///   -> NIOHTTP2Handler          (standard SwiftNIO HTTP/2, client mode)
///   -> (per-stream) AirlanceStreamHandler, added per RPC call by
///      AirlanceClient inside multiplexer.createStreamChannel — see
///      AirlanceStreamHandler.swift and AirlanceClient.swift
///
/// Trade-off accepted by going around `ClientConnection`: no automatic
/// reconnection, connection pooling, or keepalive — `AirlanceClient`
/// owns the connection lifecycle explicitly and reconnects are the
/// caller's responsibility (surfaced via `WireAuthChannelHandler.HandshakeFailed`
/// and normal NIO `channelInactive`).
public final class AirlanceChannelBootstrap {
    private let eventLoopGroup: EventLoopGroup
    private let serverPublicKey: SecKey

    public init(eventLoopGroup: EventLoopGroup, serverPublicKey: SecKey) {
        self.eventLoopGroup = eventLoopGroup
        self.serverPublicKey = serverPublicKey
    }

    /// Connects to `host:port`, completes the wireauthgrpc handshake, and
    /// returns the resulting HTTP/2-ready `Channel` together with its
    /// `HTTP2StreamMultiplexer` for creating per-RPC streams.
    ///
    /// The returned future only completes once BOTH the TCP connection
    /// and the wireauthgrpc handshake have succeeded — a handshake
    /// failure fails this future (the connection is closed automatically,
    /// see `WireAuthChannelHandler.failSecureChannel`).
    public func connect(host: String, port: Int) -> EventLoopFuture<(channel: Channel, multiplexer: NIOHTTP2Handler.StreamMultiplexer)> {
        let serverPublicKey = self.serverPublicKey

        // Bridges WireAuthChannelHandler's "handshake complete" user event
        // into the returned future — see HandshakeAwaiter below.
        let handshakePromise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise()

        let bootstrap = ClientBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let wireAuthHandler = WireAuthChannelHandler(serverPublicKey: serverPublicKey)
                    let awaiter = HandshakeAwaiter(promise: handshakePromise)

                    try channel.pipeline.syncOperations.addHandler(wireAuthHandler)
                    try channel.pipeline.syncOperations.addHandler(awaiter)

                    // Standard SwiftNIO HTTP/2, client mode, sitting
                    // directly on top of the now-decrypted byte stream.
                    // This is the same call site the swift-nio-examples
                    // http2-client uses.
                    _ = try channel.pipeline.syncOperations.configureHTTP2Pipeline(
                        mode: .client,
                        connectionConfiguration: .init(),
                        streamConfiguration: .init()
                    ) { _ in
                        // No default inbound stream handling — Airlance's
                        // AuthService only ever has client-initiated
                        // streams (unary calls, WaitQRLoginResult
                        // server-streaming), so there's nothing to
                        // configure for server-pushed streams.
                        channel.eventLoop.makeSucceededVoidFuture()
                    }
                }
            }

        return bootstrap.connect(host: host, port: port).flatMap { channel in
            // Wait for the handshake to actually finish before handing the
            // channel back — a caller that immediately tries to open an
            // HTTP/2 stream needs the secure channel already active.
            //
            // handshakePromise was created on `eventLoopGroup.next()`,
            // which is not necessarily `channel.eventLoop` — hop onto the
            // channel's own loop before touching `syncOperations` (NIO
            // requires pipeline mutations/reads to happen on-loop).
            handshakePromise.futureResult.flatMap { () -> EventLoopFuture<(channel: Channel, multiplexer: NIOHTTP2Handler.StreamMultiplexer)> in
                channel.eventLoop.submit {
                    // ⚠️ NOT YET RUN AGAINST A REAL BUILD: `syncMultiplexer()`
                    // requires NIOHTTP2Handler to have been configured for
                    // inline multiplexing, which `configureHTTP2Pipeline`
                    // above does — but the exact API (throwing vs.
                    // returning EventLoopFuture, method name) has moved
                    // between swift-nio-http2 releases. Verify this against
                    // whichever version Package.swift resolves to.
                    let multiplexer = try channel.pipeline.syncOperations.handler(type: NIOHTTP2Handler.self).syncMultiplexer()
                    return (channel: channel, multiplexer: multiplexer)
                }
            }
        }
    }
}

/// A minimal inbound handler whose only job is to resolve
/// `handshakePromise` when `WireAuthChannelHandler.HandshakeComplete`
/// fires, or fail it on `HandshakeFailed`. Removed from the pipeline
/// (implicitly, by no longer mattering) once the promise is resolved —
/// it stays in the pipeline afterward but is inert, since neither event
/// fires again for the lifetime of the connection.
private final class HandshakeAwaiter: ChannelInboundHandler {
    typealias InboundIn = Any

    private let promise: EventLoopPromise<Void>
    private var resolved = false

    init(promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if !resolved {
            if event is WireAuthChannelHandler.HandshakeComplete {
                resolved = true
                promise.succeed(())
            } else if let failed = event as? WireAuthChannelHandler.HandshakeFailed {
                resolved = true
                promise.fail(failed.error)
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !resolved {
            resolved = true
            promise.fail(WireAuthError.connectionClosed)
        }
        context.fireChannelInactive()
    }
}