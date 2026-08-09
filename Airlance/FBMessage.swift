import FlatBuffers
import Foundation

/// Anything that can be marshaled to / unmarshaled from a raw flatbuffers
/// buffer for use as a gRPC message. Mirrors Go's
/// `flatcodec.Message` interface (see codec.go):
///
///   MarshalFB() []byte
///   UnmarshalFB(buf []byte) error
///
/// grpc-swift's `GRPCPayload` is not used here — see AirlanceStreamHandler
/// (this project speaks gRPC-over-HTTP/2 framing directly). This protocol
/// is purely the flatbuffers-specific marshal/unmarshal contract that
/// `FlatbuffersCodec` builds on.
public protocol FBMessage {
    func marshalFB() -> Data
    static func unmarshalFB(_ data: Data) throws -> Self
}

/// Generic wrapper around a flatc `--gen-object-api` generated "T" object
/// (e.g. `authv1_LoginByGithubRequestT`), giving it `marshalFB`/`unmarshalFB`.
/// Swift mirror of Go's `fbwrap.Msg[T]`.
///
/// Confirmed against real `flatc --swift --gen-object-api` output
/// (flatc 25.12.19, see `common_generated.swift` / `session_generated.swift`):
/// - There is **no** `getRootAsXxx` method on generated table types (that
///   was a stale assumption from older flatbuffers generators/other
///   languages). The Swift runtime instead exposes free functions
///   `getRoot(byteBuffer:)` / `getCheckedRoot(byteBuffer:) throws`,
///   generic over any `FlatBufferTable & Verifiable` — see
///   `FlatBufferGeneratedTable.decode` below, which calls
///   `getCheckedRoot` (verified decode; the extra safety is worth it for
///   anything coming off a socket).
/// - `pack`/`unpack` exist exactly as assumed: `Reader.pack(&builder,
///   obj: &value)` and `readerInstance.unpack() -> T`.
public struct FBMsg<T, Reader: FlatBufferGeneratedTable>: FBMessage where Reader.ObjectT == T {
    public var v: T?

    public init(_ v: T? = nil) {
        self.v = v
    }

    public func marshalFB() -> Data {
        guard var value = v else {
            // Matches Go's fbwrap behavior of panicking on a nil V during
            // Marshal — an outgoing message with no value set is a
            // programmer error (forgot to set the request body), not a
            // recoverable runtime condition.
            preconditionFailure("FBMsg.marshalFB called with v == nil — set a value before sending")
        }
        var builder = FlatBufferBuilder(initialSize: 1024)
        let offset = Reader.pack(&builder, obj: &value)
        builder.finish(offset: offset)
        return Data(builder.sizedByteArray)
    }

    public static func unmarshalFB(_ data: Data) throws -> FBMsg<T, Reader> {
        var buffer = ByteBuffer(bytes: [UInt8](data))
        let table: Reader = try getCheckedRoot(byteBuffer: &buffer)
        return FBMsg(table.unpack())
    }
}

/// Bridges flatc's generated per-type API into something `FBMsg` can be
/// generic over. Each generated `authv1_Xxx` table type (the `struct`,
/// NOT the `XxxT` object-API class) needs a conformance — see
/// `Generated/MessageConformances.swift`.
///
/// Confirmed shape against real generated output: every generated table
/// struct already has `unpack() -> XxxT` and the two overloaded
/// `static func pack(_ builder:obj:)` methods (one takes `XxxT`, one
/// takes `XxxT?`) as part of `ObjectAPIPacker` conformance — this
/// protocol only needs to name the non-optional `pack` overload, since
/// `FBMsg.marshalFB` always has a definite `value` by the time it calls
/// it.
public protocol FlatBufferGeneratedTable: FlatBufferTable, Verifiable {
    associatedtype ObjectT
    func unpack() -> ObjectT
    static func pack(_ builder: inout FlatBufferBuilder, obj: inout ObjectT) -> Offset
}