import Foundation

/// Swift mirror of the Go server's `flatcodec.Codec` (see codec.go):
/// every gRPC message BODY (i.e. what `GRPCMessageFraming` wraps in the
/// 5-byte gRPC length prefix) is:
///
///   offset 0, size 8 : xxhash64(payload), big-endian
///   offset 8, size N : raw flatbuffers buffer
///
/// Not a security mechanism (the channel is already authenticated by
/// wireauthgrpc) — purely a corruption/framing sanity check, same
/// rationale as the Go side.
enum FlatbuffersCodec {
    static let checksumSize = 8

    /// Serializes `message` and prepends the xxhash64 checksum, producing
    /// exactly what `GRPCMessageFraming.frame` expects as its
    /// `messageBody` argument.
    static func encode<M: FBMessage>(_ message: M) -> Data {
        let payload = message.marshalFB()
        let sum = XXHash64.sum64(payload)

        var out = Data(capacity: checksumSize + payload.count)
        out.append(ByteOrder.uint64BigEndian(sum))
        out.append(payload)
        return out
    }

    enum DecodeError: Error, Equatable {
        case frameTooShort(got: Int, want: Int)
        case checksumMismatch(got: UInt64, want: UInt64)
    }

    /// Verifies the checksum and decodes the flatbuffers payload that
    /// follows it. `data` is one already-length-delimited gRPC message
    /// body (i.e. the output of `GRPCMessageFraming.decodeAvailableMessages`,
    /// not the whole HTTP/2 DATA frame).
    static func decode<M: FBMessage>(_ data: Data, as type: M.Type) throws -> M {
        guard data.count >= checksumSize else {
            throw DecodeError.frameTooShort(got: data.count, want: checksumSize)
        }

        let checksumBytes = data.subdata(in: 0..<checksumSize)
        let wantSum = ByteOrder.readUInt64BigEndian(checksumBytes)
        let payload = data.subdata(in: checksumSize..<data.count)

        let gotSum = XXHash64.sum64(payload)
        guard gotSum == wantSum else {
            throw DecodeError.checksumMismatch(got: gotSum, want: wantSum)
        }

        return try M.unmarshalFB(payload)
    }
}