import Foundation
import NIOCore
import NIOFoundationCompat

/// Implements the gRPC-over-HTTP/2 message framing defined in
/// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
/// ("Length-Prefixed-Message"), independent of both the payload format
/// (flatbuffers here, protobuf normally) and of grpc-swift's own
/// (internal, unavailable) framing handler:
///
///   Length-Prefixed-Message -> Compressed-Flag Message-Length Message
///   Compressed-Flag         -> 1 byte, 0 or 1
///   Message-Length          -> 4-byte big-endian unsigned int
///
/// This project never sends `grpc-encoding`, so Compressed-Flag is
/// always 0 on write, and any Compressed-Flag other than 0 on read is a
/// protocol violation (we never advertised support for a
/// `grpc-accept-encoding`).
enum GRPCMessageFraming {
    static let compressedFlagSize = 1
    static let messageLengthSize = 4
    static let prefixSize = compressedFlagSize + messageLengthSize

    /// Wraps a single already-serialized message body (the flatcodec
    /// output — see `FlatbuffersCodec.swift` — NOT a raw flatbuffers
    /// buffer, since flatcodec's own xxhash prefix happens at a layer
    /// below this one) in the 5-byte gRPC length prefix.
    static func frame(_ messageBody: Data) -> Data {
        var out = Data(capacity: prefixSize + messageBody.count)
        out.append(0) // Compressed-Flag = 0, uncompressed
        out.append(ByteOrder.uint32BigEndian(UInt32(messageBody.count)))
        out.append(messageBody)
        return out
    }

    /// Errors specific to parsing the gRPC length-prefix framing itself
    /// (as opposed to errors from the payload codec above it).
    enum FramingError: Error, Equatable {
        case unsupportedCompression(flag: UInt8)
        case messageTooLarge(declared: UInt32, limit: UInt32)
    }

    /// A byte limit for a single gRPC message's declared length, applied
    /// before allocating a buffer for it — defends against a corrupt or
    /// hostile length prefix causing an unbounded allocation. 16 MiB is
    /// generous for anything AuthService sends (its largest messages are
    /// small fixed-shape tables), but not so tight that it could clip a
    /// legitimate future message.
    static let maxMessageSize: UInt32 = 16 * 1024 * 1024

    /// Incrementally parses zero or more complete `Length-Prefixed-Message`
    /// bodies out of `buffer`, leaving any trailing partial message in
    /// place for the next call. Mirrors the shape of a NIO
    /// `ByteToMessageDecoder`'s decode loop, but is deliberately a plain
    /// function (not a `ByteToMessageDecoder` conformance) so it can be
    /// driven directly from `AirlanceStreamHandler`'s `channelRead`
    /// alongside HTTP/2 frame/stream bookkeeping that a standalone
    /// decoder wouldn't have access to.
    ///
    /// Returns the decoded message bodies, in order. `buffer`'s reader
    /// index is advanced past everything consumed; unread trailing bytes
    /// (a partial length prefix or a partial message body) are left
    /// exactly where they are.
    static func decodeAvailableMessages(from buffer: inout ByteBuffer) throws -> [Data] {
        var messages: [Data] = []

        while true {
            guard buffer.readableBytes >= prefixSize else { return messages }

            let startIndex = buffer.readerIndex
            let compressedFlag: UInt8 = buffer.getInteger(at: startIndex, as: UInt8.self)!
            guard compressedFlag == 0 else {
                throw FramingError.unsupportedCompression(flag: compressedFlag)
            }

            let lengthBytes = buffer.getSlice(at: startIndex + compressedFlagSize, length: messageLengthSize)!
            let messageLength = ByteOrder.readUInt32BigEndian(Data(buffer: lengthBytes))

            guard messageLength <= maxMessageSize else {
                throw FramingError.messageTooLarge(declared: messageLength, limit: maxMessageSize)
            }

            let totalNeeded = prefixSize + Int(messageLength)
            guard buffer.readableBytes >= totalNeeded else { return messages } // wait for more bytes

            buffer.moveReaderIndex(forwardBy: prefixSize)
            let messageSlice = buffer.readSlice(length: Int(messageLength))!
            messages.append(Data(buffer: messageSlice))
        }
    }
}