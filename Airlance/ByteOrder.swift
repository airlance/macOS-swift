import Foundation

/// Explicit, alignment-safe big/little-endian integer <-> Data
/// conversions. Deliberately avoids `withUnsafeBytes { $0.load(...) }`
/// on `Data` subranges (not guaranteed aligned) and avoids relying on
/// host byte order via `Data(bytes: &scalar, count:)`, even though every
/// realistic macOS target is little-endian — the wire protocol's byte
/// order must never depend on the host's.
enum ByteOrder {

    static func uint32BigEndian(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ])
    }

    static func uint32LittleEndian(_ value: UInt32) -> Data {
        Data([
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF),
        ])
    }

    static func uint64BigEndian(_ value: UInt64) -> Data {
        var out = Data(capacity: 8)
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8((value >> UInt64(shift)) & 0xFF))
        }
        return out
    }

    /// Parses a big-endian UInt32 from exactly 4 bytes.
    static func readUInt32BigEndian(_ data: Data) -> UInt32 {
        precondition(data.count == 4)
        var value: UInt32 = 0
        for byte in data {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    /// Parses a little-endian UInt32 from exactly 4 bytes.
    static func readUInt32LittleEndian(_ data: Data) -> UInt32 {
        precondition(data.count == 4)
        var value: UInt32 = 0
        for (i, byte) in data.enumerated() {
            value |= UInt32(byte) << (8 * i)
        }
        return value
    }

    /// Parses a big-endian UInt64 from exactly 8 bytes.
    static func readUInt64BigEndian(_ data: Data) -> UInt64 {
        precondition(data.count == 8)
        var value: UInt64 = 0
        for byte in data {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }
}