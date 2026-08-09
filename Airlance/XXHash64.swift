import Foundation

/// Pure-Swift XXH64 (seed = 0), matching `github.com/cespare/xxhash/v2`'s
/// `xxhash.Sum64` exactly — this is what the Go server's `flatcodec.Codec`
/// uses for the 8-byte checksum prefix on every gRPC message body (see
/// `internal/infrastructure/flatcodec/codec.go`). Algorithm per the
/// official xxHash spec (Cyan4973/xxHash, xxhash_spec.md).
///
/// This is NOT a security mechanism (see the extensive comment in the
/// Go source) — purely a corruption/framing sanity check. A one-shot,
/// non-streaming implementation is sufficient here since every message
/// is fully buffered in memory before being framed.
enum XXHash64 {
    private static let prime1: UInt64 = 0x9E3779B185EBCA87
    private static let prime2: UInt64 = 0xC2B2AE3D27D4EB4F
    private static let prime3: UInt64 = 0x165667B19E3779F9
    private static let prime4: UInt64 = 0x85EBCA77C2B2AE63
    private static let prime5: UInt64 = 0x27D4EB2F165667C5

    /// Computes XXH64(data, seed: 0), matching `xxhash.Sum64(payload)` on
    /// the Go side.
    static func sum64(_ data: Data) -> UInt64 {
        sum64(data, seed: 0)
    }

    static func sum64(_ data: Data, seed: UInt64) -> UInt64 {
        let bytes = [UInt8](data)
        let length = bytes.count
        var pos = 0
        var h64: UInt64

        if length >= 32 {
            var v1 = seed &+ prime1 &+ prime2
            var v2 = seed &+ prime2
            var v3 = seed
            var v4 = seed &- prime1

            let limit = length - 32
            while pos <= limit {
                v1 = round(v1, readLE64(bytes, pos)); pos += 8
                v2 = round(v2, readLE64(bytes, pos)); pos += 8
                v3 = round(v3, readLE64(bytes, pos)); pos += 8
                v4 = round(v4, readLE64(bytes, pos)); pos += 8
            }

            h64 = rotl(v1, 1) &+ rotl(v2, 7) &+ rotl(v3, 12) &+ rotl(v4, 18)
            h64 = mergeRound(h64, v1)
            h64 = mergeRound(h64, v2)
            h64 = mergeRound(h64, v3)
            h64 = mergeRound(h64, v4)
        } else {
            h64 = seed &+ prime5
        }

        h64 = h64 &+ UInt64(length)

        while pos + 8 <= length {
            let k1 = round(0, readLE64(bytes, pos))
            h64 ^= k1
            h64 = rotl(h64, 27) &* prime1 &+ prime4
            pos += 8
        }

        if pos + 4 <= length {
            let v = UInt64(readLE32(bytes, pos))
            h64 ^= v &* prime1
            h64 = rotl(h64, 23) &* prime2 &+ prime3
            pos += 4
        }

        while pos < length {
            let v = UInt64(bytes[pos])
            h64 ^= v &* prime5
            h64 = rotl(h64, 11) &* prime1
            pos += 1
        }

        return avalanche(h64)
    }

    // MARK: - Primitive operations (see xxhash_spec.md "round"/"mergeRound"/"avalanche")

    private static func round(_ acc: UInt64, _ input: UInt64) -> UInt64 {
        var acc = acc
        acc = acc &+ (input &* prime2)
        acc = rotl(acc, 31)
        acc = acc &* prime1
        return acc
    }

    private static func mergeRound(_ acc: UInt64, _ val: UInt64) -> UInt64 {
        let val = round(0, val)
        var acc = acc ^ val
        acc = acc &* prime1 &+ prime4
        return acc
    }

    private static func avalanche(_ x: UInt64) -> UInt64 {
        var x = x
        x ^= x >> 33
        x = x &* prime2
        x ^= x >> 29
        x = x &* prime3
        x ^= x >> 32
        return x
    }

    private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x << n) | (x >> (64 - n))
    }

    // MARK: - Little-endian reads (xxHash reads input lanes as little-endian regardless of host order)

    private static func readLE64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 {
            v |= UInt64(bytes[offset + i]) << (8 * i)
        }
        return v
    }

    private static func readLE32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        var v: UInt32 = 0
        for i in 0..<4 {
            v |= UInt32(bytes[offset + i]) << (8 * i)
        }
        return v
    }
}