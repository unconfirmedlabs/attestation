//
// Minimal CBOR decoder for the slices of Apple App Attest we need:
//
// 1. The top-level attestationObject CBOR map (to pull out authData).
// 2. The authData layout (fixed-offset bytes).
// 3. The credentialPublicKey embedded inside authData (a COSE_Key map),
//    from which we extract the X and Y coordinates and assemble the
//    65-byte X9.63 (SEC1 uncompressed) representation:
//
//        0x04 ‖ X(32) ‖ Y(32)
//
// We deliberately avoid pulling in a CBOR dependency for ~100 lines of
// hand-written parsing. This is read-only and only handles the CBOR
// subset used by App Attest.
//

import Foundation

enum CBORError: Error {
    case truncated
    case unexpectedType(UInt8)
    case missingKey(String)
    case malformedKey
    case missingField(Int)
    case wrongCurve
}

struct CBORReader {
    let bytes: [UInt8]
    var pos: Int = 0

    init(_ data: Data) {
        self.bytes = Array(data)
    }

    mutating func readByte() throws -> UInt8 {
        guard pos < bytes.count else { throw CBORError.truncated }
        let b = bytes[pos]
        pos += 1
        return b
    }

    // Read CBOR length/value field for major types that use it.
    // Returns the decoded count or unsigned value.
    mutating func readLength(_ info: UInt8) throws -> UInt64 {
        switch info {
        case 0...23: return UInt64(info)
        case 24: return UInt64(try readByte())
        case 25:
            let a = UInt64(try readByte())
            let b = UInt64(try readByte())
            return (a << 8) | b
        case 26:
            var v: UInt64 = 0
            for _ in 0..<4 { v = (v << 8) | UInt64(try readByte()) }
            return v
        case 27:
            var v: UInt64 = 0
            for _ in 0..<8 { v = (v << 8) | UInt64(try readByte()) }
            return v
        default:
            throw CBORError.unexpectedType(info)
        }
    }

    mutating func readBytes() throws -> Data {
        let h = try readByte()
        let major = h >> 5
        let info = h & 0x1F
        guard major == 2 else { throw CBORError.unexpectedType(h) }
        let len = Int(try readLength(info))
        guard pos + len <= bytes.count else { throw CBORError.truncated }
        let slice = bytes[pos..<(pos + len)]
        pos += len
        return Data(slice)
    }

    mutating func readText() throws -> String {
        let h = try readByte()
        let major = h >> 5
        let info = h & 0x1F
        guard major == 3 else { throw CBORError.unexpectedType(h) }
        let len = Int(try readLength(info))
        guard pos + len <= bytes.count else { throw CBORError.truncated }
        let slice = bytes[pos..<(pos + len)]
        pos += len
        return String(bytes: slice, encoding: .utf8) ?? ""
    }

    // Read a CBOR integer (uint or negint). Returns signed Int64.
    mutating func readInt() throws -> Int64 {
        let h = try readByte()
        let major = h >> 5
        let info = h & 0x1F
        let v = Int64(try readLength(info))
        switch major {
        case 0: return v          // uint
        case 1: return -1 - v     // negint (encoded as -1 - n)
        default: throw CBORError.unexpectedType(h)
        }
    }

    // Skip a CBOR value of any of the major types we encounter.
    mutating func skipValue() throws {
        let h = try readByte()
        let major = h >> 5
        let info = h & 0x1F
        switch major {
        case 0, 1: _ = try readLength(info)
        case 2:
            let n = Int(try readLength(info)); pos += n
        case 3:
            let n = Int(try readLength(info)); pos += n
        case 4:
            let n = Int(try readLength(info))
            for _ in 0..<n { try skipValue() }
        case 5:
            let n = Int(try readLength(info))
            for _ in 0..<n { try skipValue(); try skipValue() }
        default:
            throw CBORError.unexpectedType(h)
        }
    }

    // Read a CBOR map header and return the entry count.
    mutating func readMapHeader() throws -> Int {
        let h = try readByte()
        let major = h >> 5
        let info = h & 0x1F
        guard major == 5 else { throw CBORError.unexpectedType(h) }
        return Int(try readLength(info))
    }
}

/// Extract the 65-byte X9.63 (SEC1 uncompressed) public key from an
/// Apple App Attest `attestationObject` payload.
///
/// The hex of this is what the iOS app stores as `attested_key_hex`
/// alongside the `keyId`, so subsequent assertion verifications can
/// be performed without parsing the attestationObject again.
func extractAttestedPublicKey(from attestationObject: Data) throws -> Data {
    var r = CBORReader(attestationObject)

    // Top-level map: { fmt, attStmt, authData }
    let n = try r.readMapHeader()
    var authData: Data?
    for _ in 0..<n {
        let key = try r.readText()
        switch key {
        case "authData":
            authData = try r.readBytes()
        default:
            try r.skipValue()
        }
    }
    guard let ad = authData else { throw CBORError.missingKey("authData") }

    // authData layout:
    //   rpIdHash      32 B
    //   flags          1 B
    //   signCount      4 B
    //   aaguid        16 B
    //   credIdLength   2 B (big-endian)
    //   credId       credIdLength B
    //   credentialPublicKey (rest of authData; a COSE_Key CBOR map)
    guard ad.count >= 37 + 18 else { throw CBORError.truncated }
    let credIdLen = (UInt16(ad[53]) << 8) | UInt16(ad[54])
    let cosePkStart = 55 + Int(credIdLen)
    guard cosePkStart <= ad.count else { throw CBORError.truncated }
    let coseBytes = ad.subdata(in: cosePkStart..<ad.count)

    // COSE_Key map. For P-256: { 1: 2, 3: -7, -1: 1, -2: X(32), -3: Y(32) }
    var c = CBORReader(coseBytes)
    let cn = try c.readMapHeader()
    var x: Data?
    var y: Data?
    var kty: Int64?
    var crv: Int64?
    for _ in 0..<cn {
        let k = try c.readInt()
        switch k {
        case 1:  kty = try c.readInt()
        case 3:  _ = try c.readInt()     // alg — accept any, ignore
        case -1: crv = try c.readInt()
        case -2: x = try c.readBytes()
        case -3: y = try c.readBytes()
        default: try c.skipValue()
        }
    }
    guard kty == 2 else { throw CBORError.wrongCurve }  // EC2
    guard crv == 1 else { throw CBORError.wrongCurve }  // P-256
    guard let xb = x, let yb = y, xb.count == 32, yb.count == 32 else {
        throw CBORError.missingField(-2)
    }

    var pk = Data(capacity: 65)
    pk.append(0x04)
    pk.append(xb)
    pk.append(yb)
    return pk
}
