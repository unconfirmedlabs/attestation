import CryptoKit
import DeviceCheck
import Foundation

/// Errors specific to the App Attest demo flow.
enum AttestError: LocalizedError {
    case unsupported
    case generateKeyFailed(Error)
    case attestKeyFailed(Error)
    case assertionFailed(Error)
    case noActiveKey
    case cborParseFailed(Error)

    var errorDescription: String? {
        switch self {
        case .unsupported:
            return "App Attest is not supported on this device or simulator. Run on a real device."
        case .generateKeyFailed(let e):
            return "generateKey failed: \(e.localizedDescription)"
        case .attestKeyFailed(let e):
            return "attestKey failed: \(e.localizedDescription)"
        case .assertionFailed(let e):
            return "generateAssertion failed: \(e.localizedDescription)"
        case .noActiveKey:
            return "No active attested key. Run an attestation first."
        case .cborParseFailed(let e):
            return "Failed to parse attestationObject CBOR: \(e.localizedDescription)"
        }
    }
}

/// A captured attestation — written to disk as a Rust-fixture JSON.
struct AttestationCapture {
    /// `keyId == SHA256(public_key_in_X9_63_form)`.
    let keyIdBytes: Data
    /// CBOR `attestationObject` from `attestKey`.
    let attestationObject: Data
    /// The 65-byte X9.63 public key the SE generated.
    let attestedPublicKey: Data
    /// Caller-supplied challenge the attestation was bound to.
    let challenge: Data
    /// `"<TEAM_ID>.<bundle_id>"` — the rpIdHash preimage.
    let appId: String
    /// `true` in production App Store / TestFlight builds, `false` for dev.
    let production: Bool
}

/// A captured assertion — also written as a fixture, but consumed by
/// the `attest_apple::assertion` Move module instead of `attestation`.
struct AssertionCapture {
    /// CBOR assertion bytes from `generateAssertion`.
    let assertionObject: Data
    /// Exact bytes the SE signed (the iOS app passed
    /// `clientDataHash = SHA256(clientData)` to Apple).
    let clientData: Data
    /// The previously-attested SE public key (X9.63, 65 B). Carried in
    /// the fixture so the host doesn't have to re-parse the attestation.
    let attestedPublicKey: Data
    /// Same app id used at attestation time.
    let appId: String
}

/// Persistent record of the active attested key. Saved to UserDefaults
/// so `generateAssertion` can be called across app launches.
private struct ActiveKey: Codable {
    let keyId: String              // base64 string, as Apple returns it
    let attestedKeyHex: String     // 65-byte X9.63 pk, hex-encoded
    let appId: String              // "TEAMID.bundleID" we used
}

final class AttestService {
    private let service = DCAppAttestService.shared
    private let activeKeyDefaultsKey = "AttestKitDemo.activeKey"

    var isSupported: Bool { service.isSupported }

    /// Returns the currently-active attested key, if any.
    var activeKey: (keyId: String, attestedKey: Data, appId: String)? {
        guard
            let data = UserDefaults.standard.data(forKey: activeKeyDefaultsKey),
            let stored = try? JSONDecoder().decode(ActiveKey.self, from: data),
            let pk = Data(hexString: stored.attestedKeyHex)
        else { return nil }
        return (stored.keyId, pk, stored.appId)
    }

    func clearActiveKey() {
        UserDefaults.standard.removeObject(forKey: activeKeyDefaultsKey)
    }

    /// Run a fresh attestation, persist the resulting (keyId, pk) so the
    /// assertion flow can reuse them.
    func attest(challenge: Data, appId: String, production: Bool) async throws -> AttestationCapture {
        guard isSupported else { throw AttestError.unsupported }

        // 1. New SE-bound key.
        let keyId: String = try await withCheckedThrowingContinuation { cont in
            service.generateKey { keyId, err in
                if let err { cont.resume(throwing: AttestError.generateKeyFailed(err)); return }
                guard let keyId else {
                    cont.resume(throwing: AttestError.generateKeyFailed(
                        NSError(domain: "AttestKitDemo", code: -1,
                                userInfo: [NSLocalizedDescriptionKey: "nil keyId"])))
                    return
                }
                cont.resume(returning: keyId)
            }
        }

        // 2. clientDataHash = SHA-256(challenge).
        let clientDataHash = Data(SHA256.hash(data: challenge))

        // 3. Attest.
        let attestationObject: Data = try await withCheckedThrowingContinuation { cont in
            service.attestKey(keyId, clientDataHash: clientDataHash) { att, err in
                if let err { cont.resume(throwing: AttestError.attestKeyFailed(err)); return }
                guard let att else {
                    cont.resume(throwing: AttestError.attestKeyFailed(
                        NSError(domain: "AttestKitDemo", code: -1,
                                userInfo: [NSLocalizedDescriptionKey: "nil attestation"])))
                    return
                }
                cont.resume(returning: att)
            }
        }

        // 4. Extract the attested pk by parsing the CBOR.
        let pk: Data
        do {
            pk = try extractAttestedPublicKey(from: attestationObject)
        } catch {
            throw AttestError.cborParseFailed(error)
        }

        // 5. keyId from Apple is base64 of the SHA-256 of the pk.
        let keyIdBytes = Data(base64Encoded: keyId) ?? Data()

        // 6. Persist for the assertion flow.
        let stored = ActiveKey(
            keyId: keyId,
            attestedKeyHex: pk.hex,
            appId: appId,
        )
        if let data = try? JSONEncoder().encode(stored) {
            UserDefaults.standard.set(data, forKey: activeKeyDefaultsKey)
        }

        return AttestationCapture(
            keyIdBytes: keyIdBytes,
            attestationObject: attestationObject,
            attestedPublicKey: pk,
            challenge: challenge,
            appId: appId,
            production: production,
        )
    }

    /// Sign arbitrary client data with the previously-attested SE key.
    /// Returns the assertion bytes for the host's verifier to consume.
    func assert(clientData: Data) async throws -> AssertionCapture {
        guard isSupported else { throw AttestError.unsupported }
        guard let active = activeKey else { throw AttestError.noActiveKey }

        let clientDataHash = Data(SHA256.hash(data: clientData))

        let assertion: Data = try await withCheckedThrowingContinuation { cont in
            service.generateAssertion(active.keyId, clientDataHash: clientDataHash) { a, err in
                if let err { cont.resume(throwing: AttestError.assertionFailed(err)); return }
                guard let a else {
                    cont.resume(throwing: AttestError.assertionFailed(
                        NSError(domain: "AttestKitDemo", code: -1,
                                userInfo: [NSLocalizedDescriptionKey: "nil assertion"])))
                    return
                }
                cont.resume(returning: a)
            }
        }

        return AssertionCapture(
            assertionObject: assertion,
            clientData: clientData,
            attestedPublicKey: active.attestedKey,
            appId: active.appId,
        )
    }
}

// MARK: - Helpers

extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            bytes.append(b)
            i += 2
        }
        self.init(bytes)
    }
}
