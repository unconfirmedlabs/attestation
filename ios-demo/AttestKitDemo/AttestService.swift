import CryptoKit
import DeviceCheck
import Foundation

/// Errors specific to the App Attest demo flow.
enum AttestError: LocalizedError {
    case unsupported
    case generateKeyFailed(Error)
    case attestKeyFailed(Error)

    var errorDescription: String? {
        switch self {
        case .unsupported:
            return "App Attest is not supported on this device or simulator. Run on a real device."
        case .generateKeyFailed(let e):
            return "generateKey failed: \(e.localizedDescription)"
        case .attestKeyFailed(let e):
            return "attestKey failed: \(e.localizedDescription)"
        }
    }
}

/// A captured attestation, suitable for serializing as a Rust test fixture.
struct AttestationCapture {
    /// The keyId Apple returned. Base64-decoded to raw bytes.
    /// `keyId == SHA256(public_key_in_X9_63_form)`.
    let keyIdBytes: Data

    /// The CBOR-encoded attestationObject from `attestKey`.
    let attestationObject: Data

    /// The challenge that was bound into the attestation.
    let challenge: Data

    /// The full app id used by Apple's rpIdHash check: "TEAMID.bundleID".
    /// This is filled in by the caller (the device knows its bundle id; the
    /// team id comes from provisioning).
    let appId: String

    /// `true` when running in production (App Store / TestFlight), `false`
    /// for the development sandbox.
    let production: Bool
}

/// Thin wrapper around `DCAppAttestService`.
final class AttestService {
    private let service = DCAppAttestService.shared

    /// `true` on real iOS devices (production or dev), `false` on simulator
    /// and on devices that lack the necessary hardware.
    var isSupported: Bool { service.isSupported }

    /// Generate a fresh Secure Enclave key and attest it against the given
    /// challenge. Always returns the development-mode attestation when the
    /// app is signed with the development App Attest entitlement, which is
    /// what the dev workflow uses.
    func attest(challenge: Data, appId: String, production: Bool) async throws -> AttestationCapture {
        guard isSupported else { throw AttestError.unsupported }

        // 1. Generate a new key inside the Secure Enclave.
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

        // 2. Compute clientDataHash = SHA-256(challenge).
        let clientDataHash = Data(SHA256.hash(data: challenge))

        // 3. Attest the key against that hash.
        let attestation: Data = try await withCheckedThrowingContinuation { cont in
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

        // 4. Apple returns keyId as a base64 string; decode to raw bytes.
        let keyIdBytes = Data(base64Encoded: keyId) ?? Data()

        return AttestationCapture(
            keyIdBytes: keyIdBytes,
            attestationObject: attestation,
            challenge: challenge,
            appId: appId,
            production: production
        )
    }
}

extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
