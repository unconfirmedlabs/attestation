/// Android Key Attestation source markers.
///
/// `Witness<AndroidKeyAttestation>` proves that a key generated inside
/// an Android Keystore (TEE or StrongBox) was attested by an X.509 chain
/// rooted at one of Google's pinned hardware attestation roots, and that
/// the policy decision (security level, verified boot, device locked)
/// passed inside the pinned enclave image.
module attest_android::source;

/// Marker for `Witness<AndroidKeyAttestation>`: proves a key was
/// attested by an X.509 chain anchored at a Google attestation root,
/// with hardware-enforced metadata that meets the verifier's policy.
public struct AndroidKeyAttestation has drop {}

public(package) fun new_android_key_attestation(): AndroidKeyAttestation {
    AndroidKeyAttestation {}
}
