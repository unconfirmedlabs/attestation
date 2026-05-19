/// Package one-time-witness module.
///
/// Creates the kagi `EnclavePolicy<ATTESTATION>` shared object at deploy
/// time. PCR values start empty and must be filled in after the EIF is
/// built (via `update_pcrs` on the cap).
module attestation::attestation;

use kagi::enclave_policy;

/// One-time witness for the package. The all-caps name matches the
/// module's name, as required by `sui::types::is_one_time_witness`.
public struct ATTESTATION has drop {}

fun init(otw: ATTESTATION, ctx: &mut TxContext) {
    let (policy, cap) = enclave_policy::new(
        otw,
        vector[], // PCR0 — set after first EIF build
        vector[], // PCR1
        vector[], // PCR2
        ctx,
    );
    policy.share();
    transfer::public_transfer(cap, ctx.sender());
}
