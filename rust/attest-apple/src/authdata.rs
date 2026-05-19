//! Parser for App Attest's `authData` field.
//!
//! Format (per the WebAuthn spec, which App Attest follows):
//!
//! ```text
//!  0..32   rpIdHash         (32 bytes)
//! 32..33   flags            (1 byte)
//! 33..37   signCount        (4 bytes, big-endian u32)
//! 37..53   aaguid           (16 bytes)        -- present iff flags & 0x40
//! 53..55   credentialIdLen  (2 bytes, BE u16)
//! 55..N    credentialId
//! N..end   credentialPublicKey (COSE_Key, CBOR-encoded)
//! ```

use crate::errors::{Error, Result};

const AT_FLAG: u8 = 0x40;

#[derive(Debug)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// Raw COSE_Key bytes (CBOR-encoded). Decode with `cose::extract_p256_pk`.
    pub credential_public_key: Vec<u8>,
}

pub fn parse(bytes: &[u8]) -> Result<AuthData> {
    if bytes.len() < 37 {
        return Err(Error::AuthDataTooShort(bytes.len()));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[0..32]);

    let flags = bytes[32];
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().expect("4 bytes"));

    if flags & AT_FLAG == 0 {
        return Err(Error::NoAttestedCredentialData);
    }

    if bytes.len() < 37 + 16 + 2 {
        return Err(Error::AuthDataTooShort(bytes.len()));
    }

    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&bytes[37..53]);

    let cred_id_len = u16::from_be_bytes(bytes[53..55].try_into().expect("2 bytes")) as usize;

    if bytes.len() < 55 + cred_id_len {
        return Err(Error::AuthDataTooShort(bytes.len()));
    }

    let credential_id = bytes[55..55 + cred_id_len].to_vec();
    let credential_public_key = bytes[55 + cred_id_len..].to_vec();

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        aaguid,
        credential_id,
        credential_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short() {
        let r = parse(&[0u8; 36]);
        assert!(matches!(r, Err(Error::AuthDataTooShort(36))));
    }

    #[test]
    fn rejects_no_at_flag() {
        let mut buf = vec![0u8; 60];
        buf[32] = 0x00; // flags = 0
        let r = parse(&buf);
        assert!(matches!(r, Err(Error::NoAttestedCredentialData)));
    }
}
