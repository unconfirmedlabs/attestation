//! COSE_Key decoding for the credential public key inside `authData`.
//!
//! A P-256 COSE_Key looks like:
//!
//! ```text
//! {
//!   1  (kty): 2 (EC2),
//!   3  (alg): -7 (ES256),
//!   -1 (crv): 1 (P-256),
//!   -2 (x):   <32 bytes>,
//!   -3 (y):   <32 bytes>,
//! }
//! ```

use crate::errors::{Error, Result};
use ciborium::value::Value;
use std::io::Cursor;

/// P-256 public key in uncompressed SEC1 form (0x04 || X || Y), 65 bytes.
pub type P256Pk = [u8; 65];

pub fn extract_p256_pk(cose_bytes: &[u8]) -> Result<P256Pk> {
    let value: Value = ciborium::from_reader(Cursor::new(cose_bytes))
        .map_err(|e| Error::Cose(format!("decode: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| Error::Cose("COSE_Key is not a map".into()))?;

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;

    for (k, v) in map {
        let Some(key_int) = k.as_integer() else { continue };
        let key: i64 = match key_int.try_into() {
            Ok(i) => i,
            Err(_) => continue,
        };
        match key {
            1 => kty = v.as_integer().and_then(|i| i.try_into().ok()),
            3 => alg = v.as_integer().and_then(|i| i.try_into().ok()),
            -1 => crv = v.as_integer().and_then(|i| i.try_into().ok()),
            -2 => x = v.as_bytes().cloned(),
            -3 => y = v.as_bytes().cloned(),
            _ => {}
        }
    }

    if kty != Some(2) {
        return Err(Error::NotP256);
    }
    if alg != Some(-7) {
        return Err(Error::Cose(format!("alg must be -7 (ES256), got {alg:?}")));
    }
    if crv != Some(1) {
        return Err(Error::NotP256);
    }

    let x = x.ok_or_else(|| Error::Cose("missing x coordinate".into()))?;
    let y = y.ok_or_else(|| Error::Cose("missing y coordinate".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Cose(format!(
            "x/y must be 32 bytes (got x={}, y={})",
            x.len(),
            y.len()
        )));
    }

    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&x);
    pk[33..65].copy_from_slice(&y);
    Ok(pk)
}

/// The "public key" that Apple's `keyId` hashes is the X9.63 uncompressed
/// representation: `0x04 || X || Y` (65 bytes). This is what
/// `SecKeyCopyExternalRepresentation` returns for an `ECPublicKey`.
pub fn key_id_input(pk: &P256Pk) -> &[u8] {
    pk.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a COSE_Key CBOR map from optional members. `None` omits the member.
    fn cose_key(
        kty: Option<i64>,
        alg: Option<i64>,
        crv: Option<i64>,
        x: Option<Vec<u8>>,
        y: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut entries = Vec::new();
        if let Some(v) = kty {
            entries.push((Value::Integer(1.into()), Value::Integer(v.into())));
        }
        if let Some(v) = alg {
            entries.push((Value::Integer(3.into()), Value::Integer(v.into())));
        }
        if let Some(v) = crv {
            entries.push((Value::Integer((-1).into()), Value::Integer(v.into())));
        }
        if let Some(v) = x {
            entries.push((Value::Integer((-2).into()), Value::Bytes(v)));
        }
        if let Some(v) = y {
            entries.push((Value::Integer((-3).into()), Value::Bytes(v)));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    }

    fn valid_key() -> Vec<u8> {
        let x = vec![0x11u8; 32];
        let y = vec![0x22u8; 32];
        cose_key(Some(2), Some(-7), Some(1), Some(x), Some(y))
    }

    #[test]
    fn extracts_valid_p256_key() {
        let bytes = valid_key();
        let pk = extract_p256_pk(&bytes).unwrap();
        assert_eq!(pk[0], 0x04);
        assert_eq!(&pk[1..33], &[0x11u8; 32]);
        assert_eq!(&pk[33..65], &[0x22u8; 32]);
        // key_id_input is the full 65-byte SEC1 point.
        assert_eq!(key_id_input(&pk), &pk[..]);
    }

    #[test]
    fn rejects_wrong_kty() {
        let bytes = cose_key(Some(3), Some(-7), Some(1), Some(vec![1; 32]), Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::NotP256)));
    }

    #[test]
    fn rejects_missing_kty() {
        let bytes = cose_key(None, Some(-7), Some(1), Some(vec![1; 32]), Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::NotP256)));
    }

    #[test]
    fn rejects_wrong_alg() {
        // alg = -8 (EdDSA) instead of -7 (ES256).
        let bytes = cose_key(Some(2), Some(-8), Some(1), Some(vec![1; 32]), Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_wrong_curve() {
        // crv = 2 (P-384) instead of 1 (P-256).
        let bytes = cose_key(Some(2), Some(-7), Some(2), Some(vec![1; 32]), Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::NotP256)));
    }

    #[test]
    fn rejects_missing_x() {
        let bytes = cose_key(Some(2), Some(-7), Some(1), None, Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_missing_y() {
        let bytes = cose_key(Some(2), Some(-7), Some(1), Some(vec![1; 32]), None);
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_wrong_coordinate_length() {
        // x is 31 bytes, not 32.
        let bytes = cose_key(Some(2), Some(-7), Some(1), Some(vec![1; 31]), Some(vec![2; 32]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
        // y is 33 bytes, not 32.
        let bytes = cose_key(Some(2), Some(-7), Some(1), Some(vec![1; 32]), Some(vec![2; 33]));
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_non_cbor() {
        assert!(matches!(extract_p256_pk(&[0xFF, 0xFF, 0xFF]), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_cbor_that_is_not_a_map() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Array(vec![]), &mut bytes).unwrap();
        assert!(matches!(extract_p256_pk(&bytes), Err(Error::Cose(_))));
    }

    #[test]
    fn rejects_truncated_cbor() {
        let bytes = valid_key();
        let truncated = &bytes[..bytes.len() / 2];
        // Must Err, not panic.
        assert!(extract_p256_pk(truncated).is_err());
    }
}
