//! CBOR decoding for Apple App Attest's `attestationObject`.
//!
//! The object is a CBOR map with three top-level keys:
//!
//! ```text
//! {
//!   "fmt":      "apple-appattest",
//!   "authData": <bytes>,
//!   "attStmt":  {
//!       "x5c":     [<DER-encoded cert>, <DER-encoded cert>, ...],
//!       "receipt": <bytes>
//!   }
//! }
//! ```

use crate::errors::{Error, Result};
use ciborium::value::Value;
use std::io::Cursor;

#[derive(Debug)]
pub struct AttestationStatement {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    pub x5c: Vec<Vec<u8>>,
    pub receipt: Vec<u8>,
}

pub fn decode_attestation_object(bytes: &[u8]) -> Result<AttestationStatement> {
    let value: Value = ciborium::from_reader(Cursor::new(bytes))
        .map_err(|e| Error::Cbor(format!("top-level decode: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| Error::Cbor("top-level value is not a map".into()))?;

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Vec<u8>> = None;
    let mut att_stmt: Option<&Value> = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| Error::Cbor("non-text key at top level".into()))?;
        match key {
            "fmt" => {
                fmt = v.as_text().map(str::to_owned);
            }
            "authData" => {
                auth_data = v.as_bytes().cloned();
            }
            "attStmt" => {
                att_stmt = Some(v);
            }
            _ => {}
        }
    }

    let fmt = fmt.ok_or_else(|| Error::Cbor("missing 'fmt'".into()))?;
    let auth_data = auth_data.ok_or_else(|| Error::Cbor("missing 'authData'".into()))?;
    let att_stmt = att_stmt.ok_or_else(|| Error::Cbor("missing 'attStmt'".into()))?;

    let att_map = att_stmt
        .as_map()
        .ok_or_else(|| Error::Cbor("attStmt is not a map".into()))?;

    let mut x5c: Option<Vec<Vec<u8>>> = None;
    let mut receipt: Vec<u8> = Vec::new();

    for (k, v) in att_map {
        let key = k
            .as_text()
            .ok_or_else(|| Error::Cbor("non-text key in attStmt".into()))?;
        match key {
            "x5c" => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| Error::Cbor("x5c is not an array".into()))?;
                let mut certs = Vec::with_capacity(arr.len());
                for c in arr {
                    let bytes = c
                        .as_bytes()
                        .ok_or_else(|| Error::Cbor("x5c element is not bytes".into()))?;
                    certs.push(bytes.to_vec());
                }
                x5c = Some(certs);
            }
            "receipt" => {
                if let Some(b) = v.as_bytes() {
                    receipt = b.to_vec();
                }
            }
            _ => {}
        }
    }

    let x5c = x5c.ok_or_else(|| Error::Cbor("missing 'x5c' in attStmt".into()))?;

    Ok(AttestationStatement {
        fmt,
        auth_data,
        x5c,
        receipt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an attestationObject CBOR map. `x5c`/`receipt` go inside attStmt.
    /// Pass `None` for a top-level key to omit it.
    fn build(
        fmt: Option<&str>,
        auth_data: Option<Vec<u8>>,
        att_stmt: Option<Value>,
    ) -> Vec<u8> {
        let mut entries = Vec::new();
        if let Some(f) = fmt {
            entries.push((Value::Text("fmt".into()), Value::Text(f.into())));
        }
        if let Some(a) = auth_data {
            entries.push((Value::Text("authData".into()), Value::Bytes(a)));
        }
        if let Some(s) = att_stmt {
            entries.push((Value::Text("attStmt".into()), s));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    }

    fn att_stmt(x5c: Option<Vec<Vec<u8>>>, receipt: Option<Vec<u8>>) -> Value {
        let mut entries = Vec::new();
        if let Some(certs) = x5c {
            entries.push((
                Value::Text("x5c".into()),
                Value::Array(certs.into_iter().map(Value::Bytes).collect()),
            ));
        }
        if let Some(r) = receipt {
            entries.push((Value::Text("receipt".into()), Value::Bytes(r)));
        }
        Value::Map(entries)
    }

    #[test]
    fn decodes_well_formed_object() {
        let bytes = build(
            Some("apple-appattest"),
            Some(vec![1, 2, 3]),
            Some(att_stmt(Some(vec![vec![0xAA], vec![0xBB]]), Some(vec![9, 9]))),
        );
        let stmt = decode_attestation_object(&bytes).unwrap();
        assert_eq!(stmt.fmt, "apple-appattest");
        assert_eq!(stmt.auth_data, vec![1, 2, 3]);
        assert_eq!(stmt.x5c, vec![vec![0xAA], vec![0xBB]]);
        assert_eq!(stmt.receipt, vec![9, 9]);
    }

    #[test]
    fn receipt_is_optional() {
        let bytes = build(
            Some("apple-appattest"),
            Some(vec![1]),
            Some(att_stmt(Some(vec![vec![0xAA]]), None)),
        );
        let stmt = decode_attestation_object(&bytes).unwrap();
        assert!(stmt.receipt.is_empty());
    }

    #[test]
    fn rejects_non_cbor() {
        assert!(matches!(
            decode_attestation_object(&[0xFF, 0xFF]),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_truncated_cbor() {
        let bytes = build(
            Some("apple-appattest"),
            Some(vec![1, 2, 3]),
            Some(att_stmt(Some(vec![vec![0xAA]]), None)),
        );
        let truncated = &bytes[..bytes.len() / 2];
        assert!(decode_attestation_object(truncated).is_err());
    }

    #[test]
    fn rejects_top_level_not_map() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Array(vec![]), &mut bytes).unwrap();
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_missing_fmt() {
        let bytes = build(None, Some(vec![1]), Some(att_stmt(Some(vec![vec![0xAA]]), None)));
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_missing_auth_data() {
        let bytes = build(
            Some("apple-appattest"),
            None,
            Some(att_stmt(Some(vec![vec![0xAA]]), None)),
        );
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_missing_att_stmt() {
        let bytes = build(Some("apple-appattest"), Some(vec![1]), None);
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_missing_x5c() {
        let bytes = build(
            Some("apple-appattest"),
            Some(vec![1]),
            Some(att_stmt(None, Some(vec![9]))),
        );
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_x5c_not_array() {
        let stmt = Value::Map(vec![(
            Value::Text("x5c".into()),
            Value::Text("not-an-array".into()),
        )]);
        let bytes = build(Some("apple-appattest"), Some(vec![1]), Some(stmt));
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_x5c_element_not_bytes() {
        let stmt = Value::Map(vec![(
            Value::Text("x5c".into()),
            Value::Array(vec![Value::Text("not-bytes".into())]),
        )]);
        let bytes = build(Some("apple-appattest"), Some(vec![1]), Some(stmt));
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn rejects_att_stmt_not_map() {
        let bytes = build(
            Some("apple-appattest"),
            Some(vec![1]),
            Some(Value::Text("not-a-map".into())),
        );
        assert!(matches!(
            decode_attestation_object(&bytes),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn fmt_is_preserved_for_wrong_format() {
        // decode itself does not enforce fmt == apple-appattest; it returns whatever
        // the blob says (verify_app_attest is what rejects a wrong fmt).
        let bytes = build(
            Some("android-key"),
            Some(vec![1]),
            Some(att_stmt(Some(vec![vec![0xAA]]), None)),
        );
        let stmt = decode_attestation_object(&bytes).unwrap();
        assert_eq!(stmt.fmt, "android-key");
    }
}
