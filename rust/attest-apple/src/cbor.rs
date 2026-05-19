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
