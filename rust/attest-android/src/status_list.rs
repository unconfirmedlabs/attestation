//! Google's attestation status list — revocation/suspension records for
//! attestation keys.
//!
//! Source: <https://android.googleapis.com/attestation/status>
//!
//! Shape (JSON):
//!
//! ```json
//! {
//!   "entries": {
//!     "<cert serial in lowercase hex>": {
//!       "status": "REVOKED" | "SUSPENDED",
//!       "reason": "KEY_COMPROMISE" | "CA_COMPROMISE" | "SUPERSEDED" | "SOFTWARE_FLAW"
//!     },
//!     ...
//!   }
//! }
//! ```
//!
//! This module does *not* fetch the list — fetching is the caller's
//! responsibility (typically the enclave, which can pin a max-age + a
//! retry cadence). We just parse and look up.

use crate::errors::{Error, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    /// Keyed by certificate serial in lowercase hex, no leading-zero padding.
    entries: HashMap<String, StatusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    pub status: String,
    pub reason: String,
}

impl StatusList {
    /// Parse a status list JSON blob fetched from
    /// `https://android.googleapis.com/attestation/status`.
    pub fn from_json(json: &str) -> Result<Self> {
        // Minimal hand-rolled parser to avoid adding a JSON dependency to
        // the verifier crate. The status list has a fixed shape — top-level
        // object with a single `"entries"` key whose value is an object of
        // string→object pairs.
        //
        // The enclave-server crate pulls in `serde_json` already; if this
        // module ever grows we can switch over.
        let trimmed = json.trim_start_matches('\u{feff}').trim();
        let bytes = trimmed.as_bytes();
        let mut pos = 0;
        expect_char(bytes, &mut pos, b'{')?;
        skip_ws(bytes, &mut pos);
        // Expect "entries"
        let key = read_string(bytes, &mut pos)?;
        if key != "entries" {
            return Err(Error::Der(format!(
                "status list expected top-level 'entries', got '{key}'"
            )));
        }
        skip_ws(bytes, &mut pos);
        expect_char(bytes, &mut pos, b':')?;
        skip_ws(bytes, &mut pos);
        expect_char(bytes, &mut pos, b'{')?;
        skip_ws(bytes, &mut pos);

        let mut entries = HashMap::new();
        if peek_char(bytes, pos) != Some(b'}') {
            loop {
                let serial = read_string(bytes, &mut pos)?;
                skip_ws(bytes, &mut pos);
                expect_char(bytes, &mut pos, b':')?;
                skip_ws(bytes, &mut pos);
                let entry = read_status_object(bytes, &mut pos)?;
                entries.insert(serial.to_lowercase(), entry);
                skip_ws(bytes, &mut pos);
                if peek_char(bytes, pos) == Some(b',') {
                    pos += 1;
                    skip_ws(bytes, &mut pos);
                    continue;
                }
                break;
            }
        }
        expect_char(bytes, &mut pos, b'}')?;
        skip_ws(bytes, &mut pos);
        expect_char(bytes, &mut pos, b'}')?;

        Ok(Self { entries })
    }

    pub fn lookup_serial(&self, serial_hex_lower: &str) -> Option<&StatusEntry> {
        self.entries.get(serial_hex_lower)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn expect_char(bytes: &[u8], pos: &mut usize, c: u8) -> Result<()> {
    skip_ws(bytes, pos);
    if bytes.get(*pos).copied() != Some(c) {
        return Err(Error::Der(format!(
            "status list JSON: expected '{}' at {}",
            c as char, *pos
        )));
    }
    *pos += 1;
    Ok(())
}

fn peek_char(bytes: &[u8], pos: usize) -> Option<u8> {
    bytes.get(pos).copied()
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while let Some(c) = bytes.get(*pos).copied() {
        if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
            *pos += 1;
        } else {
            break;
        }
    }
}

fn read_string(bytes: &[u8], pos: &mut usize) -> Result<String> {
    skip_ws(bytes, pos);
    if bytes.get(*pos).copied() != Some(b'"') {
        return Err(Error::Der(format!(
            "status list JSON: expected string at {}",
            *pos
        )));
    }
    *pos += 1;
    let start = *pos;
    while let Some(c) = bytes.get(*pos).copied() {
        if c == b'\\' {
            // We don't expect escapes in status-list serials/values, but
            // tolerate them by skipping the next byte.
            *pos += 2;
            continue;
        }
        if c == b'"' {
            let s = std::str::from_utf8(&bytes[start..*pos])
                .map_err(|e| Error::Der(format!("status list utf8: {e}")))?
                .to_string();
            *pos += 1;
            return Ok(s);
        }
        *pos += 1;
    }
    Err(Error::Der("status list JSON: unterminated string".into()))
}

fn read_status_object(bytes: &[u8], pos: &mut usize) -> Result<StatusEntry> {
    expect_char(bytes, pos, b'{')?;
    let mut status = String::new();
    let mut reason = String::new();
    skip_ws(bytes, pos);
    if peek_char(bytes, *pos) != Some(b'}') {
        loop {
            let key = read_string(bytes, pos)?;
            skip_ws(bytes, pos);
            expect_char(bytes, pos, b':')?;
            let val = read_string(bytes, pos)?;
            match key.as_str() {
                "status" => status = val,
                "reason" => reason = val,
                _ => {}
            }
            skip_ws(bytes, pos);
            if peek_char(bytes, *pos) == Some(b',') {
                *pos += 1;
                skip_ws(bytes, pos);
                continue;
            }
            break;
        }
    }
    expect_char(bytes, pos, b'}')?;
    Ok(StatusEntry { status, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_status_list() {
        let json = r#"{
            "entries": {
                "abc123": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
                "DEAD": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"}
            }
        }"#;
        let list = StatusList::from_json(json).expect("parse");
        assert_eq!(list.len(), 2);
        let e1 = list.lookup_serial("abc123").expect("abc123 present");
        assert_eq!(e1.status, "REVOKED");
        assert_eq!(e1.reason, "KEY_COMPROMISE");
        let e2 = list.lookup_serial("dead").expect("DEAD present (lowercased)");
        assert_eq!(e2.status, "SUSPENDED");
    }

    #[test]
    fn parse_empty_list() {
        let list = StatusList::from_json(r#"{"entries":{}}"#).expect("parse");
        assert!(list.is_empty());
    }
}
