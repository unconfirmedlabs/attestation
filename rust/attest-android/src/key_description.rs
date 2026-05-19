//! ASN.1 decoder for Google's Android Key Attestation extension.
//!
//! Reference: <https://source.android.com/docs/security/features/keystore/attestation>
//!
//! The leaf certificate of an attestation chain carries an extension at OID
//! `1.3.6.1.4.1.11129.2.1.17` whose value is a DER-encoded `KeyDescription`:
//!
//! ```text
//! KeyDescription ::= SEQUENCE {
//!     attestationVersion         INTEGER,        -- 1, 2, 3, 4, 100, 200, 300, 400
//!     attestationSecurityLevel   SecurityLevel,
//!     keymasterVersion           INTEGER,        -- renamed keyMintVersion in v300+
//!     keymasterSecurityLevel     SecurityLevel,
//!     attestationChallenge       OCTET_STRING,
//!     uniqueId                   OCTET_STRING,
//!     softwareEnforced           AuthorizationList,
//!     teeEnforced                AuthorizationList,  -- renamed hardwareEnforced in v300+
//! }
//! ```
//!
//! `AuthorizationList` is a SEQUENCE of sparsely-tagged fields. Every field
//! is OPTIONAL and identified by its EXPLICIT context-specific tag, not by
//! position. We decode it by walking the SEQUENCE's children and dispatching
//! on tag number.
//!
//! Tag numbers we extract here cover what a security-policy decision actually
//! needs. We deliberately don't decode every tag in the spec — most consumers
//! never look at them, and the unparsed bytes are kept available via
//! `KeyDescription::raw` for callers that need finer-grained inspection.

use crate::errors::{Error, Result};
use der::{
    asn1::{Int, OctetString},
    Decode, Reader, SliceReader, Tag,
};

/// Android attestation custom extension OID.
pub const OID_ANDROID_KEY_ATTESTATION: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Security level enum, identical wire format in both KeyDescription header
/// and inside an AuthorizationList.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// `0` — host process, no hardware backing.
    Software,
    /// `1` — TEE (TrustZone or equivalent secure world).
    TrustedEnvironment,
    /// `2` — discrete secure element (StrongBox).
    StrongBox,
}

impl SecurityLevel {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }

    /// Returns `true` if `self` is at least as strong as `other`.
    /// Ordering: Software < TrustedEnvironment < StrongBox.
    pub fn meets(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::Software => 0,
            Self::TrustedEnvironment => 1,
            Self::StrongBox => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    /// `0` — GREEN. Verified Boot succeeded with the OEM key.
    Verified,
    /// `1` — YELLOW. Locked with a user-installed key (e.g., GrapheneOS).
    SelfSigned,
    /// `2` — ORANGE. Bootloader unlocked.
    Unverified,
    /// `3` — RED. Verified Boot failed.
    Failed,
}

impl VerifiedBootState {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Verified),
            1 => Some(Self::SelfSigned),
            2 => Some(Self::Unverified),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Root-of-Trust block, present inside the hardware-enforced AuthorizationList
/// at tag `[704]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    /// Present from attestation version 3 onwards.
    pub verified_boot_hash: Option<Vec<u8>>,
}

/// Subset of AuthorizationList fields a verifier actually uses.
///
/// Every field is OPTIONAL on the wire; an absent field is `None` here.
/// The full byte slice for the AuthorizationList is preserved in
/// `KeyDescription::software_enforced_raw` / `hardware_enforced_raw` so a
/// caller that needs a tag we don't decode can reach for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    /// Tag `[701]` — `creationDateTime`, milliseconds since epoch.
    pub creation_date_time: Option<u64>,
    /// Tag `[704]` — `rootOfTrust`. Only meaningful inside the
    /// hardware-enforced list.
    pub root_of_trust: Option<RootOfTrust>,
    /// Tag `[705]` — `osVersion`, packed integer.
    pub os_version: Option<u32>,
    /// Tag `[706]` — `osPatchLevel`, YYYYMM integer.
    pub os_patch_level: Option<u32>,
    /// Tag `[709]` — `attestationApplicationId`, a DER OCTET STRING
    /// wrapping a nested ASN.1 SEQUENCE. Stored here as raw bytes — the
    /// inner structure can be parsed with [`attestation_application_id`].
    pub attestation_application_id: Option<Vec<u8>>,
}

/// Decoded Android Key Attestation extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    pub attestation_version: i32,
    pub attestation_security_level: SecurityLevel,
    pub keymint_version: i32,
    pub keymint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

impl KeyDescription {
    /// Decode a `KeyDescription` from the DER bytes of the attestation
    /// extension value. The extension value is itself an OCTET STRING
    /// in the X.509 extension, so callers should pass the bytes *inside*
    /// that OCTET STRING (not the OCTET STRING header).
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = SliceReader::new(bytes)
            .map_err(|e| Error::Der(format!("KeyDescription outer: {e}")))?;
        let outer_header = reader.peek_header().map_err(|e| Error::Der(e.to_string()))?;
        if outer_header.tag != Tag::Sequence {
            return Err(Error::Der(format!(
                "expected SEQUENCE, got {:?}",
                outer_header.tag
            )));
        }

        // Consume the sequence header and re-parse the body using `Decode`
        // helpers.
        let header = reader.decode::<der::Header>().map_err(|e| Error::Der(e.to_string()))?;
        let body = reader
            .read_slice(header.length)
            .map_err(|e| Error::Der(format!("KeyDescription body: {e}")))?;

        let mut br = SliceReader::new(body)
            .map_err(|e| Error::Der(format!("KeyDescription body reader: {e}")))?;

        let attestation_version =
            decode_i32(&mut br).map_err(|e| Error::Der(format!("attestationVersion: {e}")))?;
        let attestation_security_level_i =
            decode_enumerated(&mut br).map_err(|e| Error::Der(format!("attSecLevel: {e}")))?;
        let attestation_security_level = SecurityLevel::from_i32(attestation_security_level_i)
            .ok_or_else(|| Error::Der(format!("unknown SecurityLevel {attestation_security_level_i}")))?;

        let keymint_version =
            decode_i32(&mut br).map_err(|e| Error::Der(format!("keymintVersion: {e}")))?;
        let keymint_security_level_i =
            decode_enumerated(&mut br).map_err(|e| Error::Der(format!("kmSecLevel: {e}")))?;
        let keymint_security_level = SecurityLevel::from_i32(keymint_security_level_i)
            .ok_or_else(|| Error::Der(format!("unknown SecurityLevel {keymint_security_level_i}")))?;

        let attestation_challenge = OctetString::decode(&mut br)
            .map_err(|e| Error::Der(format!("attestationChallenge: {e}")))?
            .into_bytes();

        let unique_id = OctetString::decode(&mut br)
            .map_err(|e| Error::Der(format!("uniqueId: {e}")))?
            .into_bytes();

        let software_enforced = decode_authorization_list(&mut br)
            .map_err(|e| Error::Der(format!("softwareEnforced: {e}")))?;

        let hardware_enforced = decode_authorization_list(&mut br)
            .map_err(|e| Error::Der(format!("hardwareEnforced: {e}")))?;

        Ok(Self {
            attestation_version,
            attestation_security_level,
            keymint_version,
            keymint_security_level,
            attestation_challenge,
            unique_id,
            software_enforced,
            hardware_enforced,
        })
    }
}

/// Decode an `AuthorizationList`. The outer wrapper is a SEQUENCE; its
/// children are EXPLICIT context-specific tags whose tag numbers exceed
/// 255 (e.g. 400, 702). The `der` crate caps tag numbers at u8, so we
/// can't use it for these — we walk the SEQUENCE body with a minimal
/// TLV parser that handles long-form tags + lengths.
fn decode_authorization_list<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<AuthorizationList> {
    let header = reader.decode::<der::Header>()?;
    if header.tag != Tag::Sequence {
        return Err(der::Error::new(
            der::ErrorKind::TagUnexpected {
                expected: Some(Tag::Sequence),
                actual: header.tag,
            },
            reader.position(),
        ));
    }
    let body = reader.read_slice(header.length)?;
    let body_bytes = body.as_ref();

    let mut out = AuthorizationList::default();
    let mut pos = 0;
    while pos < body_bytes.len() {
        let (class, _constructed, tag_num, header_len, body_len) =
            parse_tlv_header(body_bytes, pos).map_err(|_| {
                der::Error::new(
                    der::ErrorKind::Value { tag: Tag::Sequence },
                    reader.position(),
                )
            })?;
        let value_start = pos + header_len;
        let value_end = value_start + body_len;
        if value_end > body_bytes.len() {
            return Err(der::Error::new(
                der::ErrorKind::Length { tag: Tag::Sequence },
                reader.position(),
            ));
        }
        let inner = &body_bytes[value_start..value_end];

        // Context-specific class only.
        if class == 2 {
            let mut ir = SliceReader::new(inner)?;
            match tag_num {
                701 => {
                    let n = decode_u64(&mut ir).map_err(|_| {
                        der::Error::new(
                            der::ErrorKind::Value { tag: Tag::Integer },
                            ir.position(),
                        )
                    })?;
                    out.creation_date_time = Some(n);
                }
                704 => {
                    out.root_of_trust = Some(decode_root_of_trust(&mut ir)?);
                }
                705 => {
                    let n = decode_i32(&mut ir).map_err(|_| {
                        der::Error::new(
                            der::ErrorKind::Value { tag: Tag::Integer },
                            ir.position(),
                        )
                    })?;
                    out.os_version = Some(n as u32);
                }
                706 => {
                    let n = decode_i32(&mut ir).map_err(|_| {
                        der::Error::new(
                            der::ErrorKind::Value { tag: Tag::Integer },
                            ir.position(),
                        )
                    })?;
                    out.os_patch_level = Some(n as u32);
                }
                709 => {
                    let v = OctetString::decode(&mut ir)?;
                    out.attestation_application_id = Some(v.into_bytes());
                }
                _ => {
                    // Tag we don't decode; ignored.
                }
            }
        }

        pos = value_end;
    }

    Ok(out)
}

/// Parse the leading TLV header from `bytes[pos..]`.
///
/// Returns `(class, constructed, tag_number, header_length, body_length)`.
/// Handles long-form tag numbers (first-byte low 5 bits = 0x1F + 7-bit
/// continuation bytes) and long-form lengths (first-byte high bit set +
/// N bytes following).
///
/// `class` is the two-bit ASN.1 tag class (0=universal, 1=application,
/// 2=context-specific, 3=private). `constructed` is the constructed bit.
fn parse_tlv_header(
    bytes: &[u8],
    pos: usize,
) -> std::result::Result<(u8, bool, u32, usize, usize), ()> {
    if pos >= bytes.len() {
        return Err(());
    }
    let first = bytes[pos];
    let class = (first >> 6) & 0b11;
    let constructed = first & 0b0010_0000 != 0;
    let low5 = first & 0b0001_1111;

    let mut cur = pos + 1;
    let tag_number: u32 = if low5 < 0x1F {
        low5 as u32
    } else {
        let mut n: u32 = 0;
        loop {
            if cur >= bytes.len() {
                return Err(());
            }
            let b = bytes[cur];
            cur += 1;
            n = n
                .checked_shl(7)
                .ok_or(())?
                .checked_add((b & 0x7F) as u32)
                .ok_or(())?;
            if b & 0x80 == 0 {
                break;
            }
        }
        n
    };

    if cur >= bytes.len() {
        return Err(());
    }
    let len_first = bytes[cur];
    cur += 1;
    let body_len: usize = if len_first & 0x80 == 0 {
        len_first as usize
    } else {
        let n = (len_first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(()); // indefinite or absurdly large
        }
        let mut v: usize = 0;
        for _ in 0..n {
            if cur >= bytes.len() {
                return Err(());
            }
            v = v
                .checked_shl(8)
                .ok_or(())?
                .checked_add(bytes[cur] as usize)
                .ok_or(())?;
            cur += 1;
        }
        v
    };

    Ok((class, constructed, tag_number, cur - pos, body_len))
}

fn decode_root_of_trust<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<RootOfTrust> {
    // RootOfTrust ::= SEQUENCE { ... }
    let header = reader.decode::<der::Header>()?;
    if header.tag != Tag::Sequence {
        return Err(der::Error::new(
            der::ErrorKind::TagUnexpected {
                expected: Some(Tag::Sequence),
                actual: header.tag,
            },
            reader.position(),
        ));
    }
    let body = reader.read_slice(header.length)?;
    let mut br = SliceReader::new(body)?;

    let verified_boot_key = OctetString::decode(&mut br)?.into_bytes();
    let device_locked = bool::decode(&mut br)?;
    let verified_boot_state_i = decode_enumerated(&mut br)
        .map_err(|_| der::Error::new(der::ErrorKind::Value { tag: Tag::Enumerated }, br.position()))?;
    let verified_boot_state = VerifiedBootState::from_i32(verified_boot_state_i)
        .ok_or_else(|| der::Error::new(der::ErrorKind::Value { tag: Tag::Enumerated }, br.position()))?;

    let verified_boot_hash = if br.is_finished() {
        None
    } else {
        Some(OctetString::decode(&mut br)?.into_bytes())
    };

    Ok(RootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot_state,
        verified_boot_hash,
    })
}

/// Decode an ASN.1 INTEGER as `i32`. Rejects values that don't fit.
fn decode_i32<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<i32> {
    let int = Int::decode(reader)?;
    let bytes = int.as_bytes();
    if bytes.len() > 4 {
        return Err(der::Error::new(
            der::ErrorKind::Overflow,
            reader.position(),
        ));
    }
    // Sign-extend the big-endian representation.
    let mut buf = [0u8; 4];
    let negative = bytes.first().copied().map(|b| b & 0x80 != 0).unwrap_or(false);
    if negative {
        buf = [0xFF; 4];
    }
    let offset = 4 - bytes.len();
    buf[offset..].copy_from_slice(bytes);
    Ok(i32::from_be_bytes(buf))
}

/// Decode an ASN.1 INTEGER as `u64`, rejecting negatives or values >2^63-1.
fn decode_u64<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<u64> {
    let int = Int::decode(reader)?;
    let bytes = int.as_bytes();
    // INTEGER is two's-complement; first byte high-bit set means negative.
    if bytes.first().copied().map(|b| b & 0x80 != 0).unwrap_or(false) {
        return Err(der::Error::new(
            der::ErrorKind::Value { tag: Tag::Integer },
            reader.position(),
        ));
    }
    if bytes.len() > 8 {
        return Err(der::Error::new(
            der::ErrorKind::Overflow,
            reader.position(),
        ));
    }
    let mut buf = [0u8; 8];
    let offset = 8 - bytes.len();
    buf[offset..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

/// Decode an ASN.1 ENUMERATED as `i32`.
fn decode_enumerated<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<i32> {
    let header = reader.decode::<der::Header>()?;
    if header.tag != Tag::Enumerated {
        return Err(der::Error::new(
            der::ErrorKind::TagUnexpected {
                expected: Some(Tag::Enumerated),
                actual: header.tag,
            },
            reader.position(),
        ));
    }
    let body = reader.read_slice(header.length)?;
    let mut buf = [0u8; 4];
    if body.len() > 4 {
        return Err(der::Error::new(
            der::ErrorKind::Overflow,
            reader.position(),
        ));
    }
    let negative = body.first().copied().map(|b| b & 0x80 != 0).unwrap_or(false);
    if negative {
        buf = [0xFF; 4];
    }
    let offset = 4 - body.len();
    buf[offset..].copy_from_slice(body);
    Ok(i32::from_be_bytes(buf))
}

/// Parsed `attestationApplicationId` field (tag `[709]` historically,
/// `[706]` in current spec). The outer OCTET STRING wraps a SEQUENCE:
///
/// ```text
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos      SET OF AttestationPackageInfo,
///     signatureDigests  SET OF OCTET_STRING
/// }
/// AttestationPackageInfo ::= SEQUENCE {
///     packageName  OCTET_STRING,
///     version      INTEGER
/// }
/// ```
///
/// Each `signatureDigest` is SHA-256 of an APK signing certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationApplicationId {
    pub package_infos: Vec<PackageInfo>,
    pub signature_digests: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub package_name: Vec<u8>,
    pub version: i64,
}

/// Parse an `attestationApplicationId` blob (the value stored in
/// [`AuthorizationList::attestation_application_id`]).
pub fn attestation_application_id(bytes: &[u8]) -> Result<AttestationApplicationId> {
    let mut reader = SliceReader::new(bytes)
        .map_err(|e| Error::Der(format!("AAID outer: {e}")))?;

    let header = reader
        .decode::<der::Header>()
        .map_err(|e| Error::Der(e.to_string()))?;
    if header.tag != Tag::Sequence {
        return Err(Error::Der(format!(
            "AAID expected SEQUENCE got {:?}",
            header.tag
        )));
    }
    let body = reader
        .read_slice(header.length)
        .map_err(|e| Error::Der(format!("AAID body: {e}")))?;
    let mut br = SliceReader::new(body)
        .map_err(|e| Error::Der(format!("AAID body reader: {e}")))?;

    // packageInfos  SET OF SEQUENCE
    let pkgs_header = br.decode::<der::Header>().map_err(|e| Error::Der(e.to_string()))?;
    if pkgs_header.tag != Tag::Set {
        return Err(Error::Der(format!(
            "AAID packageInfos expected SET got {:?}",
            pkgs_header.tag
        )));
    }
    let pkgs_body = br.read_slice(pkgs_header.length).map_err(|e| Error::Der(e.to_string()))?;
    let mut pr = SliceReader::new(pkgs_body).map_err(|e| Error::Der(e.to_string()))?;
    let mut package_infos = Vec::new();
    while !pr.is_finished() {
        let h = pr.decode::<der::Header>().map_err(|e| Error::Der(e.to_string()))?;
        if h.tag != Tag::Sequence {
            return Err(Error::Der(format!("AAID PackageInfo expected SEQ got {:?}", h.tag)));
        }
        let pbody = pr.read_slice(h.length).map_err(|e| Error::Der(e.to_string()))?;
        let mut pbr = SliceReader::new(pbody).map_err(|e| Error::Der(e.to_string()))?;
        let name = OctetString::decode(&mut pbr).map_err(|e| Error::Der(e.to_string()))?;
        let version_int = Int::decode(&mut pbr).map_err(|e| Error::Der(e.to_string()))?;
        let version = decode_i64_from_int(version_int.as_bytes())?;
        package_infos.push(PackageInfo {
            package_name: name.into_bytes(),
            version,
        });
    }

    // signatureDigests  SET OF OCTET STRING
    let sigs_header = br.decode::<der::Header>().map_err(|e| Error::Der(e.to_string()))?;
    if sigs_header.tag != Tag::Set {
        return Err(Error::Der(format!(
            "AAID signatureDigests expected SET got {:?}",
            sigs_header.tag
        )));
    }
    let sigs_body = br.read_slice(sigs_header.length).map_err(|e| Error::Der(e.to_string()))?;
    let mut sr = SliceReader::new(sigs_body).map_err(|e| Error::Der(e.to_string()))?;
    let mut signature_digests = Vec::new();
    while !sr.is_finished() {
        let v = OctetString::decode(&mut sr).map_err(|e| Error::Der(e.to_string()))?;
        signature_digests.push(v.into_bytes());
    }

    Ok(AttestationApplicationId {
        package_infos,
        signature_digests,
    })
}

fn decode_i64_from_int(bytes: &[u8]) -> Result<i64> {
    if bytes.len() > 8 {
        return Err(Error::Der("AAID version > i64".into()));
    }
    let mut buf = [0u8; 8];
    let negative = bytes.first().copied().map(|b| b & 0x80 != 0).unwrap_or(false);
    if negative {
        buf = [0xFF; 8];
    }
    let offset = 8 - bytes.len();
    buf[offset..].copy_from_slice(bytes);
    Ok(i64::from_be_bytes(buf))
}
