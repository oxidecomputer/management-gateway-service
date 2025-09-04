// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::tlv;
use core::fmt;
use core::str;
use zerocopy::{little_endian, IntoBytes};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Vpd<'buf> {
    Cpn(&'buf str),
    Serial(&'buf str),
    OxideRev(little_endian::U32),
    Mpn(&'buf str),
    MfgName(&'buf str),
    MfgRev(&'buf str),
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedVpd {
    Cpn(String),
    Serial(String),
    OxideRev(u32),
    Mpn(String),
    MfgName(String),
    MfgRev(String),
}

impl Vpd<'_> {
    // TLV tags for FRUID VPD.
    // See: https://rfd.shared.oxide.computer/rfd/308#_fruid_data

    pub const SERIAL_TAG: tlv::Tag = tlv::Tag(*b"SER0");
    /// Tag for Oxide part numbers. The value of this tag is a UTF-8-encoded string.
    pub const CPN_TAG: tlv::Tag = tlv::Tag(*b"CPN0");
    /// Tag for Oxide revisions. The value of this tag is always a little-endian `u32`.
    pub const OXIDE_REV_TAG: tlv::Tag = tlv::Tag(*b"REV0");

    /// Tag for manufacturer names. The value of this tag is a UTF-8-encoded string.
    pub const MFG_TAG: tlv::Tag = tlv::Tag(*b"MFG0");
    /// Tag for manufacturer part numbers. The value of this tag is a UTF-8-encoded string.
    pub const MPN_TAG: tlv::Tag = tlv::Tag(*b"MPN0");
    /// Manufacturer revision tag. Unlike `OXIDE_REV_TAG`, this is a byte array rather than a `u32`.
    pub const MFG_REV_TAG: tlv::Tag = tlv::Tag(*b"MRV0");

    pub fn tag(&self) -> tlv::Tag {
        match self {
            Self::Cpn(_) => Self::CPN_TAG,
            Self::Serial(_) => Self::SERIAL_TAG,
            Self::OxideRev(_) => Self::OXIDE_REV_TAG,
            Self::Mpn(_) => Self::MPN_TAG,
            Self::MfgName(_) => Self::MFG_TAG,
            Self::MfgRev(_) => Self::MFG_REV_TAG,
        }
    }

    pub fn value_bytes(&self) -> &[u8] {
        match self {
            Self::Cpn(cpn) => cpn.as_bytes(),
            Self::Serial(serial) => serial.as_bytes(),
            Self::OxideRev(rev) => rev.as_bytes(),
            Self::Mpn(mpn) => mpn.as_bytes(),
            Self::MfgName(name) => name.as_bytes(),
            Self::MfgRev(rev) => rev.as_bytes(),
        }
    }

    #[cfg(feature = "std")]
    pub fn into_owned(self) -> OwnedVpd {
        match self {
            Self::Cpn(cpn) => OwnedVpd::Cpn(cpn.to_string()),
            Self::Serial(serial) => OwnedVpd::Serial(serial.to_string()),
            Self::OxideRev(rev) => OwnedVpd::OxideRev(rev.get()),
            Self::Mpn(mpn) => OwnedVpd::Mpn(mpn.to_string()),
            Self::MfgName(mfg_name) => OwnedVpd::MfgName(mfg_name.to_string()),
            Self::MfgRev(mfg_rev) => OwnedVpd::MfgRev(mfg_rev.to_string()),
        }
    }
}

/// Intended for use with [`tlv::decode_iter`] and friends.
impl<'buf> TryFrom<(tlv::Tag, &'buf [u8])> for Vpd<'buf> {
    type Error = DecodeError;
    fn try_from(
        (tag, value): (tlv::Tag, &'buf [u8]),
    ) -> Result<Self, Self::Error> {
        match tag {
            Self::CPN_TAG => std::str::from_utf8(value)
                .map_err(DecodeError::invalid_str(tag))
                .map(Self::Cpn),
            Self::SERIAL_TAG => std::str::from_utf8(value)
                .map_err(DecodeError::invalid_str(tag))
                .map(Self::Serial),
            Self::OXIDE_REV_TAG => {
                let bytes: [u8; 4] = value
                    .try_into()
                    .map_err(|_| DecodeError::InvalidU32(tag))?;
                Ok(Self::OxideRev(u32::from_le_bytes(bytes).into()))
            }
            Self::MPN_TAG => std::str::from_utf8(value)
                .map_err(DecodeError::invalid_str(tag))
                .map(Self::Mpn),
            Self::MFG_TAG => std::str::from_utf8(value)
                .map_err(DecodeError::invalid_str(tag))
                .map(Self::MfgName),
            Self::MFG_REV_TAG => std::str::from_utf8(value)
                .map_err(DecodeError::invalid_str(tag))
                .map(Self::MfgRev),
            _ => Err(DecodeError::UnexpectedTag(tag)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedTag(tlv::Tag),
    InvalidUtf8(tlv::Tag, str::Utf8Error),
    InvalidU32(tlv::Tag),
}

impl DecodeError {
    fn invalid_str(tag: tlv::Tag) -> impl Fn(str::Utf8Error) -> Self {
        move |err| DecodeError::InvalidUtf8(tag, err)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedTag(tag) => {
                write!(f, "unexpected TLV tag {tag:?}")
            }
            DecodeError::InvalidUtf8(tag, err) => {
                write!(f, "value for tag {tag:?} was not UTF-8: {err}")
            }
            DecodeError::InvalidU32(tag) => {
                write!(f, "value for tag {tag:?} was not a u32")
            }
        }
    }
}
