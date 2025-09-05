// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::tlv;
use core::fmt;
use core::str;

pub const MAX_STR_LEN: usize = 32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Vpd<S> {
    Oxide(OxideVpd<S>),
    Mfg(MfgVpd<S>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OxideVpd<S> {
    pub serial: S,
    pub rev: u32,
    pub part_number: S,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MfgVpd<S> {
    pub mfg: S,
    pub serial: S,
    pub mfg_rev: S,
    pub mpn: S,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedOxideVpd {
    pub serial: String,
    pub rev: u32,
    pub part_number: String,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedMfgVpd {
    pub mfg: String,
    pub serial: String,
    pub mfg_rev: String,
    pub mpn: String,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedVpd {
    Oxide(OwnedOxideVpd),
    Mfg(OwnedMfgVpd),
}

// TLV tags for FRUID VPD.
// See: https://rfd.shared.oxide.computer/rfd/308#_fruid_data

const SERIAL_TAG: tlv::Tag = tlv::Tag(*b"SER0");
/// Tag for Oxide part numbers. The value of this tag is a UTF-8-encoded string.
const CPN_TAG: tlv::Tag = tlv::Tag(*b"CPN0");
/// Tag for Oxide revisions. The value of this tag is always a little-endian `u32`.
const OXIDE_REV_TAG: tlv::Tag = tlv::Tag(*b"REV0");

/// Tag for manufacturer names. The value of this tag is a UTF-8-encoded string.
const MFG_TAG: tlv::Tag = tlv::Tag(*b"MFG0");
/// Tag for manufacturer part numbers. The value of this tag is a UTF-8-encoded string.
const MPN_TAG: tlv::Tag = tlv::Tag(*b"MPN0");
/// Manufacturer revision tag. Unlike `OXIDE_REV_TAG`, this is a byte array rather than a `u32`.
const MFG_REV_TAG: tlv::Tag = tlv::Tag(*b"MRV0");

impl<S> Vpd<S>
where
    S: AsRef<str>,
{
    pub const TAG: tlv::Tag = tlv::Tag(*b"FRU0");

    pub fn tlv_len(&self) -> usize {
        match self {
            Vpd::Oxide(vpd) => tlv::tlv_len(vpd.tlv_len()),
            Vpd::Mfg(vpd) => tlv::tlv_len(vpd.tlv_len()),
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, hubpack::Error> {
        if out.len() < self.tlv_len() {
            return Err(hubpack::Error::Overrun);
        }
        match self {
            Vpd::Oxide(vpd) => vpd.encode(out),
            Vpd::Mfg(vpd) => vpd.encode(out),
        }
        .map_err(|e| match e {
            tlv::EncodeError::BufferTooSmall => hubpack::Error::Overrun,
            tlv::EncodeError::Custom(e) => e,
        })
    }
}

impl<'buf> Vpd<&'buf str> {
    pub fn decode_body(buf: &'buf [u8]) -> Result<Self, DecodeError> {
        let mut tags = tlv::decode_iter(buf);

        fn expect_tag<'a, T>(
            tags: &mut impl Iterator<
                Item = Result<(tlv::Tag, &'a [u8]), tlv::DecodeError>,
            >,
            expected_tag: tlv::Tag,
            decode: impl Fn(&'a [u8]) -> Result<T, DecodeError>,
        ) -> Result<T, DecodeError> {
            match tags.next() {
                Some(Ok((tag, value))) if tag == expected_tag => decode(value),
                Some(Ok((tag, _))) => Err(DecodeError::UnexpectedTag(tag)),
                Some(Err(err)) => Err(DecodeError::Tlv(expected_tag, err)),
                None => Err(DecodeError::MissingTag(expected_tag)),
            }
        }

        fn expect_str_tag<'a>(
            tags: &mut impl Iterator<
                Item = Result<(tlv::Tag, &'a [u8]), tlv::DecodeError>,
            >,
            expected_tag: tlv::Tag,
        ) -> Result<&'a str, DecodeError> {
            expect_tag(tags, expected_tag, |value| {
                core::str::from_utf8(value)
                    .map_err(DecodeError::invalid_str(expected_tag))
            })
        }

        let serial = expect_str_tag(&mut tags, SERIAL_TAG)?;
        match tags.next() {
            Some(Ok((MFG_TAG, mfg))) => {
                let mfg = core::str::from_utf8(mfg)
                    .map_err(DecodeError::invalid_str(MFG_TAG))?;
                let mpn = expect_str_tag(&mut tags, MPN_TAG)?;
                let mfg_rev = expect_str_tag(&mut tags, MFG_REV_TAG)?;
                Ok(Self::Mfg(MfgVpd { mfg, mpn, mfg_rev, serial }))
            }
            Some(Ok((CPN_TAG, cpn))) => {
                let part_number = core::str::from_utf8(cpn)
                    .map_err(DecodeError::invalid_str(MFG_TAG))?;
                let rev = expect_tag(&mut tags, OXIDE_REV_TAG, |value| {
                    let rev_bytes: [u8; 4] = value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidU32(OXIDE_REV_TAG))?;
                    Ok(u32::from_le_bytes(rev_bytes))
                })?;
                Ok(Self::Oxide(OxideVpd { part_number, rev, serial }))
            }
            Some(Ok((tag, _))) => Err(DecodeError::UnexpectedTag(tag)),
            Some(Err(e)) => Err(DecodeError::TlvUntyped(e)),
            None => Err(DecodeError::UnexpectedEnd),
        }
    }

    #[cfg(feature = "std")]
    pub fn into_owned(self) -> Vpd<String> {
        match self {
            Self::Oxide(vpd) => Vpd::Oxide(vpd.into_owned()),
            Self::Mfg(vpd) => Vpd::Mfg(vpd.into_owned()),
        }
    }
}

impl<S> OxideVpd<S>
where
    S: AsRef<str>,
{
    pub fn tlv_len(&self) -> usize {
        tlv::tlv_len(self.part_number.as_ref().len())
            + tlv::tlv_len(self.serial.as_ref().len())
            + tlv::tlv_len(4) // revision number (u32)
    }

    pub fn encode(
        &self,
        out: &mut [u8],
    ) -> Result<usize, tlv::EncodeError<hubpack::Error>> {
        if out.len() < self.tlv_len() {
            return Err(tlv::EncodeError::Custom(hubpack::Error::Overrun));
        }
        let mut total = 0;
        total += encode_str(&mut out[total..], SERIAL_TAG, &self.serial)?;
        total += encode_str(&mut out[total..], CPN_TAG, &self.part_number)?;
        total += tlv::encode(&mut out[total..], OXIDE_REV_TAG, |out| {
            if out.len() < 4 {
                return Err(hubpack::Error::Overrun);
            }
            out.copy_from_slice(&self.rev.to_le_bytes()[..]);
            Ok(4)
        })?;
        Ok(total)
    }

    #[cfg(feature = "std")]
    pub fn into_owned(self) -> OxideVpd<String> {
        let Self { serial, rev, part_number } = self;
        OxideVpd {
            serial: serial.as_ref().to_owned(),
            rev,
            part_number: part_number.as_ref().to_owned(),
        }
    }
}

impl<S> MfgVpd<S>
where
    S: AsRef<str>,
{
    pub fn tlv_len(&self) -> usize {
        tlv::tlv_len(self.mfg.as_ref().len())
            + tlv::tlv_len(self.mpn.as_ref().len())
            + tlv::tlv_len(self.mfg_rev.as_ref().len())
            + tlv::tlv_len(self.serial.as_ref().len())
    }

    pub fn encode(
        &self,
        out: &mut [u8],
    ) -> Result<usize, tlv::EncodeError<hubpack::Error>> {
        if out.len() < self.tlv_len() {
            return Err(tlv::EncodeError::Custom(hubpack::Error::Overrun));
        }
        let mut total = 0;
        total += encode_str(&mut out[total..], SERIAL_TAG, &self.serial)?;
        total += encode_str(&mut out[total..], MFG_TAG, &self.mfg)?;
        total += encode_str(&mut out[total..], MPN_TAG, &self.mpn)?;
        total += encode_str(&mut out[total..], MFG_REV_TAG, &self.mfg_rev)?;
        Ok(total)
    }

    #[cfg(feature = "std")]
    pub fn into_owned(self) -> MfgVpd<String> {
        let Self { serial, mfg_rev, mpn, mfg } = self;
        MfgVpd {
            serial: serial.as_ref().to_owned(),
            mfg_rev: mfg_rev.as_ref().to_owned(),
            mpn: mpn.as_ref().to_owned(),
            mfg: mfg.as_ref().to_owned(),
        }
    }
}

fn encode_str(
    out: &mut [u8],
    tag: tlv::Tag,
    value: &impl AsRef<str>,
) -> Result<usize, tlv::EncodeError<hubpack::Error>> {
    let value = value.as_ref();
    tlv::encode(out, tag, |out| {
        if out.len() < value.len() {
            return Err(hubpack::Error::Overrun);
        }
        out[..value.len()].copy_from_slice(value.as_bytes());
        Ok(value.len())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    MissingTag(tlv::Tag),
    UnexpectedTag(tlv::Tag),
    InvalidUtf8(tlv::Tag, str::Utf8Error),
    InvalidU32(tlv::Tag),
    Tlv(tlv::Tag, tlv::DecodeError),
    TlvUntyped(tlv::DecodeError),
}

impl DecodeError {
    fn invalid_str(tag: tlv::Tag) -> impl Fn(str::Utf8Error) -> Self {
        move |err| DecodeError::InvalidUtf8(tag, err)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTag(tag) => write!(
                f,
                "unexpected end of input while expecting TLV tag {tag:?}"
            ),
            Self::UnexpectedTag(tag) => {
                write!(f, "unexpected TLV tag {tag:?}")
            }
            Self::InvalidUtf8(tag, err) => {
                write!(f, "value for tag {tag:?} was not UTF-8: {err}")
            }
            Self::InvalidU32(tag) => {
                write!(f, "value for tag {tag:?} was not a u32")
            }
            Self::Tlv(tag, error) => {
                write!(f, "TLV decode error while decoding {tag:?}: {error}")
            }
            Self::TlvUntyped(error) => {
                write!(f, "TLV decode error while expecting {MFG_TAG:?} or {CPN_TAG:?}: {error}")
            }
            Self::UnexpectedEnd => {
                write!(f, "unexpected end of input")
            }
        }
    }
}
