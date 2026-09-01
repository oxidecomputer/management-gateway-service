// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::nullstr::{self, NullStr};
use core::fmt;
use hubpack::SerializedSize;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

pub use nullstr::ReadIntoError as BarcodeReadError;

/// Contains one component's vital product data.
///
/// This owned representation is intended for MGS to use when deserializing data
/// from the SP. SP implementations may serialize [`VpdRef`] directly into
/// packet storage instead of constructing this enum on their stack.
#[allow(clippy::large_enum_variant)]
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum Vpd {
    Pmbus(PmbusVpd),
    Barcode(Barcode),
    FanAssembly(FanAssemblyVpd),
    Tmp117(Tmp117Identity),
}

impl fmt::Display for Vpd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pmbus(vpd) => vpd.fmt(f),
            Self::Barcode(identity) => identity.fmt(f),
            Self::FanAssembly(identity) => identity.fmt(f),
            Self::Tmp117(identity) => identity.fmt(f),
        }
    }
}

/// A borrowed reference to any device's VPD type.
///
/// This type has the same hubpack representation as [`Vpd`]. The SP
/// implementation may use it to serialize VPD directly into a packet's
/// trailing-data buffer rather than constructing an owned [`Vpd`] on the stack.
#[derive(Debug, Serialize)]
pub enum VpdRef<'a> {
    Pmbus(&'a PmbusVpd),
    Barcode(&'a Barcode),
    FanAssembly(&'a FanAssemblyVpd),
    Tmp117(&'a Tmp117Identity),
}

impl<'a> From<&'a Vpd> for VpdRef<'a> {
    fn from(value: &'a Vpd) -> Self {
        match value {
            Vpd::Pmbus(vpd) => Self::Pmbus(vpd),
            Vpd::Barcode(identity) => Self::Barcode(identity),
            Vpd::FanAssembly(identity) => Self::FanAssembly(identity),
            Vpd::Tmp117(identity) => Self::Tmp117(identity),
        }
    }
}

impl fmt::Display for VpdRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pmbus(vpd) => vpd.fmt(f),
            Self::Barcode(identity) => identity.fmt(f),
            Self::FanAssembly(identity) => identity.fmt(f),
            Self::Tmp117(identity) => identity.fmt(f),
        }
    }
}
/// Maximum length to represent a barcode is determined based on the max
/// length of the MPN1 format, per [§7.2 RFD308]. An 0XV1 or 0XV2 barcode
/// will be much shorter.
///
/// [§7.2 RFD308]: https://rfd.shared.oxide.computer/rfd/0308#fmt-mpn.
pub const MAX_BARCODE_LEN: usize = 128;

/// A barcode in any of the 0XV1, 0XV2, or MPN1 formats (see [RFD308]).
///
/// [RFD308]: https://rfd.shared.oxide.computer/rfd/0308
pub type Barcode = NullStr<MAX_BARCODE_LEN>;

/// Vital product data for a PMBus device.
///
/// All vital product data commands we read are SMBus block reads. See the
/// [`SmbusBlock`] type for more details on how the result of block read
/// commands are represented.
///
/// Depending on the particular device in question, some VPD commands may or may
/// not be supported. When a device does not implement a particular command, the
/// field for that command's value is set to [`SmbusBlock::UNSUPPORTED`].
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct PmbusVpd {
    /// `MFR_ID` (PMBus command 0x99).
    pub mfr_id: SmbusBlock,
    /// `MFR_MODEL` (PMBus command 0x9A).
    pub mfr_model: SmbusBlock,
    /// `MFR_REVISION` (PMBus command 0x9B).
    pub mfr_revision: SmbusBlock,
    /// `MFR_LOCATION` (PMBus command 0x9C).
    pub mfr_location: SmbusBlock,
    /// `MFR_DATE` (PMBus command 0x9D).
    pub mfr_date: SmbusBlock,
    /// `MFR_SERIAL` (PMBus command 0x9E).
    pub mfr_serial: SmbusBlock,
    /// `IC_DEVICE_ID` (PMBus command 0xAD).
    pub ic_device_id: SmbusBlock,
    /// `IC_DEVICE_REV` (PMBus command 0xAE).
    pub ic_device_rev: SmbusBlock,
}

impl PmbusVpd {
    /// An instance with every command marked unsupported and every buffer zeroed.
    pub const EMPTY: Self = Self {
        mfr_id: SmbusBlock::UNSUPPORTED,
        mfr_model: SmbusBlock::UNSUPPORTED,
        mfr_revision: SmbusBlock::UNSUPPORTED,
        mfr_location: SmbusBlock::UNSUPPORTED,
        mfr_date: SmbusBlock::UNSUPPORTED,
        mfr_serial: SmbusBlock::UNSUPPORTED,
        ic_device_id: SmbusBlock::UNSUPPORTED,
        ic_device_rev: SmbusBlock::UNSUPPORTED,
    };
}

impl Default for PmbusVpd {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl fmt::Display for PmbusVpd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, block) in [
            ("MFR_ID", &self.mfr_id),
            ("MFR_MODEL", &self.mfr_model),
            ("MFR_REVISION", &self.mfr_revision),
            ("MFR_LOCATION", &self.mfr_location),
            ("MFR_DATE", &self.mfr_date),
            ("MFR_SERIAL", &self.mfr_serial),
            ("IC_DEVICE_ID", &self.ic_device_id),
            ("IC_DEVICE_REV", &self.ic_device_rev),
        ] {
            if block.is_unsupported() {
                continue;
            }
            if !first {
                f.write_str("\n")?;
            }
            write!(f, "{name:<13} : {block}")?;
            first = false;
        }
        Ok(())
    }
}

/// A buffer for storing the value sent in response to a SMBus block read
/// command (see 6.5.7 in the [SMBus Specification 3.3][smbus]), along with the
/// length of the data read into that buffer, or an indication that the device
/// does not support a given command.
///
/// [smbus]: https://www.smbus.org/specs/SMBus_3_3_20230228.pdf
#[derive(Debug, Clone, PartialEq, Eq, SerializedSize, Serialize)]
pub struct SmbusBlock {
    // The structure of this type may seem a bit weird, but it is intended to be
    // able to represent a few things distinctly:
    //
    // - We did not send the device a particular PMBus command at all, because
    //   it does not support that command and will NAK it,
    //
    // - We read a block of data from the device, which included some bytes that
    //   were zero; these may be trailing zeroes,
    //
    // - The device responded to a read with a zero-length response.
    //
    // In order to represent all of these possibiliies, we must store the length
    // of the buffer that contains bytes actually returned by the device, so
    // that it is possible to distinguish trailing zero bytes actually read from
    // a device from NUL padding inserted due to hubpack serialization
    // requirements. Furthermore, we must *also* be able to distinguish a zero
    // length because no bytes were read because the command was not supported
    // from a zero-length response from the device.
    //
    // Thus, we arrive here. The `len` field is an `Option<u8>` that represents
    // the number of bytes in the `bytes` array that were actually read over
    // PMBus in response to a command. If the `len` is `None`, then the command
    // is not believed to be supported by the device and therefore was not sent.
    // If it is `Some`, then it contains the length of the response, which may
    // be zero, but also may not be. Any zero bytes at indices within `len` were
    // read from the device, and any zero bytes *past* len are `NUL`-padding
    // inserted to satisfy hubpack serialization requirements.
    len: Option<u8>,
    bytes: [u8; SmbusBlock::MAX_LEN],
}

impl SmbusBlock {
    /// Marks an unsupported command and provides zeroed backing storage.
    pub const UNSUPPORTED: Self =
        Self { len: None, bytes: [0; SmbusBlock::MAX_LEN] };

    /// Maximum number of bytes we support in a SMBus block read.
    ///
    /// This is a bit arbitrary, as the protocol as specified in the SMBus
    /// specification will permit a block to be up to 255 bytes in length.
    /// However, none of the devices we expect to work with will return blocks
    /// bigger than 32 bytes for any of these commands, so it's fine.
    pub const MAX_LEN: usize = 32;

    /// Perform a SMBus block read into this block's buffer.
    ///
    /// The provided read function should return an `Option<usize>`, with `None`
    /// indicating that the device does not support this VPD command, and
    /// `Some(len)` indicating the number of bytes read.
    ///
    /// The remaining length of the `SmbusBlock`'s buffer after the portion
    /// filled by the read function is zeroed after reading into it. If the read
    /// function returns an error, returns `None` to indicate that the register
    /// is unsupported by the device, or returns a length greater than the
    /// length of the buffer, the `SmbusBlock` is zeroed completely, and this
    /// function returns an error and the buffer is zeroed completely.
    pub fn read_into<E>(
        &mut self,
        f: impl FnOnce(&mut [u8; SmbusBlock::MAX_LEN]) -> Result<Option<usize>, E>,
    ) -> Result<Option<usize>, SmbusReadIntoError<E>> {
        let result = f(&mut self.bytes)
            .map_err(SmbusReadIntoError::ReadError)
            .and_then(|len| {
                if len > Some(SmbusBlock::MAX_LEN) {
                    Err(SmbusReadIntoError::ReadTooLong)
                } else {
                    Ok(len)
                }
            });

        // Based on the result of the read, set the length field for this
        // `SmbusBlock`.
        self.len = result
            .as_ref()
            .unwrap_or(&None)
            .as_ref()
            // Casting this to a u8 unconditionally is okay since the
            // `and_then` closure above checks that it is less than MAX_LEN,
            // which is, of course, less than u8::MAX. :)
            .map(|&len| len as u8);

        // Zero any remaining bytes (or the whole buffer, if nothing was
        // read/the read failed).
        let start = self.len.unwrap_or(0) as usize;
        for byte in &mut self.bytes[start..] {
            *byte = 0;
        }

        result
    }

    /// Returns the response bytes, or `None` if the command is unsupported.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.len.map(|len| &self.bytes[..len as usize])
    }

    /// Returns the response length, or `None` if the command is unsupported.
    pub fn response_len(&self) -> Option<usize> {
        self.len.map(usize::from)
    }

    /// Returns `true` if the device does not support the command to read this
    /// register.
    pub fn is_unsupported(&self) -> bool {
        self.len.is_none()
    }
}

impl fmt::Display for SmbusBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(bytes) = self.as_bytes() else {
            return f.write_str("unsupported");
        };
        match core::str::from_utf8(bytes) {
            Ok(value) => f.write_str(value),
            Err(_) => write!(f, "{bytes:02x?}"),
        }
    }
}

impl<'de> Deserialize<'de> for SmbusBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireBlock {
            len: Option<u8>,
            bytes: [u8; SmbusBlock::MAX_LEN],
        }

        let WireBlock { len, bytes } = WireBlock::deserialize(deserializer)?;
        let nbytes = usize::from(len.unwrap_or(0));
        if nbytes > SmbusBlock::MAX_LEN {
            return Err(D::Error::invalid_length(
                nbytes,
                &"a PMBus block read of 32 bytes in length",
            ));
        }

        // Check if all padding bytes are zero
        if let Some(idx) = bytes[nbytes..].iter().position(|&byte| byte != 0) {
            let idx = nbytes + idx;
            return Err(D::Error::invalid_value(
                serde::de::Unexpected::Bytes(&bytes[idx..]),
                &"expected all padding bytes to be zero",
            ));
        }

        Ok(Self { len, bytes })
    }
}

/// Errors returned by [`SmbusBlock::read_into`].
///
/// Any of these errors being returned indicates that the [`SmbusBlock`] may
/// not have contained valid UTF-8 bytes after the read operation, and was
/// therefore zeroed in its entireity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmbusReadIntoError<E> {
    /// The read function returned an error (such as an I/O error).
    ReadError(E),
    /// The read function returned a length greater than
    /// [`SmbusBlock::MAX_LEN`]. It probably did not actually read that many
    /// bytes, since it was not given a sufficiently long buffer to read into.
    /// But, this almost certainly indicates that the read function is in some
    /// way broken.
    ReadTooLong,
}

/// VPD for a compute sled fan subassembly.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct FanAssemblyVpd {
    /// Identity of the fan assembly.
    pub identity: Barcode,
    /// Identity of the VPD board within the fan assembly.
    pub vpd_board_identity: Barcode,
    /// Identities of the individual fans.
    ///
    /// Depending on the time of manufacture, the fans may be identified by
    /// either an `0XV1`, `0XV2`, or `MPN1` barcode.
    pub fans: [Barcode; 3],
}

impl fmt::Display for FanAssemblyVpd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "fan tray    : {}", self.identity)?;
        writeln!(f, "  VPD board : {}", self.vpd_board_identity)?;
        for (i, fan) in self.fans.iter().enumerate() {
            writeln!(f, "  fan {i:<5} : {fan}")?;
        }
        Ok(())
    }
}

/// Identity of a TMP117 temperature sensor.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct Tmp117Identity {
    /// Device ID (register 0x0F)
    pub id: u16,
    /// 48-bit NIST traceability data
    pub eeprom1: u16,
    pub eeprom2: u16,
    pub eeprom3: u16,
}

impl fmt::Display for Tmp117Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "device ID : {:#06x}", self.id)?;
        writeln!(f, "  EEPROM1 : {:#06x}", self.eeprom1)?;
        writeln!(f, "  EEPROM2 : {:#06x}", self.eeprom2)?;
        writeln!(f, "  EEPROM3 : {:#06x}", self.eeprom3)
    }
}

static_assertions::const_assert!(Vpd::MAX_SIZE <= crate::MIN_TRAILING_DATA_LEN);

#[cfg(test)]
mod tests {
    use super::*;

    fn barcode(value: &str) -> Barcode {
        value.try_into().unwrap()
    }

    fn smbus_block(value: &[u8]) -> SmbusBlock {
        let mut block = SmbusBlock::UNSUPPORTED;
        block
            .read_into(|buffer| {
                buffer[..value.len()].copy_from_slice(value);
                Ok::<_, core::convert::Infallible>(Some(value.len()))
            })
            .unwrap();
        block
    }

    fn pmbus_vpd() -> PmbusVpd {
        PmbusVpd {
            // Unfortunately, "Crazy Eliza's Discount Pre-Owned Power
            // Electronics Warehouse, Everything Must Go, Priced To Sell" was
            // too many bytes to fit in one 32-byte SMBus block read.
            mfr_id: smbus_block(b"Eliza's Discount Power Supplies"),
            mfr_model: smbus_block(&[0x55; 32]),
            mfr_revision: SmbusBlock::UNSUPPORTED,
            mfr_location: smbus_block(b"\0Anytown,\0USA"),
            mfr_date: smbus_block(b"January 1st, 1970"),
            mfr_serial: smbus_block(&[1, 2, 3, 4]),
            ic_device_id: smbus_block(&[0xff, 0, 0x80]),
            ic_device_rev: SmbusBlock::UNSUPPORTED,
        }
    }

    fn serialize(value: &impl Serialize) -> Vec<u8> {
        let mut out = vec![0; Vpd::MAX_SIZE];
        let len = hubpack::serialize(&mut out, value).unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn borrowed_and_owned_encodings_match() {
        let oxide = barcode("0XV2:913-000000:003:BRM41210001");
        let mpn1 = barcode("MPN1:Joe's Stuff:Thingy 2000:revision:mpn1-serial");
        let values = [
            Vpd::Pmbus(pmbus_vpd()),
            Vpd::Barcode(oxide),
            Vpd::Barcode(mpn1),
            Vpd::FanAssembly(FanAssemblyVpd {
                identity: oxide,
                vpd_board_identity: oxide,
                fans: [
                    mpn1,
                    barcode("0XV2:913-00005:001:BRM41210002"),
                    barcode("0XV2:913-00005:002:BRM41210003"),
                ],
            }),
            Vpd::Tmp117(Tmp117Identity {
                id: 0x117,
                eeprom1: 1,
                eeprom2: 2,
                eeprom3: 3,
            }),
        ];

        for value in values {
            let owned = serialize(&value);
            let borrowed = serialize(&VpdRef::from(&value));
            assert_eq!(borrowed, owned);

            let (decoded, remainder) = hubpack::deserialize::<Vpd>(&borrowed)
                .expect("borrowed encoding must deserialize as owned VPD");
            assert!(remainder.is_empty());
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn smbus_blocks_preserve_presence_length_and_opaque_bytes() {
        let vpd = pmbus_vpd();
        assert_eq!(
            vpd.mfr_id.as_bytes().unwrap(),
            b"Eliza's Discount Power Supplies"
        );
        assert_eq!(vpd.mfr_model.as_bytes().unwrap(), &[0x55; 32]);
        assert!(vpd.mfr_revision.is_unsupported());
        assert_eq!(vpd.mfr_location.as_bytes().unwrap(), b"\0Anytown,\0USA");
        assert_eq!(vpd.mfr_date.as_bytes().unwrap(), b"January 1st, 1970");
        assert_eq!(vpd.mfr_serial.as_bytes().unwrap(), &[1, 2, 3, 4]);
        assert_eq!(vpd.ic_device_id.as_bytes().unwrap(), &[0xff, 0, 0x80]);
        assert!(vpd.ic_device_rev.is_unsupported());

        let mut empty = SmbusBlock::UNSUPPORTED;
        empty
            .read_into(|_| Ok::<_, core::convert::Infallible>(Some(0)))
            .unwrap();
        assert_eq!(empty.as_bytes(), Some(&[][..]));
        assert!(!empty.is_unsupported());
    }

    #[test]
    fn smbus_block_read_into_canonicalizes_the_result() {
        let mut block = smbus_block(&[0x55; SmbusBlock::MAX_LEN]);
        block
            .read_into(|buffer| {
                buffer[0] = 0xaa;
                Ok::<_, core::convert::Infallible>(Some(1))
            })
            .unwrap();
        assert_eq!(block.as_bytes(), Some(&[0xaa][..]));
        assert!(block.bytes[1..].iter().all(|&byte| byte == 0));

        block
            .read_into(|buffer| {
                buffer[0] = 0xff;
                Ok::<_, core::convert::Infallible>(None)
            })
            .unwrap();
        assert_eq!(block, SmbusBlock::UNSUPPORTED);
    }

    #[test]
    fn smbus_block_rejects_noncanonical_wire_padding() {
        let mut noncanonical = [0; SmbusBlock::MAX_LEN + 2];
        noncanonical[0] = 1;
        noncanonical[1] = 1;
        noncanonical[3] = 1;
        assert!(hubpack::deserialize::<SmbusBlock>(&noncanonical).is_err());
    }
}
