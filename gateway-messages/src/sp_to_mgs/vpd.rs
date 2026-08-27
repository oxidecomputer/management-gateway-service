use crate::nullstr::NullStr;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum Vpd {
    Pmbus(PmbusIdentity),
    OxideBarcode(OxideIdentity),
    Mpn1Barcode(Mpn1Identity),
    FanAssembly(FanAssemblyIdentity),
    Tmp117(Tmp117Identity),
}

#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum Barcode {
    Oxide(OxideIdentity),
    Mpn1(Mpn1Identity),
}

/// An Oxide-assigned VPD identity.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct OxideIdentity {
    // Serial and revision are only 11 bytes in practice; we have plenty of room
    // so we'll leave the fields wider in case we grow it in the future. The
    // values are 0-padded.
    pub serial_number: NullStr<32>,
    pub model: NullStr<32>,
    pub revision: u32,
}

/// An MPN1 identity
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct Mpn1Identity {
    pub manufacturer: NullStr<32>,
    pub model: NullStr<32>,
    pub revision: NullStr<32>,
    pub serial_number: NullStr<32>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct PmbusIdentity {
    /// `MFR_ID` (PMBus operation 0x99)
    pub mfr_id: NullStr<PMBUS_BLOCK_LEN>,
    /// `MFR_MODEL` (PMBus operation 0x9A)
    pub mfr_model: NullStr<PMBUS_BLOCK_LEN>,
    /// `MFR_REVISION` (PMBus operation 0x9B)
    pub mfr_revision: NullStr<PMBUS_BLOCK_LEN>,
    /// `MFR_LOCATION` (PMBus operation 0x9C)
    pub mfr_location: NullStr<PMBUS_BLOCK_LEN>,
    /// `MFR_DATE` (PMBus operation 0x9D)
    pub mfr_date: NullStr<PMBUS_BLOCK_LEN>,
    /// `MFR_SERIAL` (PMBus operation 0x9E)
    pub mfr_serial: NullStr<PMBUS_BLOCK_LEN>,
    /// `IC_DEVICE_ID` (PMBus operation 0x9F)
    pub ic_device_id: NullStr<PMBUS_BLOCK_LEN>,
    /// `IC_DEVICE_REV` (PMBus operation 0xA0)
    pub ic_device_rev: NullStr<PMBUS_BLOCK_LEN>,
}

/// VPD for a compute sled fan subassembly.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct FanAssemblyIdentity {
    /// Identity of the fan assembly.
    pub identity: OxideIdentity,
    /// Identity of the VPD board within the fan assembly.
    pub vpd_board_identity: OxideIdentity,
    /// Identities of the individual fans.
    ///
    /// Depending on the time of manufacture, the fans may be identified by
    /// either an `0XV1` or `0XV2` barcode ([`OxideIdentity`]) or a `MPN1`
    /// barcode ([`Mpn1Identity`]).
    pub fans: [Barcode; 3],
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

const PMBUS_BLOCK_LEN: usize = 32;
