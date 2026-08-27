// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

mod mgs_to_sp;
pub mod sp_impl;
mod sp_to_mgs;
pub mod tlv;

use core::fmt;
use core::str;
use core::time::Duration;
use serde::Deserialize;
use serde::Serialize;
use static_assertions::const_assert;

pub use hubpack::error::Error as HubpackError;
pub use hubpack::{SerializedSize, deserialize, serialize};

// Re-export all public types in our submodules for messages in either
// direction.
pub use mgs_to_sp::*;
pub use sp_to_mgs::*;

// This is now used for more than just ereports
pub use gateway_ereport_messages::RestartId;

/// The SP should detach an attached serial console client if it has not heard
/// from it in this long (based on the assumption that it has gone away without
/// sending an explicit detach).
///
/// Clients should send data or keepalive packets more frequently than this
/// timeout to avoid being detached.
pub const SERIAL_CONSOLE_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum size in bytes for a serialized message.
pub const MAX_SERIALIZED_SIZE: usize = 1024;

/// Size for a memory page in the Root of Trust (LPC55)
pub const ROT_PAGE_SIZE: usize = 512;

/// Size for a host flash page
pub const HF_PAGE_SIZE: usize = 256;

/// Module specifying the minimum and current version of the MGS protocol.
///
/// Our primary mechanism for serializing requests and responses is enums
/// encoded via hubpack. It is easy to extend these enums by adding new
/// variants, but changing, reordering, or removing existing variants is
/// (usually) a breaking change.
///
/// Our plan for versioning this protocol is simple: for as long as we can,
/// leave `version::MIN` unchanged, and do not change, reorder, or remove
/// existing variants. When we add new variants, increase `CURRENT`. Both the SP
/// and MGS will attempt to deserialize any message with a version that is at
/// least `MIN`. If the deserialization fails and the message version is higher
/// than `CURRENT`, we note a version mismatch error (with the expectation that
/// the failure is due to a new message type we don't understand): the SP will
/// response with a version mismatch error, and MGS will log it / return an
/// error to its caller. (If deserialization fails despite the message version
/// being in the range `MIN..=CURRENT`, we fail with a general deserialization
/// error.)
///
/// As a part of this plan, we have tests that cover the expected serialized
/// form of all messages for versions `MIN..=CURRENT`. These should catch any
/// accidental changes that would break backwards compatibility.
///
/// This is lifted from the versioning strategy taken by the transceivers
/// protocol; see https://github.com/oxidecomputer/transceiver-control/pull/66
/// for more detail and discussion.
pub mod version {
    pub const MIN: u32 = 2;
    pub const CURRENT: u32 = 29;

    /// MGS protocol version in which SP watchdog messages were added
    pub const WATCHDOG_VERSION: u32 = 12;
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub struct Header {
    /// Protocol version.
    pub version: u32,
    /// Arbitrary message id; responses should set this to match their
    /// corresponding request.
    pub message_id: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub struct Message {
    pub header: Header,
    pub kind: MessageKind,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Serialize,
    Deserialize,
    SerializedSize,
    strum_macros::VariantNames,
)]
#[strum(serialize_all = "snake_case")]
pub enum MessageKind {
    MgsRequest(MgsRequest),
    MgsResponse(MgsResponse),
    SpRequest(SpRequest),
    SpResponse(SpResponse),
}

/// See RFD 81.
///
/// This enum only lists power states the SP is able to control; higher power
/// states are controlled by ignition.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum PowerState {
    A0,
    A1,
    A2,
}

/// The reason for the power state's most recent change.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum StateChangeReason {
    /// No reason was provided.
    ///
    /// This indicates a legacy caller of `Sequencer.set_state`, rather than
    /// `Sequencer.set_state_with_reason`. All Hubris-internal callers should
    /// use `set_state_with_reason`, so this variant generally indicates that
    /// the `Sequencer.set_state` IPC is being called via Hiffy.
    Other,
    /// The system has just received power, so the sequencer has booted the
    /// host CPU.
    InitialPowerOn,
    /// A power state change was requested by the control plane.
    ControlPlane,
    /// The host CPU reset while in A0, so the system has powered off to clear
    /// hidden core state.
    CpuReset,
    /// The host OS failed to boot, so the system has powered off.
    HostBootFailure,
    /// The host OS panicked.
    HostPanic,
    /// The host OS requested that the system power off without rebooting.
    HostPowerOff,
    /// The host OS requested that the system reboot.
    HostReboot,
    /// The system powered off because a component has overheated.
    Overheat,
    /// A0 MAPO fault from the sequencer
    A0Mapo,
    /// System Management Error
    SmerrAssert,
    /// NIC MAPO fault from the sequencer.
    NicMapo,
    /// The system powered off for reasons we can't explain
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct PowerStateWithReason {
    pub state: PowerState,
    pub reason: StateChangeReason,
    /// The Hubris tick at which the device transitioned to this state.
    pub since: u64,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum BadRequestReason {
    /// The [`Request::version`] field did not match what we expected.
    WrongVersion { sp: u32, request: u32 },
    /// The message is the wrong direction (e.g., the SP received an `SpToMgs`
    /// message).
    WrongDirection,
    /// The message had unexpected trailing data.
    UnexpectedTrailingData,
    /// The message failed to deserialize.
    DeserializationError,
}

/// Image slot name for SwitchDefaultImage on component ROT
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotSlotId {
    A,
    B,
}

/// Duration for SwitchDefaultImage
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SwitchDuration {
    Once,
    Forever,
}

/// Sensor readings that we could request from the target by `SensorId`
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SensorRequestKind {
    /// Requests the most recent reading, which is either a value or error
    LastReading,
    /// Requests the most recent data value
    LastData,
    /// Requests the most recent error value
    LastError,
    /// Requests the error count for a given sensor
    ErrorCount,
}

/// Sensor readings that we could request from the target by `SensorId`
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SensorRequest {
    pub kind: SensorRequestKind,
    pub id: u32,
}

/// Most recent sensor reading, which may be a reading or a value
#[derive(
    Debug, Clone, Copy, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub struct SensorReading {
    pub value: Result<f32, SensorDataMissing>,
    pub timestamp: u64,
}

/// Response to a [`SensorRequest`]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
    strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum SensorResponse {
    LastReading(SensorReading),
    LastData { value: f32, timestamp: u64 },
    LastError { value: SensorDataMissing, timestamp: u64 },
    ErrorCount(u32),
}

/// Response to an [`RotRequest`]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
    strum_macros::IntoStaticStr,
)]
pub enum RotResponse {
    Ok,
}

/// An error or issue that led to sensor data not being available
///
/// Equivalent to `NoData` in Hubris.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SensorDataMissing {
    DeviceOff,
    DeviceError,
    DeviceNotPresent,
    DeviceUnavailable,
    DeviceTimeout,
}

/// Request to the CMPA
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotRequest {
    ReadCmpa,
    ReadCfpa(CfpaPage),
}

/// Specific CFPA page
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum CfpaPage {
    /// Currently active page
    Active,
    /// Currently inactive page
    Inactive,
    /// Page that may become active upon reset
    Scratch,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct UpdateId(pub [u8; 16]);

impl From<uuid::Uuid> for UpdateId {
    fn from(id: uuid::Uuid) -> Self {
        Self(id.into_bytes())
    }
}

impl From<UpdateId> for uuid::Uuid {
    fn from(id: UpdateId) -> Self {
        Self::from_bytes(id.0)
    }
}

mod nullstr {
    use super::*;

    /// A reusable type that implements a fixed-max-capacity string where the
    /// unused capacity is always guaranteed to be zero-filled. This is used
    /// for strings sent over the wire using [`hubpack`], which requires fixed
    /// size items.
    ///
    /// This type does NOT guarantee that the contents are null-*terminated*,
    /// only null-*padded*. If the contained string is exactly the length of the
    /// container, there will be no null bytes present.
    ///
    /// It is not intended for this type to be part of the public API, see
    /// [`SpComponent`] for usage guidance.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, SerializedSize)]
    pub struct NullStr<const N: usize> {
        contents: [u8; N],
    }

    impl<const N: usize> NullStr<N> {
        /// Create a [`NullStr`] from the given slice.
        ///
        /// This function has some Interesting Details:
        ///
        /// 1. If `src` exceeds the length of `N`, only the first `N` bytes will
        ///    be copied in
        /// 2. If `src` contains null bytes, these will be copied in
        ///
        /// You might ask yourself, why isn't this unsafe? Why doesn't it
        /// violate any invariants? Well, we implement `Deserialize`, which
        /// means we might obtain garbage off the wire anyway! So, morally, this
        /// is not particularly worse to support.
        ///
        /// This is *primarily* intended to be done when re-magicking from a
        /// code-generated string.
        pub fn from_bstr_unchecked(src: &[u8]) -> Self {
            let mut buf = [0u8; N];
            buf.iter_mut().zip(src.iter()).for_each(|(w, r)| *w = *r);
            Self { contents: buf }
        }

        /// Interpret the content as a UTF-8 string.
        ///
        /// Our current expectation of contents is that this should never
        /// fail (i.e., we're always storing contents as UTF-8 strings), but
        /// because we reconstitute components from network messages we still
        /// need to check.
        pub fn as_str(&self) -> Option<&str> {
            str::from_utf8(self.as_bstr()).ok()
        }

        /// Get the raw "binary string" version of the nullstr, e.g. the
        /// contents prior to the first null byte, or the entire string if no
        /// null bytes are present.
        ///
        /// This is guaranteed to never contain a `0`.
        pub fn as_bstr(&self) -> &[u8] {
            // `next()` can only be "None" if `N == 0`. Otherwise, split will
            // always yield at least item.
            self.contents.split(|x| *x == 0).next().unwrap_or(&[])
        }

        /// Const function to create a zero-padded [`NullStr`] from a given
        /// [`str`].
        ///
        /// Panics if `src` exceeds the capacity of `N`. This should generally
        /// only be used in const context where panics become compilation
        /// errors.
        pub const fn from_const(src: &str) -> Self {
            let mut buf = [0u8; N];
            assert!(src.len() <= N);
            let mut idx = 0;
            while idx < src.len() {
                buf[idx] = src.as_bytes()[idx];
                idx += 1;
            }

            Self { contents: buf }
        }

        /// Interpret the contents as a UTF-8 string in a `const` context,
        /// panicking if the string is not valid.
        ///
        /// This function should only be used in const contexts when the caller
        /// knows the contents is valid (e.g., one of this type's associated
        /// constants); for contents names parsed or constructed at runtime,
        /// prefer [`SpComponent::as_str()`] which performs runtime validation.
        pub const fn const_as_str(&self) -> &str {
            // const-equivalent of
            // ```
            // let n =
            //    self.contents.iter().position(|&c| c == 0)
            //      .unwrap_or(Self::MAX_ID_LENGTH);
            // ```
            let mut n = 0;
            while n < self.contents.len() {
                if self.contents[n] == 0 {
                    break;
                }
                n += 1;
            }

            // const-equivalent of `let s = &self.contents[..n]`.
            //
            // SAFETY: We really want to say `&self.contents[..n]` here, but
            // we're not allowed to use the indexing operator inside a
            // `const fn`. We know from the loop above that
            // `n <= self.contents.len()`, turning the following into a manual
            // `&self.contents[..n]` without a bounds check.
            let s = unsafe {
                core::slice::from_raw_parts(self.contents.as_ptr(), n)
            };

            // const-equivalent of `str::from_utf8(s).unwrap_lite()`.
            match str::from_utf8(s) {
                Ok(s) => s,
                Err(_) => panic!("invalid NullStr (not a utf8 string)"),
            }
        }

        /// Obtain a view of the internal null-padded array of bytes.
        pub fn contents(&self) -> &[u8; N] {
            &self.contents
        }
    }

    impl<const N: usize> Serialize for NullStr<N> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            // NOTE: We are implicitly performing an action here similar to
            // `serde(transparent)`, serializing the inner field directly rather
            // than as a struct field. This is aesthetically pleasing for JSON,
            // and not impactful for `hubpack`.
            //
            // If we're serializing to a human-readable form (e.g.,
            // `faux-mgs --json output`), serialize ourself as a string....
            if serializer.is_human_readable()
                && let Some(s) = self.as_str()
            {
                return serializer.serialize_str(s);
            }

            // ... otherwise, serialize our id array directly, which matches
            // what hubpack expects from serde's derived impl.
            //
            // NOTE: We use `serde_big_array` as we are const-generic over the
            // length, and serde's implementation is *not* generic, and only
            // provides manual impls up to N=32.
            <[u8; N] as serde_big_array::BigArray<'static, u8>>::serialize(
                &self.contents,
                serializer,
            )
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for NullStr<N> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Visitor;
            // NOTE: We are implicitly performing an action here similar to
            // `serde(transparent)`, deserializing the inner field directly
            // rather than as a struct field. This is aesthetically pleasing for
            // JSON, and not impactful for `hubpack`.
            //
            // Inverse of our serialize method: if we're deserializing from a
            // human-readable form, deserialize a string...
            if deserializer.is_human_readable() {
                struct StrVisitor<const N: usize>;
                impl<const N: usize> Visitor<'_> for StrVisitor<N> {
                    type Value = NullStr<N>;

                    fn expecting(
                        &self,
                        formatter: &mut fmt::Formatter,
                    ) -> fmt::Result {
                        write!(formatter, "a string of at most {} bytes", N)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        NullStr::try_from(v).map_err(|NullStrTooLong| {
                            E::invalid_length(
                                v.len(),
                                &"contents within capacity",
                            )
                        })
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            } else {
                // ... otherwise, deserialize an array just like the derived
                // serde impl would do.
                //
                // NOTE: We use `serde_big_array` as we are const-generic over
                // the length, and serde's implementation is *not* generic, and
                // only provides manual impls up to N=32.
                let contents = <[u8; N] as serde_big_array::BigArray<
                    'de,
                    u8,
                >>::deserialize(deserializer)?;
                Ok(Self { contents })
            }
        }
    }

    /// Error type returned from `TryFrom<&str> for SpComponent` if the provided
    /// ID is too long.
    #[derive(Debug)]
    pub struct NullStrTooLong;

    impl<const N: usize> TryFrom<&str> for NullStr<N> {
        type Error = NullStrTooLong;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            if value.len() > N {
                return Err(NullStrTooLong);
            }

            let mut me = Self { contents: [0; N] };

            // should we sanity check that `value` doesn't contain any nul
            // bytes? seems like overkill; probably fine to omit
            me.contents[..value.len()].copy_from_slice(value.as_bytes());

            Ok(me)
        }
    }

    impl<const N: usize> fmt::Debug for NullStr<N> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(s) = self.as_str() {
                s.fmt(f)
            } else {
                write!(f, "{:02x?}", self.contents)
            }
        }
    }

    impl<const N: usize> core::fmt::Display for NullStr<N> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            if let Some(s) = self.as_str() {
                f.write_str(s)
            } else {
                write!(f, "{:02x?}", self.contents)
            }
        }
    }
}

/// Identifier for a single component managed by an SP.
//
// NOTE: `serde(transparent)` is used to provide a "flattening" here. This
// is aesthetically intentional for JSON, and not impactful for non self
// describing formats like hubpack.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct SpComponent {
    /// The ID of the component.
    ///
    /// TODO This may need some thought. Currently we expect this to contain
    /// up to `MAX_ID_LENGTH` nonzero utf8 bytes followed by nul bytes as
    /// padding.
    ///
    /// An `SpComponent` can be created via its `TryFrom<&str>` implementation,
    /// which appends the appropriate padding.
    id: nullstr::NullStr<{ Self::MAX_ID_LENGTH }>,
}

impl core::fmt::Display for SpComponent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.id.fmt(f)
    }
}

impl SpComponent {
    /// Maximum number of bytes for a component ID.
    ///
    /// Note: Some methods like `Self::from_const` will panic if the given
    /// string exceeds this length.
    pub const MAX_ID_LENGTH: usize = 16;

    /// The SP itself.
    pub const SP_ITSELF: Self = Self::from_const("sp");

    /// The SP's auxiliary flash.
    pub const SP_AUX_FLASH: Self = Self::from_const("sp-aux-flash");

    /// The `sp3` host CPU.
    pub const SP3_HOST_CPU: Self = Self::from_const("sp3-host-cpu");

    /// The `sp5` host CPU.
    pub const SP5_HOST_CPU: Self = Self::from_const("sp5-host-cpu");

    /// The FPGA's buffer of POST codes emitted by the SP5 CPU
    ///
    /// This is deliberately a separate component from [`SP5_HOST_CPU`] because
    /// it contains a dynamic (and large) number of component details, based
    /// on how many POST codes have been recorded by the FPGA.
    ///
    /// For example, if the FPGA's buffer is empty, this reports 0 component
    /// details; if the FPGA has seen 1K POST codes, then this component has 1K
    /// component details and reports them in the order they were recorded.
    pub const SP5_POST_CODES: Self = Self::from_const("sp5-post-codes");

    /// The host CPU boot flash.
    pub const HOST_CPU_BOOT_FLASH: Self = Self::from_const("host-boot-flash");

    /// The AMD PSP Output Blob for the host
    pub const HOST_CPU_BOOT_APOB: Self = Self::from_const("host-boot-apob");

    /// The sidecar management network switch.
    pub const MONORAIL: Self = Self::from_const("monorail");

    /// The Tofino on a sidecar SP
    pub const TOFINO: Self = Self::from_const("tofino");

    // The RoT attached to the SP via SPI
    pub const ROT: Self = Self::from_const("rot");

    // The Stage0 bootloader for the RoT attached to the SP via SPI
    pub const STAGE0: Self = Self::from_const("stage0");

    /// Thermal control loop
    pub const FAN_CTRL: Self = Self::from_const("fan-ctrl");

    /// Prefix for devices that are identified generically by index (e.g.,
    /// `dev-17`).
    pub const GENERIC_DEVICE_PREFIX: &'static str = "dev-";

    /// System attention LED (of which there is one per system)
    pub const SYSTEM_LED: Self = Self::from_const("system-led");

    /// Get the raw "binary string" version of the component name, e.g. the
    /// contents prior to the first null byte, or the entire string if no null
    /// bytes are present.
    ///
    /// This is guaranteed to never contain a `0`.
    #[inline]
    pub fn as_bstr(&self) -> &[u8] {
        self.id.as_bstr()
    }

    /// Interpret the component name as a UTF-8 string.
    ///
    /// Our current expectation of component names is that this should never
    /// fail (i.e., we're always storing component names as valid UTF-8
    /// strings), but because we reconstitute components from network messages
    /// we still need to check.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        self.id.as_str()
    }

    /// Interpret the component name as a UTF-8 string in a `const`
    /// context, panicking if the string is not valid.
    ///
    /// This function should only be used in const contexts when the caller
    /// knows the component is valid (e.g., one of this type's associated
    /// constants); for component names parsed or constructed at runtime, prefer
    /// [`SpComponent::as_str()`] which performs runtime validation.
    #[inline]
    pub const fn const_as_str(&self) -> &str {
        self.id.const_as_str()
    }

    /// Create an [`SpComponent`] from the given slice.
    ///
    /// This function has some Interesting Details:
    ///
    /// 1. If `src` exceeds the length of `N`, only the first `N` bytes will be
    ///    copied in
    /// 2. If `src` contains null bytes, these will be copied in
    ///
    /// You might ask yourself, why isn't this unsafe? Why doesn't it violate
    /// any invariants? Well, we implement `Deserialize`, which means we might
    /// obtain garbage off the wire anyway! So, morally, this is not
    /// particularly worse to support.
    ///
    /// This is *primarily* intended to be done when re-magicking from a code
    /// generated string.
    #[inline]
    pub fn from_bstr_unchecked(src: &[u8]) -> Self {
        Self { id: nullstr::NullStr::from_bstr_unchecked(src) }
    }

    #[inline]
    pub const fn from_const(val: &str) -> Self {
        Self { id: nullstr::NullStr::from_const(val) }
    }

    #[inline]
    pub fn id(&self) -> &[u8; Self::MAX_ID_LENGTH] {
        self.id.contents()
    }
}

/// Error type returned from `TryFrom<&str> for SpComponent` if the provided ID
/// is too long.
#[derive(Debug)]
pub struct SpComponentIdTooLong;

impl From<nullstr::NullStrTooLong> for SpComponentIdTooLong {
    #[inline(always)]
    fn from(_value: nullstr::NullStrTooLong) -> Self {
        SpComponentIdTooLong
    }
}

impl TryFrom<&str> for SpComponent {
    type Error = SpComponentIdTooLong;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self { id: nullstr::NullStr::try_from(value)? })
    }
}

/// Identifier for a single power rail.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct PowerRailName {
    name: nullstr::NullStr<{ Self::MAX_NAME_LENGTH }>,
}

impl core::fmt::Display for PowerRailName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.name.fmt(f)
    }
}

impl PowerRailName {
    /// Maximum number of bytes for a Power Rail Name.
    ///
    /// Note: Some methods like `Self::from_const` will panic if the given
    /// string exceeds this length.
    pub const MAX_NAME_LENGTH: usize = 32;

    /// Interpret the power rail name as a UTF-8 string.
    ///
    /// Our current expectation of power rail names is that this should never
    /// fail (i.e., we're always storing power rail names as UTF-8
    /// strings), but because we reconstitute components from network messages
    /// we still need to check.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        self.name.as_str()
    }

    /// Get the raw "binary string" version of the rail name, e.g. the
    /// contents prior to the first null byte, or the entire string if no null
    /// bytes are present.
    ///
    /// This is guaranteed to never contain a `0`.
    #[inline]
    pub fn as_bstr(&self) -> &[u8] {
        self.name.as_bstr()
    }

    /// Interpret the power rail name as a UTF-8 string in a `const`
    /// context, panicking if the string is not valid UTF-8.
    ///
    /// This function should only be used in const contexts when the caller
    /// knows the component is valid (e.g., one of this type's associated
    /// constants); for component names parsed or constructed at runtime, prefer
    /// [`PowerRailName::as_str()`] which performs runtime validation.
    #[inline]
    pub const fn const_as_str(&self) -> &str {
        self.name.const_as_str()
    }

    /// Create an [`PowerRailName`] from the given slice.
    ///
    /// This function has some Interesting Details:
    ///
    /// 1. If `src` exceeds the length of `N`, only the first `N` bytes will be
    ///    copied in
    /// 2. If `src` contains null bytes, these will be copied in
    ///
    /// You might ask yourself, why isn't this unsafe? Why doesn't it violate
    /// any invariants? Well, we implement `Deserialize`, which means we might
    /// obtain garbage off the wire anyway! So, morally, this is not
    /// particularly worse to support.
    ///
    /// This is *primarily* intended to be done when re-magicking from a code
    /// generated string.
    #[inline]
    pub fn from_bstr_unchecked(src: &[u8]) -> Self {
        Self { name: nullstr::NullStr::from_bstr_unchecked(src) }
    }

    #[inline]
    pub const fn from_const(val: &str) -> Self {
        Self { name: nullstr::NullStr::from_const(val) }
    }

    #[inline]
    pub fn name(&self) -> &[u8; Self::MAX_NAME_LENGTH] {
        self.name.contents()
    }
}

/// Error type returned from `TryFrom<&str> for PowerRailName` if the provided ID
/// is too long.
#[derive(Debug)]
pub struct PowerRailNameTooLong;

impl From<nullstr::NullStrTooLong> for PowerRailNameTooLong {
    #[inline(always)]
    fn from(_value: nullstr::NullStrTooLong) -> Self {
        PowerRailNameTooLong
    }
}

impl TryFrom<&str> for PowerRailName {
    type Error = PowerRailNameTooLong;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self { name: nullstr::NullStr::try_from(value)? })
    }
}

/// Minimum guaranteed space for trailing data in a single packet.
///
/// Depending on the [`Message`] payload, there may be more space for trailing
/// data than indicated by this constant; this specifies the minimum amount
/// available regardless of the request type.
pub const MIN_TRAILING_DATA_LEN: usize =
    MAX_SERIALIZED_SIZE - Message::MAX_SIZE;

// A serialized `Message` can be followed by binary data; we want the majority
// of our packet to be available for that data. Statically check that our
// serialized message headers haven't gotten too large. The specific value here
// is arbitrary; if this check starts failing, it's probably fine to reduce it
// some. The check is here to force us to think about it.
const_assert!(MIN_TRAILING_DATA_LEN > 700);

/// Returns `(serialized_size, data_bytes_written)` where `serialized_size` is
/// the message size written to `out` and `data_bytes_written` is the number of
/// bytes included in `out` from `data_slices`.
///
/// `data_slices` is provided as multiple slices to allow for data structures
/// like `heapless::Deque` (which presents its contents as two slices). If
/// multiple slices are present in `data_slices`, `data_bytes_written` will be
/// at most the sum of all their lengths. Bytes will be appended from the slices
/// in order.
pub fn serialize_with_trailing_data(
    out: &mut [u8; MAX_SERIALIZED_SIZE],
    message: &Message,
    data_slices: &[&[u8]],
) -> (usize, usize) {
    // We know statically (confirmed by the `const_assert` above) that a
    // serialized `Message` is significantly smaller than `MAX_SERIALIZED_SIZE`.
    // This call cannot fail for any reason other than an undersized buffer, so
    // we can unwrap here.
    let n = hubpack::serialize(out, message).unwrap();
    let mut out = &mut out[n..];

    let mut nwritten = 0;
    for &data in data_slices {
        // How much of this slice can we fit in `out`?
        let to_write = usize::min(out.len(), data.len());
        out[..to_write].copy_from_slice(&data[..to_write]);
        nwritten += to_write;
        out = &mut out[to_write..];
        if out.is_empty() {
            break;
        }
    }

    (n + nwritten, nwritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_with_trailing_data() {
        let mut out = [0; MAX_SERIALIZED_SIZE];
        let message = Message {
            header: Header { version: 1, message_id: 2 },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };
        let data_vecs = &[
            vec![0; 256],
            vec![1; 256],
            vec![2; 256],
            vec![3; 256],
            vec![4; 256],
            vec![5; 256],
        ];
        let data_slices =
            data_vecs.iter().map(|v| v.as_slice()).collect::<Vec<_>>();

        let (out_len, nwritten) =
            serialize_with_trailing_data(&mut out, &message, &data_slices);

        // We should have filled `out` entirely; `data_vecs` contains more data
        // than fits in `MAX_SERIALIZED_SIZE`.
        assert_eq!(out_len, MAX_SERIALIZED_SIZE);

        let (deserialized_message, remainder) =
            deserialize::<Message>(&out).unwrap();

        assert_eq!(message, deserialized_message);
        assert_eq!(remainder.len(), nwritten);

        for (i, chunk) in remainder.chunks(256).enumerate() {
            assert_eq!(chunk, &data_vecs[i][..chunk.len()]);
        }
    }

    #[test]
    fn test_human_readable_sp_component() {
        let component = SpComponent::SP_ITSELF;
        let expected_value = serde_json::Value::String("sp".to_string());

        assert_eq!(serde_json::to_value(component).unwrap(), expected_value);
        assert_eq!(
            serde_json::from_value::<SpComponent>(expected_value).unwrap(),
            component
        );
    }

    #[test]
    fn test_non_human_readable_sp_component() {
        let component = SpComponent::SP_ITSELF;
        let expected_value = component.id;

        let mut out = [0; SpComponent::MAX_SIZE];
        let n = hubpack::serialize(&mut out, &component).unwrap();
        assert_eq!(&out[..n], expected_value.contents());

        assert_eq!(
            hubpack::deserialize::<SpComponent>(expected_value.contents())
                .unwrap(),
            (component, &[] as &[u8])
        );
    }

    #[test]
    fn test_human_readable_power_rail() {
        let rail = const { PowerRailName::from_const("V0P96_NIC_VDD_A0HP") };
        let expected_value =
            serde_json::Value::String("V0P96_NIC_VDD_A0HP".to_string());

        assert_eq!(serde_json::to_value(rail).unwrap(), expected_value);
        assert_eq!(
            serde_json::from_value::<PowerRailName>(expected_value).unwrap(),
            rail
        );
    }

    #[test]
    fn test_non_human_readable_power_rail() {
        let rail = const { PowerRailName::from_const("V0P96_NIC_VDD_A0HP") };
        let expected_value = rail.name;

        let mut out = [0; PowerRailName::MAX_SIZE];
        let n = hubpack::serialize(&mut out, &rail).unwrap();
        assert_eq!(&out[..n], expected_value.contents());

        assert_eq!(
            hubpack::deserialize::<PowerRailName>(expected_value.contents())
                .unwrap(),
            (rail, &[] as &[u8])
        );
    }
}
