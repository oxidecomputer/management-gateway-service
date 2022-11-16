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
use serde::Deserialize;
use serde::Serialize;
use static_assertions::const_assert;

pub use hubpack::error::Error as HubpackError;
pub use hubpack::{deserialize, serialize, SerializedSize};

// Re-export all public types in our submodules for messages in either
// direction.
pub use mgs_to_sp::*;
pub use sp_to_mgs::*;

/// Maximum size in bytes for a serialized message.
pub const MAX_SERIALIZED_SIZE: usize = 1024;

pub mod version {
    pub const V2: u32 = 2;
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
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub struct Message {
    pub header: Header,
    pub kind: MessageKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
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

/// Identifier for a single component managed by an SP.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, SerializedSize, Serialize, Deserialize,
)]
pub struct SpComponent {
    /// The ID of the component.
    ///
    /// TODO This may need some thought. Currently we expect this to contain
    /// up to `MAX_ID_LENGTH` nonzero utf8 bytes followed by nul bytes as
    /// padding.
    ///
    /// An `SpComponent` can be created via its `TryFrom<&str>` implementation,
    /// which appends the appropriate padding.
    pub id: [u8; Self::MAX_ID_LENGTH],
}

impl SpComponent {
    /// Maximum number of bytes for a component ID.
    pub const MAX_ID_LENGTH: usize = 16;

    /// The SP itself.
    pub const SP_ITSELF: Self = Self { id: *b"sp\0\0\0\0\0\0\0\0\0\0\0\0\0\0" };

    /// The SP's auxiliary flash.
    pub const SP_AUX_FLASH: Self = Self { id: *b"sp-aux-flash\0\0\0\0" };

    /// The `sp3` host CPU.
    pub const SP3_HOST_CPU: Self = Self { id: *b"sp3-host-cpu\0\0\0\0" };

    /// The host CPU boot flash.
    pub const HOST_CPU_BOOT_FLASH: Self = Self { id: *b"host-boot-flash\0" };

    /// The sidecar VSC7448 switch.
    pub const VSC7448: Self = Self { id: *b"vsc7448\0\0\0\0\0\0\0\0\0" };

    /// Prefix for devices that are identified generically by index (e.g.,
    /// `dev-17`).
    pub const GENERIC_DEVICE_PREFIX: &'static str = "dev-";

    /// Interpret the component name as a human-readable string.
    ///
    /// Our current expectation of component names is that this should never
    /// fail (i.e., we're always storing component names as human-readable
    /// strings), but because we reconstitute components from network messages
    /// we still need to check.
    pub fn as_str(&self) -> Option<&str> {
        let n =
            self.id.iter().position(|&c| c == 0).unwrap_or(Self::MAX_ID_LENGTH);
        str::from_utf8(&self.id[..n]).ok()
    }

    /// Interpret the component name as a human-readable string in a `const`
    /// context, panicking if the string is not human readable.
    ///
    /// This function should only be used in const contexts when the caller
    /// knows the component is valid (e.g., one of this type's associated
    /// constants); for component names parsed or constructed at runtime, prefer
    /// [`SpComponent::as_str()`] which performs runtime validation.
    pub const fn const_as_str(&self) -> &str {
        // const-equivalent of
        // ```
        // let n =
        //    self.id.iter().position(|&c| c == 0)
        //      .unwrap_or(Self::MAX_ID_LENGTH);
        // ```
        let mut n = 0;
        while n < self.id.len() {
            if self.id[n] == 0 {
                break;
            }
            n += 1;
        }

        // const-equivalent of `let s = &self.id[..n]`.
        //
        // SAFETY: We really want to say `&self.id[..n]` here, but we're not
        // allowed to use the indexing operator inside a `const fn`. We know
        // from the loop above that `n <= self.id.len()`, turning the following
        // into a manual `&self.id[..n]` without a bounds check.
        let s = unsafe { core::slice::from_raw_parts(self.id.as_ptr(), n) };

        // const-equivalent of `str::from_utf8(s).unwrap_lite()`.
        match str::from_utf8(s) {
            Ok(s) => s,
            Err(_) => panic!("invalid SpComponent ID (not a utf8 string)"),
        }
    }
}

impl fmt::Debug for SpComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("SpComponent");
        if let Some(s) = self.as_str() {
            debug.field("id", &s);
        } else {
            debug.field("id", &self.id);
        }
        debug.finish()
    }
}

/// Error type returned from `TryFrom<&str> for SpComponent` if the provided ID
/// is too long.
#[derive(Debug)]
pub struct SpComponentIdTooLong;

impl TryFrom<&str> for SpComponent {
    type Error = SpComponentIdTooLong;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > Self::MAX_ID_LENGTH {
            return Err(SpComponentIdTooLong);
        }

        let mut component = SpComponent { id: [0; Self::MAX_ID_LENGTH] };

        // should we sanity check that `value` doesn't contain any nul bytes?
        // seems like overkill; probably fine to omit
        component.id[..value.len()].copy_from_slice(value.as_bytes());

        Ok(component)
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
}
