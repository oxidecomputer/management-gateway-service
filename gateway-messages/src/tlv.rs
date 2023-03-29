// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Extremely simple / minimal implementation of tag/length/value encoding,
//! using 4-byte tags and lengths.

use core::fmt;
use core::iter;
use core::mem;
use zerocopy::byteorder::LittleEndian;
use zerocopy::byteorder::U32;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError<E> {
    /// The output buffer is too small to contain a tag/length header.
    BufferTooSmall,
    /// Custom error, defined and provided by the caller.
    Custom(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is too small to contain a tag/length header.
    BufferTooSmall,
    /// The `length` field requires more data than is remaining in the buffer.
    LengthTooLong,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DecodeError::BufferTooSmall => "buffer too small",
            DecodeError::LengthTooLong => "length too long",
        };
        write!(f, "{}", s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsBytes, FromBytes)]
#[repr(C)]
pub struct Tag(pub [u8; 4]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsBytes, FromBytes)]
#[repr(C)]
struct Header {
    tag: Tag,
    length: U32<LittleEndian>,
}

/// Length of a TLV triple for a value of the given length.
pub const fn tlv_len(value_len: usize) -> usize {
    value_len + mem::size_of::<Header>()
}

/// Encode a tag/length/value into `out`, returning the number of bytes of `out`
/// used to encode the triple.
///
/// The value is generated directly into the output buffer via the `value`
/// closure, which should return the length of the value it produced.
///
/// # Panics
///
/// If `value` returns a length greater than the buffer given to it, or if it
/// returns a length that doesn't fit in a `u32`.
pub fn encode<F, E>(
    out: &mut [u8],
    tag: Tag,
    value: F,
) -> Result<usize, EncodeError<E>>
where
    F: FnOnce(&mut [u8]) -> Result<usize, E>,
{
    // Ensure we have space for our tag+length header.
    if out.len() < mem::size_of::<Header>() {
        return Err(EncodeError::BufferTooSmall);
    }

    let (header_buf, out) = out.split_at_mut(mem::size_of::<Header>());

    // Generate the `value` directly into the buffer.
    let value_len = value(out).map_err(EncodeError::Custom)?;

    // `value` should never claim to have used more data than exists in `out`.
    assert!(value_len <= out.len());

    // Convert to u32 or die trying.
    let length = u32::try_from(value_len).unwrap();

    // Now that we know our length, go back and fill in the header.
    let header = Header { tag, length: length.into() };
    header_buf.copy_from_slice(header.as_bytes());

    Ok(mem::size_of::<Header>() + value_len)
}

/// Decode a tag/length/value triple from the front of `buf`. On success,
/// returns `(Tag, value, rest_of_buf)`.
pub fn decode(buf: &[u8]) -> Result<(Tag, &[u8], &[u8]), DecodeError> {
    // Peel header off the front.
    let header =
        Header::read_from_prefix(buf).ok_or(DecodeError::BufferTooSmall)?;
    let buf = &buf[mem::size_of::<Header>()..];

    // Split remaining buffer at the end of our value.
    let length = header.length.get() as usize;
    if length <= buf.len() {
        let (value, buf) = buf.split_at(length);
        Ok((header.tag, value, buf))
    } else {
        Err(DecodeError::LengthTooLong)
    }
}

/// Given a `buf` that contains multiple TLV triples packed back-to-back,
/// returns an iterator that produces each tag/value in turn.
///
/// Do not pass a buffer than contains trailing non-TLV data, especially all
/// zeroes! Eight bytes of zeroes is a valid TLV triple (with a tag of 0 and a
/// length of 0), so a buffer that starts with meaningful TLV trips and is
/// padded with trailing zeroes could produce many empty tag/value pairs after
/// the meaningful ones are decoded.
pub fn decode_iter(
    mut buf: &[u8],
) -> impl Iterator<Item = Result<(Tag, &[u8]), DecodeError>> + '_ {
    iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }

        match decode(buf) {
            Ok((tag, value, rest)) => {
                buf = rest;
                Some(Ok((tag, value)))
            }
            Err(err) => {
                buf = &[]; // fuse so we return `None` on subsequent calls
                Some(Err(err))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    #[test]
    fn round_trip() {
        const BUF_LEN: usize = 1024;
        const TAG: Tag = Tag(*b"aaaa");

        let mut buf = vec![0; BUF_LEN];
        let value = b"hello world";

        let n = encode(&mut buf, TAG, |out| {
            assert_eq!(out.len(), BUF_LEN - tlv_len(0));
            out[..value.len()].copy_from_slice(value);
            Ok::<_, Infallible>(value.len())
        })
        .unwrap();

        assert_eq!(n, tlv_len(value.len()));

        // Give decode just the encoded triple.
        let (tag, decoded_value, rest) = decode(&buf[..n]).unwrap();
        assert_eq!(tag, TAG);
        assert_eq!(decoded_value, value);
        assert_eq!(rest, &[] as &[u8]);

        // Give decode the full buffer.
        let (tag, decoded_value, rest) = decode(&buf).unwrap();
        assert_eq!(tag, TAG);
        assert_eq!(decoded_value, value);
        assert_eq!(rest.len(), BUF_LEN - n);
    }

    #[test]
    fn encode_errors() {
        // Buffer too small for header.
        let mut buf = [0; tlv_len(0) - 1];
        let err =
            encode(&mut buf, Tag(*b"aaaa"), |_| panic!("should not be called"))
                .unwrap_err();
        assert_eq!(err, EncodeError::<Infallible>::BufferTooSmall);

        // Value closure returns an error.
        let mut buf = [0; tlv_len(0)];
        let err = encode(&mut buf, Tag(*b"aaaa"), |_| Err(12345)).unwrap_err();
        assert_eq!(err, EncodeError::<i32>::Custom(12345));
    }

    #[test]
    #[should_panic = "assertion failed"]
    fn encode_lying_value_closure() {
        // Value claims to use 10 bytes, but 0 were available.
        let mut buf = [0; tlv_len(0)];
        let _ = encode::<_, Infallible>(&mut buf, Tag(*b"aaaa"), |_| Ok(10));
    }

    #[test]
    fn decode_errors() {
        // Buffer too small for header.
        let buf = [0; tlv_len(0) - 1];
        let err = decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::BufferTooSmall);

        // Header's length is too large for the buffer.
        let header = Header { tag: Tag(*b"aaaa"), length: 1.into() };
        let err = decode(header.as_bytes()).unwrap_err();
        assert_eq!(err, DecodeError::LengthTooLong);
    }

    #[test]
    fn decode_iterator() {
        let mut buf = vec![0; 1024];
        let tag_values = vec![
            (Tag(*b"aaaa"), b"hello " as &[u8]),
            (Tag(*b"bbbb"), b"world"),
            (Tag(*b"cccc"), b"a longer value"),
        ];

        let mut n = 0;
        for (tag, value) in &tag_values {
            n += encode::<_, Infallible>(&mut buf[n..], *tag, |buf| {
                buf[..value.len()].copy_from_slice(value);
                Ok(value.len())
            })
            .unwrap();
        }

        assert_eq!(
            n,
            tag_values
                .iter()
                .map(|(_tag, value)| tlv_len(value.len()))
                .sum::<usize>()
        );

        let decoded =
            decode_iter(&buf[..n]).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(decoded, tag_values);
    }
}
