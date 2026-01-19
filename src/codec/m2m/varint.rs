//! VarInt encoding (LEB128) for compact integer representation.
//!
//! Variable-length encoding where small values use fewer bytes:
//! - 0-127: 1 byte
//! - 128-16383: 2 bytes
//! - 16384-2097151: 3 bytes
//! - etc.

#![allow(missing_docs)]

use crate::error::{M2MError, Result};
use std::io::{Read, Write};

/// Write a variable-length integer to a buffer
pub fn write_varint<W: Write>(writer: &mut W, mut value: u64) -> Result<usize> {
    let mut bytes_written = 0;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80; // Set continuation bit
        }
        writer
            .write_all(&[byte])
            .map_err(|e| M2MError::Compression(format!("VarInt write error: {}", e)))?;
        bytes_written += 1;
        if value == 0 {
            break;
        }
    }
    Ok(bytes_written)
}

/// Write a variable-length integer to a Vec<u8>
pub fn write_varint_vec(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read a variable-length integer from a reader
pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;

    loop {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|e| M2MError::Decompression(format!("VarInt read error: {}", e)))?;

        result |= ((byte[0] & 0x7F) as u64) << shift;

        if byte[0] & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(M2MError::Decompression("VarInt overflow".to_string()));
        }
    }

    Ok(result)
}

/// Read a variable-length integer from a byte slice, returning (value, bytes_consumed)
pub fn read_varint_slice(data: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return Err(M2MError::Decompression(
                "VarInt: unexpected end of data".to_string(),
            ));
        }

        let byte = data[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(M2MError::Decompression("VarInt overflow".to_string()));
        }
    }

    Ok((result, pos))
}

/// Calculate the number of bytes needed to encode a value as VarInt
pub fn varint_size(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = 64 - value.leading_zeros() as usize;
    (bits + 6) / 7 // Ceiling division by 7
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_varint_small() {
        let mut buf = Vec::new();
        write_varint_vec(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        write_varint_vec(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        write_varint_vec(&mut buf, 1);
        assert_eq!(buf, vec![1]);
    }

    #[test]
    fn test_varint_medium() {
        let mut buf = Vec::new();
        write_varint_vec(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint_vec(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [
            0,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            2097151,
            2097152,
            u64::MAX,
        ];

        for &value in &test_values {
            let mut buf = Vec::new();
            write_varint_vec(&mut buf, value);

            let mut cursor = Cursor::new(&buf);
            let decoded = read_varint(&mut cursor).unwrap();

            assert_eq!(value, decoded, "Roundtrip failed for value {}", value);
        }
    }

    #[test]
    fn test_varint_slice() {
        let mut buf = Vec::new();
        write_varint_vec(&mut buf, 12345);
        buf.extend_from_slice(b"extra data");

        let (value, consumed) = read_varint_slice(&buf).unwrap();
        assert_eq!(value, 12345);
        assert!(consumed < buf.len());
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(127), 1);
        assert_eq!(varint_size(128), 2);
        assert_eq!(varint_size(16383), 2);
        assert_eq!(varint_size(16384), 3);
    }
}
