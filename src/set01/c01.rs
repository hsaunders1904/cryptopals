// Base64 can be encoded by:
//
// 1. Concatenating all the bytes in the byte stream.
// 2. Chunking the bytes into 6 bits.
//     - If the last chunk is less than 6 bits pad the front with zeros.
// 3. Indexing into the base64 table using the 6 bit number.
//     - ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
// 4. Padding the returned string with '=' until the length is divisible by 4.
//     - Padding is not strictly necessary, but is useful when base64 encoded
//       strings are concatenated, to disambiguate the beginning of one string
//       and the end of another.
//
// For example, the bytes:
//
//     01110100 01100101 01110011 01110100
//
// Should be split like this:
//
//     011101 000110 010101 110011 011101 00
//
// Which, as a u8, is
//
//     00011101 00000110 00010101 00110011 00011101 00000000
//
//        29       6        21       51        29      0
//
// Using these as an index into the table, we get:
//
//     dGVzdA
//
// Then padding:
//
//     dGVzdA==
//

const BASE64_CHARS: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

pub fn hex_to_b64(hex: &str) -> Result<String, String> {
    let bytes = hex_to_bytes(hex)?;
    Ok(bytes_to_b64(&bytes))
}

pub fn bytes_to_b64(bytes: &[u8]) -> String {
    let encode_len = bytes.len().div_ceil(3) * 4;
    let mut b64 = String::with_capacity(encode_len);
    for bit_idx in BitIter::new(bytes) {
        b64.push(BASE64_CHARS[bit_idx as usize] as char);
    }
    for _ in 0..((bytes.len() * 2) % 3) {
        b64.push('=');
    }
    b64
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex.as_bytes()
        .chunks(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16))
        .collect::<Result<Vec<u8>, std::num::ParseIntError>>()
        .map_err(|e| format!("failed to convert hex to bytes: {e}"))
}

struct BitIter<'a> {
    bytes: &'a [u8],
    bit_pos: usize, // Current bit position in the entire byte stream
}
impl<'a> BitIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }
}
impl<'a> Iterator for BitIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let byte_idx = self.bit_pos / 8;
        let bit_offset = self.bit_pos % 8;
        if byte_idx >= self.bytes.len() {
            return None;
        }

        self.bit_pos += 6;

        // Work out contribution from the current byte.
        if bit_offset == 0 {
            return Some(self.bytes[byte_idx] >> 2);
        }
        let byte_mask = 0b11111100 >> bit_offset;
        let masked_current_byte = self.bytes[byte_idx] & byte_mask;
        let from_byte = masked_current_byte << (bit_offset - 2);

        // Work out contribution from next byte.
        if bit_offset > 2 && byte_idx + 1 < self.bytes.len() {
            let from_next_byte = self.bytes[byte_idx + 1] >> (10 - bit_offset);
            return Some(from_byte | from_next_byte);
        }
        return Some(from_byte);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case("74657374", "dGVzdA==")] // test
    #[case("7465737432", "dGVzdDI=")] // test2
    #[case(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )]
    fn convert_hex_to_base64(#[case] hex: &str, #[case] b64: &str) {
        assert_eq!(hex_to_b64(&hex).unwrap(), b64);
    }

    #[test]
    fn test_hex_to_bytes_valid() {
        let hex = "0A3F";
        let expected: Vec<u8> = vec![0x0A, 0x3F];
        let result = hex_to_bytes(hex).unwrap();
        assert_eq!(result, expected);
    }
}
