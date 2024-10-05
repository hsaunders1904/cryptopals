use std::fmt::format;

const BASE64_CHARS: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

pub fn hex_to_b64(hex: &str) -> Result<String, String> {
    let bytes = hex_to_bytes(hex)?;
    Ok(bytes_to_base64(&bytes))
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

        let current_byte = self.bytes[byte_idx];
        let byte_mask = 0b11111100 >> bit_offset;
        let masked_current_byte = current_byte & byte_mask;
        if bit_offset == 0 {
            return Some(masked_current_byte >> 2);
        } else if bit_offset == 2 {
            return Some(masked_current_byte);
        }
        let from_byte = masked_current_byte << (bit_offset - 2);

        // Work out contribution from next byte.
        if byte_idx + 1 < self.bytes.len() {
            let next_byte = self.bytes[byte_idx + 1];
            let n_bytes = bit_offset - 2;
            let mask = ((1 << n_bytes) - 1) << (8 - n_bytes);
            let from_next_byte = (next_byte & mask) >> (8 - n_bytes);
            return Some(from_byte | from_next_byte);
        }
        return Some(from_byte);
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for byte in bytes {
        s += &format!("{:08b}", byte);
    }
    s
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    let encode_len = (bytes.len()).div_ceil(3) * 4;
    let mut b64 = String::with_capacity(encode_len);
    for bit_idx in BitIter::new(bytes) {
        let c = BASE64_CHARS[bit_idx as usize] as char;
        b64.push(c);
    }
    b64
}

fn hex_item_to_byte(item: &[char]) -> Result<u8, String> {
    u8::from_str_radix(&item.iter().cloned().collect::<String>(), 16).map_err(|e| format!("{e}"))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let chars: Vec<char> = hex.chars().collect();
    chars.chunks(2).map(hex_item_to_byte).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn convert_hex_to_base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        assert_eq!(
            hex_to_b64(&hex).unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn byte_iter() {
        let bytes = [
            0b01001001, 0b00100111, 0b01101101, 0b00100000, 0b01101011, 0b01101001, 0b01101100,
        ];

        let split_bytes: Vec<u8> = BitIter::new(&bytes).collect();

        let expected_splits = [
            0b010010, 0b010010, 0b011101, 0b101101, 0b001000, 0b000110, 0b101101, 0b101001,
            0b011011, 0,
        ];

        bytes.iter().for_each(|x| print!("{:08b} ", x));
        println!("");
        split_bytes.iter().for_each(|x| print!("{:08b} ", x));
        println!("");
        expected_splits.iter().for_each(|x| print!("{:08b} ", x));
        println!("");
        assert_eq!(split_bytes, expected_splits);
    }

    #[test]
    fn test_hex_to_bytes_valid() {
        // Test with a valid hex string
        let hex = "0A3F";
        let expected: Vec<u8> = vec![0x0A, 0x3F];
        let result = hex_to_bytes(hex).unwrap();
        assert_eq!(result, expected);
    }
}
