/// Implementation of base64 encode and decode.

const BASE64_CHARS: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

pub fn base64_encode(bytes: &[u8]) -> String {
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

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let idx_it = s
        .trim_end_matches('=')
        .chars()
        .map(|c| char_to_base64_index(c as u8).map(|x| x << 2));
    let idx_it2 = idx_it.clone().skip(1);
    let mut pairs_it = idx_it.zip(idx_it2);
    let mut counter = 0;
    let mut bytes = Vec::with_capacity(s.len() * 3 / 4);
    loop {
        let (b1, b2) = match pairs_it.next() {
            Some((Ok(b1), Ok(b2))) => (b1, b2),
            Some((Err(b1), _)) => return Err(b1),
            Some((_, Err(b2))) => return Err(b2),
            None => break,
        };
        let b = if counter % 3 == 0 {
            // 6 bits from first byte, 2 from second
            b1 | ((b2 & 0b11000000) >> 6)
        } else if counter % 3 == 1 {
            // 4 bits from first byte, 4 from second
            (b1 << 2) | ((b2 & 0b11110000) >> 4)
        } else {
            // 2 bits from first byte, 6 from second
            pairs_it.next(); // skip next as we've used all 6 bits.
            (b1 << 4) | ((b2 & 0b11111100) >> 2)
        };
        bytes.push(b);
        counter += 1;
    }
    return Ok(bytes);
}

fn char_to_base64_index(c: u8) -> Result<u8, String> {
    let c_val = c as u8;
    // Uppercase letters
    if 65 <= c_val && c_val <= 96 {
        return Ok(c_val - 65);
    }
    // Lowercase letters
    if 97 <= c_val && c_val <= 122 {
        return Ok(c_val - 97 + 26);
    }
    // Numbers
    if 48 <= c_val && c_val <= 57 {
        return Ok(c_val - 48 + 52);
    }
    // +
    if c_val == 43 {
        return Ok(62);
    }
    // /
    if c_val == 47 {
        return Ok(63);
    }
    Err(format!("unknown base64 char '{}'", c))
}

struct BitIter<'a> {
    bytes: &'a [u8],
    /// Current bit position in the entire byte stream
    bit_pos: usize,
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
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("QUJD", &"ABC".as_bytes())]
    #[case("QmFzZTY0", &[66, 97, 115, 101, 54, 52])]
    #[case("T2ggbXkgZ29zaA==", &[79, 104, 32, 109, 121, 32, 103, 111, 115, 104])]
    fn base64_decode_returns_expected_bytes(#[case] encoded: &str, #[case] expected: &[u8]) {
        let decoded = base64_decode(encoded).unwrap();

        assert_eq!(decoded, expected);
    }
}
