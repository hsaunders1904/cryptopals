const BUFFER_SIZE: usize = 64;
const INITIALISATION_CONSTANTS: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const SHA256_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Sha256 {
    buffer: [u8; BUFFER_SIZE],
    buffer_len: usize,
    digest: [u32; 8],
    message_bit_len: u64,
}

impl Sha256 {
    pub fn new_with_initialisation_constants(
        initialisation_constants: [u32; 8],
        message_bit_len: u64,
    ) -> Self {
        Self {
            buffer: [0u8; BUFFER_SIZE],
            buffer_len: 0,
            digest: initialisation_constants,
            message_bit_len,
        }
    }

    pub fn digest_message(message: &[u8]) -> [u8; SHA256_LEN] {
        let mut hasher = Sha256::default();
        hasher.update(message);
        hasher.digest()
    }

    pub fn digest(mut self) -> [u8; SHA256_LEN] {
        self.md_pad();
        self.digest
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn update(&mut self, message: &[u8]) {
        self.message_bit_len += (message.len() as u64) * 8;

        let mut offset = 0;
        if self.buffer_len > 0 {
            let needed = BUFFER_SIZE - self.buffer_len;
            let to_copy = needed.min(message.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&message[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == BUFFER_SIZE {
                self.process_chunk();
                self.buffer_len = 0;
            }
        }

        while offset + BUFFER_SIZE <= message.len() {
            self.buffer
                .copy_from_slice(&message[offset..offset + BUFFER_SIZE]);
            self.process_chunk();
            offset += BUFFER_SIZE;
        }

        if offset < message.len() {
            self.buffer[..message.len() - offset].copy_from_slice(&message[offset..]);
            self.buffer_len = message.len() - offset;
        }
    }

    pub fn update_and_digest(mut self, message: &[u8]) -> [u8; SHA256_LEN] {
        self.update(message);
        self.digest()
    }

    fn md_pad(&mut self) {
        let bit_len_bytes = self.message_bit_len.to_be_bytes();

        self.update(&[0x80]);

        // Pad with zeros until length is 56 mod 64
        let len_mod = self.buffer_len % BUFFER_SIZE;
        let padding_len = if len_mod <= 56 {
            56 - len_mod
        } else {
            64 + 56 - len_mod
        };
        self.update(&vec![0u8; padding_len]);
        self.update(&bit_len_bytes);
    }

    fn process_chunk(&mut self) {
        const K: [u32; 64] = [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
            0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
            0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
            0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
            0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
            0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
            0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
            0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
            0xC67178F2,
        ];

        let mut w = [0u32; 64];
        for (i, chunk) in self.buffer.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.digest;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        let state = [a, b, c, d, e, f, g, h];
        for (i, val) in state.iter().enumerate() {
            self.digest[i] = self.digest[i].wrapping_add(*val);
        }
        self.buffer_len = 0;
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new_with_initialisation_constants(INITIALISATION_CONSTANTS, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::base64_decode;

    use rstest::rstest;

    #[rstest]
    #[case("", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    #[case("abc", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")]
    #[case(
        "We all live in a yellow submarine.",
        "YIJExmRkEr9V0Q4jsQNKi+Bo7XhIpJNg/+ph2vkTyDI="
    )]
    #[case(&"012345".repeat(127), "ZeVat0eeGoWR07JInXRX5gYwrIJXK3m86PBbMku0RBw=")]
    fn digest_returns_expected_hash(#[case] input: &str, #[case] expected: &str) {
        let mut hasher = Sha256::default();
        hasher.update(&input.as_bytes());
        let digest = hasher.digest();

        let expected_bytes = base64_decode(expected).unwrap();
        assert_eq!(digest.as_slice(), expected_bytes.as_slice());
    }
}
