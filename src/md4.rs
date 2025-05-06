const BUFFER_SIZE: usize = 64;
const INITIALISATION_CONSTANTS: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
const MD4_SIZE: usize = 16;

pub struct Md4 {
    buffer: [u8; BUFFER_SIZE],
    buffer_len: usize,
    digest: [u32; 4],
    message_bit_len: u64,
}

impl Md4 {
    pub fn update(&mut self, message: &[u8]) {
        self.message_bit_len += message.len() as u64 * 8;

        // If buffer_len is not 0, then we're part way through a chunk. Get the
        // remainder of the chunk from the start of the message.
        let mut message_offset = 0;
        if self.buffer_len != 0 {
            let bytes_to_copy = (BUFFER_SIZE - self.buffer_len).min(message.len());
            self.buffer[self.buffer_len..(self.buffer_len + bytes_to_copy)]
                .copy_from_slice(&message[..bytes_to_copy]);
            self.buffer_len += bytes_to_copy;
            if BUFFER_SIZE == 64 {
                self.process_chunk();
            }
            message_offset = bytes_to_copy;
        }
        if message_offset >= message.len() {
            return;
        }

        // Loop over the chunks in the message and process full chunks.
        for chunk in message[message_offset..].chunks(BUFFER_SIZE) {
            self.buffer[..chunk.len()].copy_from_slice(chunk);
            self.buffer_len = chunk.len();
            if self.buffer_len == BUFFER_SIZE {
                self.process_chunk();
            }
        }
    }

    pub fn digest(mut self) -> [u8; MD4_SIZE] {
        self.md_pad();
        self.process_chunk();
        self.digest
            .map(|d| d.to_le_bytes())
            .concat()
            .try_into()
            .unwrap()
    }

    fn process_chunk(&mut self) {
        let x: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes(self.buffer[(4 * i)..(4 + 4 * i)].try_into().unwrap())
        });

        let mut d = self.digest;
        // Round 1
        let s = [3, 7, 11, 19];
        for r in 0..16 {
            let i = (16 - r) % 4;
            let k = r;
            d[i] = left_rotate(
                d[i].wrapping_add(f(d[(i + 1) % 4], d[(i + 2) % 4], d[(i + 3) % 4]))
                    .wrapping_add(x[k]),
                s[r % 4],
            );
        }

        // Round 2
        let s = [3, 5, 9, 13];
        for r in 0..16 {
            let i = (16 - r) % 4;
            let k = 4 * (r % 4) + r / 4;
            d[i] = left_rotate(
                d[i].wrapping_add(g(d[(i + 1) % 4], d[(i + 2) % 4], d[(i + 3) % 4]))
                    .wrapping_add(x[k])
                    .wrapping_add(0x5a827999),
                s[r % 4],
            );
        }

        // Round 3
        let s = [3, 9, 11, 15];
        let k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for r in 0..16 {
            let i = (16 - r) % 4;
            d[i] = left_rotate(
                d[i].wrapping_add(h(d[(i + 1) % 4], d[(i + 2) % 4], d[(i + 3) % 4]))
                    .wrapping_add(x[k[r]])
                    .wrapping_add(0x6ed9eba1),
                s[r % 4],
            );
        }

        for (state, increment) in self.digest.iter_mut().zip(d) {
            *state = increment.wrapping_add(*state);
        }
        self.buffer_len = 0;
    }

    fn md_pad(&mut self) {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If there's not enough space for the message bit length (8 bytes),
        // we'll need another (fully padded) buffer. Pad the rest of this
        // buffer and process it.
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0x00);
            self.process_chunk();
        }

        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&self.message_bit_len.to_le_bytes());
    }
}

impl Default for Md4 {
    fn default() -> Self {
        Self {
            buffer: [0u8; BUFFER_SIZE],
            buffer_len: 0,
            digest: INITIALISATION_CONSTANTS,
            message_bit_len: 0,
        }
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn left_rotate(i: u32, n: u32) -> u32 {
    (i << n) | (i >> (32 - n))
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::base64_decode;

    use rstest::rstest;

    #[rstest]
    #[case("", "MdbP4NFq6TG3PFnX4MCJwA==")]
    #[case("a", "veUssx3jPkYkXgX729b7JA==")]
    #[case("abc", "pEgBeq8h2FJfwQroeqZynQ==")]
    #[case("message digest", "2RMKgWRUn+gYh0gG4ccBSw==")]
    #[case("abcdefghijklmnopqrstuvwxyz", "154cMIqlu83uqO1j30EtqQ==")]
    #[case(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "BD+FgvJB2zUc5ifhU+fw5A"
    )]
    #[case(&"012345".repeat(127), "qPEhok3PQlbkSgG5T/A6nA==")]
    fn md4_generates_test_vector_hashes(#[case] input: &str, #[case] expected: &str) {
        let mut md4 = Md4::default();
        md4.update(&input.as_bytes());

        let expected_bytes = base64_decode(expected).unwrap();
        assert_eq!(md4.digest().to_vec(), expected_bytes);
    }
}
