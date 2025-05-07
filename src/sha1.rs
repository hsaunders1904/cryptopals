const BUFFER_SIZE: usize = 64;
const INITIALISATION_CONSTANTS: [u32; 5] =
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const SHA1_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct Sha1 {
    buffer: [u8; BUFFER_SIZE],
    buffer_len: usize,
    digest: [u32; 5],
    message_bit_len: u64,
}

impl Sha1 {
    pub fn new_with_initialisation_constants(
        initialisation_constants: [u32; 5],
        message_bit_len: u64,
    ) -> Self {
        Self {
            buffer: [0u8; BUFFER_SIZE],
            buffer_len: 0,
            digest: initialisation_constants,
            message_bit_len,
        }
    }

    pub fn digest_message(message: &[u8]) -> [u8; SHA1_LEN] {
        let mut hasher = Sha1::default();
        hasher.update(message);
        hasher.digest()
    }

    pub fn digest(mut self) -> [u8; SHA1_LEN] {
        self.md_pad();
        self.process_chunk();
        self.digest
            .map(|d| d.to_be_bytes())
            .concat()
            .try_into()
            .unwrap()
    }

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
            if self.buffer_len == BUFFER_SIZE {
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

    pub fn update_and_digest(mut self, message: &[u8]) -> [u8; SHA1_LEN] {
        self.update(message);
        self.digest()
    }

    fn process_chunk(&mut self) {
        let mut w = [0u32; 80];
        for (i, chunk) in self.buffer.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.digest;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for (digest_part, increment) in self.digest.iter_mut().zip([a, b, c, d, e]) {
            *digest_part = digest_part.wrapping_add(increment);
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
        self.buffer[56..].copy_from_slice(&self.message_bit_len.to_be_bytes());
    }
}

impl Default for Sha1 {
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
    #[case("", "2jmj7l5rSw0yVb/vlWAYkK/YBwk=")]
    #[case("abc", "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=")]
    #[case("We all live in a yellow submarine.", "7EdVwdNZMFk4Uq3Tz4nmnuxfrI0=")]
    #[case(&"012345".repeat(127), "/O/4J7+lv5Ykve47QZLcUTFVvrk=")]
    fn digest_returns_expected_hash(#[case] input: &str, #[case] expected: &str) {
        let mut hasher = Sha1::default();
        hasher.update(&input.as_bytes());
        let digest = hasher.digest();

        let expected_bytes = base64_decode(expected).unwrap();
        assert_eq!(digest.as_slice(), expected_bytes.as_slice());
    }
}
