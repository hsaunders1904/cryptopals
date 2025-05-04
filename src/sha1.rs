const INITIALISATION_CONSTANTS: [u32; 5] =
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const SHA1_LEN: usize = 20;

pub struct Sha1 {
    buffer: Vec<u8>,
    digest: [u32; 5],
    message_bit_len: u64,
}

impl Sha1 {
    pub fn new(input: &[u8]) -> Self {
        Self::new_with_initialisation_constants(
            input,
            INITIALISATION_CONSTANTS,
            (input.len() as u64) * 8,
        )
    }

    pub fn new_with_initialisation_constants(
        input: &[u8],
        initialisation_constants: [u32; 5],
        message_bit_len: u64,
    ) -> Self {
        Self {
            buffer: input.to_vec(),
            digest: initialisation_constants,
            message_bit_len,
        }
    }

    pub fn digest(mut self) -> [u8; SHA1_LEN] {
        let mut buffer = std::mem::take(&mut self.buffer);
        let len_mod = (buffer.len() + 8) % 64;
        let pad_len = (64 - len_mod) % 64;
        buffer.extend(std::iter::once(0x80));
        buffer.extend(std::iter::repeat(0x00).take(pad_len - 1));
        buffer.extend_from_slice(&self.message_bit_len.to_be_bytes());

        for chunk in buffer.chunks_exact(64) {
            self.process_chunk(&chunk.try_into().unwrap());
        }

        self.digest
            .map(|d| d.to_be_bytes())
            .concat()
            .try_into()
            .unwrap()
    }

    fn process_chunk(&mut self, chunk: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, chunk) in chunk.chunks_exact(4).enumerate() {
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

        self.digest[0] = self.digest[0].wrapping_add(a);
        self.digest[1] = self.digest[1].wrapping_add(b);
        self.digest[2] = self.digest[2].wrapping_add(c);
        self.digest[3] = self.digest[3].wrapping_add(d);
        self.digest[4] = self.digest[4].wrapping_add(e);
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
    fn digest_returns_expected_hash(#[case] input: &str, #[case] expected: &str) {
        let hasher = Sha1::new(&input.as_bytes());
        let digest = hasher.digest();

        let expected_bytes = base64_decode(expected).unwrap();
        assert_eq!(digest.as_slice(), expected_bytes.as_slice());
    }
}
