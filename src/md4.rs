const BUFFER_SIZE: usize = 64;
const MD4_SIZE: usize = 16;
const INITIALISATION_CONSTANTS: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];

struct Md4 {
    buffer: [u8; BUFFER_SIZE],
    buffer_len: usize,
    digest: [u32; 4],
    message_bit_len: u64,
}

impl Md4 {
    pub fn update(&mut self, message: &[u8]) {}

    pub fn digest(mut self) -> [u8; MD4_SIZE] {
        [0u8; MD4_SIZE]
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
    ((i << n) & 0xffffffff) | (i >> (32 - n))
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
    #[case(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "4ztN3Jw48hmcPnsWT8wFNg"
    )]
    fn md4_generates_test_vector_hashes(#[case] input: &str, #[case] expected: &str) {
        let mut md4 = Md4::default();
        md4.update(&input.as_bytes());

        let expected_bytes = base64_decode(expected).unwrap();
        assert_eq!(md4.digest().to_vec(), expected_bytes);
    }
}
