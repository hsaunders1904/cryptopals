// Byte-at-a-time ECB decryption (Harder)

use crate::{encrypt_aes_128_ecb, pkcs7_unpad_unchecked, Mt19937};

const BLOCK_SIZE: usize = 16;

pub struct EcbRandomPrefixOracle {
    key: [u8; BLOCK_SIZE],
    prefix: Vec<u8>,
    unknown_bytes: Vec<u8>,
}

impl EcbRandomPrefixOracle {
    pub fn new(key: [u8; BLOCK_SIZE], seed: u32, unknown_bytes: Vec<u8>) -> Self {
        Self {
            key,
            prefix: Self::make_random_prefix(seed),
            unknown_bytes,
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let plaintext = [&self.prefix, msg, &self.unknown_bytes].concat();
        encrypt_aes_128_ecb(&plaintext, &self.key)
    }

    fn make_random_prefix(seed: u32) -> Vec<u8> {
        let mut rng = Mt19937::new(seed);
        let n_random_bytes = rng.generate_in_range(1, 16 * BLOCK_SIZE as u32);
        (0..n_random_bytes)
            .map(|_| rng.generate() as u8)
            .collect::<Vec<u8>>()
    }
}

pub fn random_prefix_byte_at_a_time_with_aes_ecb_decrypt(
    oracle: &EcbRandomPrefixOracle,
) -> Option<Vec<u8>> {
    let prefix_len = find_prefix_length(oracle)?;
    let secret_length = oracle.encrypt(&[]).len() - prefix_len - 1;

    let mut decrypted_bytes: Vec<u8> = Vec::new();
    for _ in 0..secret_length {
        if let Some(byte) = crack_next_byte(BLOCK_SIZE, &decrypted_bytes, oracle, prefix_len) {
            decrypted_bytes.push(byte);
        }
    }
    pkcs7_unpad_unchecked(&mut decrypted_bytes);
    Some(decrypted_bytes)
}

fn crack_next_byte(
    block_size: usize,
    decrypted_bytes: &[u8],
    oracle: &EcbRandomPrefixOracle,
    prefix_len: usize,
) -> Option<u8> {
    let n_prefix_bytes = block_size - ((prefix_len + decrypted_bytes.len()) % block_size) - 1;
    let prefix = b"A".repeat(n_prefix_bytes);

    let crack_len = prefix_len + n_prefix_bytes + decrypted_bytes.len() + 1;

    let real_ciphertext = oracle.encrypt(&prefix);

    for i in 0..255u8 {
        let candidate_msg = [&prefix, decrypted_bytes, &[i]].concat();
        let fake_ciphertext = oracle.encrypt(&candidate_msg);
        if fake_ciphertext[..crack_len] == real_ciphertext[..crack_len] {
            return Some(i);
        }
    }
    None
}

fn find_prefix_length(oracle: &EcbRandomPrefixOracle) -> Option<usize> {
    // For two calls to our oracle with differing messages, the ciphertext
    // blocks for the random prefix will be the same. The first block that is
    // not equal in the two ciphertexts, is where the prefix must end.
    let c1 = oracle.encrypt(b"0");
    let c2 = oracle.encrypt(b"1");
    let prefix_block_end = c1
        .chunks(BLOCK_SIZE)
        .zip(c2.chunks(BLOCK_SIZE))
        .enumerate()
        .find_map(|(i, (c1, c2))| if c1 != c2 { Some(i) } else { None })?;

    // Now we have the block where the prefix must end, we need to find where
    // in that block it ends. We can use the fact that two equal blocks are
    // encrypted to the same thing in ECB, to find how many bytes of the prefix
    // are in the final prefix block. Start with two blocks worth of zeros as
    // a message and increment the length by one, until we can find two
    // consecutive equal blocks of ciphertext. Once we can, we know there are
    // 'current increment' bytes of our message in the final prefix block -
    // giving us the number of bytes of the prefix in the block.
    for i in 0..BLOCK_SIZE {
        let c_inc = oracle.encrypt(&b"0".repeat(2 * BLOCK_SIZE + i));
        let c_it = c_inc.chunks(BLOCK_SIZE).skip(8);
        let c_it_1 = c_it.clone().skip(1);
        let consecutive_equal_blocks = c_it_1.zip(c_it).find(|(x, y)| x == y);
        if consecutive_equal_blocks.is_some() {
            return Some(prefix_block_end * BLOCK_SIZE + BLOCK_SIZE - i);
        }
    }

    // No consecutive blocks found. Not possible for ECB.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{base64_decode, random_bytes};

    const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK";

    #[test]
    fn byte_at_a_time_aes_ecb_decrypt_decrypts_message_with_oracle() {
        let key = random_bytes::<16>();
        let seed = 101;
        let decoded_secret = base64_decode(UNKNOWN_STRING).unwrap();
        let oracle = EcbRandomPrefixOracle::new(key, seed, decoded_secret.clone());

        let secret_bytes = random_prefix_byte_at_a_time_with_aes_ecb_decrypt(&oracle).unwrap();

        let decrypted_string = String::from_utf8_lossy(&secret_bytes);
        let expected_string = String::from_utf8_lossy(&decoded_secret);
        assert_eq!(decrypted_string, expected_string);
    }
}
