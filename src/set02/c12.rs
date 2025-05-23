// Byte-at-a-time ECB decryption (Simple)

use crate::{encrypt_aes_128_ecb, pkcs7_unpad_unchecked, score_aes_ecb_likelihood};

use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub struct EcbOracle {
    key: [u8; 16],
    unknown_bytes: Vec<u8>,
}

impl EcbOracle {
    pub fn new(key: [u8; 16], unknown_string: Vec<u8>) -> Self {
        Self {
            key,
            unknown_bytes: unknown_string,
        }
    }

    pub fn encrypt(&self, prefix: &[u8]) -> Vec<u8> {
        let message = [prefix, &self.unknown_bytes].concat();
        encrypt_aes_128_ecb(&message, &self.key)
    }
}

pub fn byte_at_a_time_aes_ecb_decrypt(oracle: &EcbOracle) -> Result<Vec<u8>, String> {
    // Detect the block size used for encrypting the ciphertext.
    let block_size = detect_block_size(oracle);
    if block_size != 16 {
        return Err(format!("unsupported block size '{block_size}' detected"));
    }

    // Make sure the ciphertext was generated using ECB.
    let test_ciphertext = oracle.encrypt(&vec![b'A'; block_size * 4]);
    if score_aes_ecb_likelihood(&test_ciphertext) < 1e-5 {
        return Err("ciphertext not encrypted using ECB".to_string());
    }

    let secret_length = oracle.encrypt(b"").len();

    // Loop over each byte in the ciphertext and brute force it using our
    // oracle.
    // The oracle will encrypt the unknown plaintext with some given prefix
    // using a consistent but unknown key.
    // Initially we pass a prefix of arbitrary repeating bytes with a length
    // of 'block_size - 1' to the oracle, this causes the first block of the
    // plaintext to contain only a single byte of the unknown plaintext.
    // We can then loop through each candidate byte B, append it to our prefix,
    // pass that to the oracle, and compare it to the ciphertext we found
    // earlier. On the next iteration we can use a prefix of length
    // 'block_size - 2' and apply the same idea to crack the second byte.
    // We can repeat this process to crack each byte in turn.
    let mut decrypted_bytes: Vec<u8> = Vec::with_capacity(secret_length);
    for _ in 0..secret_length {
        if let Some(byte) = decrypt_next_byte(block_size, &decrypted_bytes, oracle) {
            decrypted_bytes.push(byte);
        }
    }
    pkcs7_unpad_unchecked(&mut decrypted_bytes);
    Ok(decrypted_bytes)
}

fn decrypt_next_byte(block_size: usize, decrypted_bytes: &[u8], oracle: &EcbOracle) -> Option<u8> {
    let n_prefix_bytes = block_size - (decrypted_bytes.len() % block_size) - 1;
    let prefix = b"A".repeat(n_prefix_bytes);
    let crack_len = n_prefix_bytes + decrypted_bytes.len() + 1;
    let real_ciphertext = oracle.encrypt(&prefix);

    (0u8..=255).into_par_iter().find_map_any(|i| {
        let mut input = Vec::with_capacity(prefix.len() + decrypted_bytes.len() + 1);
        input.extend_from_slice(&prefix);
        input.extend_from_slice(decrypted_bytes);
        input.push(i);
        let ciphertext = oracle.encrypt(&input);
        let candidate_block = &ciphertext[..crack_len];
        if candidate_block == &real_ciphertext[..crack_len] {
            Some(i)
        } else {
            None
        }
    })
}

fn detect_block_size(oracle: &EcbOracle) -> usize {
    let initial_len = oracle.encrypt(&[]).len();
    let mut input = vec![b'A'];
    loop {
        let new_len = oracle.encrypt(&input).len();
        if new_len > initial_len {
            return new_len - initial_len;
        }
        input.push(b'A');
    }
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
        let decoded_secret = base64_decode(UNKNOWN_STRING).unwrap();
        let oracle = EcbOracle::new(key, decoded_secret.clone());

        let secret_bytes = byte_at_a_time_aes_ecb_decrypt(&oracle).unwrap();

        let decrypted_string = String::from_utf8_lossy(&secret_bytes);
        let expected_string = String::from_utf8_lossy(&decoded_secret);
        assert_eq!(decrypted_string, expected_string);
    }
}
