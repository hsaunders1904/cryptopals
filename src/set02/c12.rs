/// Byte-at-a-time ECB decryption (Simple)
use crate::{encrypt_aes_128_ecb, score_aes_ecb_likelihood};

use super::c09::pkcs7_unpad;

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
    let block_size = detect_block_size(&oracle);
    if block_size != 16 {
        return Err(format!("unsupported block size '{block_size}' detected"));
    }

    // Make sure the ciphertext was generated using ECB.
    let ecb_score = score_aes_ecb_likelihood(&oracle.encrypt(&b"A".repeat(32)));
    if ecb_score < 1e-5 {
        return Err(format!("ciphertext not encrypted using ECB"));
    }

    // Get the length of the secret (which may have some padding)
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
    let mut decrypted_bytes: Vec<u8> = Vec::new();
    for _ in 0..secret_length {
        if let Some(byte) = crack_next_byte(block_size, &decrypted_bytes, &oracle) {
            decrypted_bytes.push(byte);
        }
    }
    pkcs7_unpad(&mut decrypted_bytes);
    Ok(decrypted_bytes)
}

fn crack_next_byte(block_size: usize, decrypted_bytes: &[u8], oracle: &EcbOracle) -> Option<u8> {
    let n_prefix_bytes = block_size - (decrypted_bytes.len() % block_size) - 1;
    let prefix = b"A".repeat(n_prefix_bytes);

    let crack_len = n_prefix_bytes + decrypted_bytes.len() + 1;

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

fn detect_block_size(oracle: &EcbOracle) -> usize {
    let initial_len = oracle.encrypt(&[]).len();
    let mut input = vec![b'A'];
    let mut ciphertext_len = oracle.encrypt(&input).len();
    while initial_len == ciphertext_len {
        input.push(b'A');
        ciphertext_len = oracle.encrypt(&input).len();
    }
    ciphertext_len - initial_len
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
