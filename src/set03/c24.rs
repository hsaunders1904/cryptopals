use crate::Mt19937;

pub fn recover_seed_from_mt19937_cipher_encrypted_message<F>(
    message: &[u8],
    plaintext_identifier: F,
) -> Option<u16>
where
    F: Fn(&[u8]) -> bool,
{
    for candidate_seed in 0..=u16::MAX {
        let candidate_plaintext = mt19937_cipher(candidate_seed, message);
        if plaintext_identifier(&candidate_plaintext) {
            return Some(candidate_seed);
        }
    }
    None
}

pub fn mt19937_cipher(seed: u16, message: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(message.len());
    let mut key_buf = [0u8; 4];
    let mut rng = Mt19937::new(seed.into());
    for (i, byte) in message.iter().enumerate() {
        let idx = i % 4;
        if idx == 0 {
            key_buf = rng.generate().to_le_bytes();
        }
        output.push(byte ^ key_buf[idx]);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mt19937_cipher_encrypts_and_decrypts() {
        let message = b"Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.".to_vec();
        let seed: u16 = 1234;

        let ciphertext = mt19937_cipher(seed, &message);
        let decrypted = mt19937_cipher(seed, &ciphertext);

        assert_ne!(message, ciphertext);
        assert_eq!(message, decrypted);
    }

    #[test]
    fn recover_seed_from_mt19937_cipher_encrypted_message_recovers_seed() {
        let mut message_rng = Mt19937::new(101);
        let n_rand_bytes = message_rng.generate_in_range(32, 128);
        let rand_bytes: Vec<u8> = (0..n_rand_bytes)
            .map(|_| (message_rng.generate() & 0b11111111).try_into().unwrap())
            .collect();
        let message = [rand_bytes, b"a".repeat(14)].concat();
        let encryption_seed = 59135;
        let ciphertext = mt19937_cipher(encryption_seed, &message);

        let recovered_seed =
            recover_seed_from_mt19937_cipher_encrypted_message(&ciphertext, |candidate| {
                candidate.ends_with(&b"a".repeat(14))
            });

        assert_eq!(recovered_seed.unwrap(), encryption_seed);
    }
}
