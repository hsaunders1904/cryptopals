// Recover the key from CBC with IV=Key

use crate::{pkcs7_unpad, xor_bytes, AesCipher, CbcQueryOracle};

const BLOCK_SIZE: usize = 16;

pub fn recover_key_from_iv_eq_key_cbc_oracle(
    oracle: &CbcIvEqKeyQueryOracle,
) -> Result<[u8; BLOCK_SIZE], String> {
    let message = b"We all live on a yellow submarine, a yellow sub.";
    let ciphertext = oracle.encrypt(message);

    let modified_message = [
        &ciphertext[..BLOCK_SIZE],
        &[0u8; 16],
        &ciphertext[..BLOCK_SIZE],
    ]
    .concat();

    let modified_decryption = oracle.decrypt_and_check_ascii(&modified_message);

    if let Err(decryption) = modified_decryption {
        let broken_key = decryption[..BLOCK_SIZE]
            .iter()
            .zip(decryption[(BLOCK_SIZE * 2)..].iter())
            .map(|(p1, p3)| p1 ^ p3)
            .collect::<Vec<_>>();
        Ok(broken_key.try_into().map_err(|e: Vec<u8>| {
            format!("key recovery failed: key size is incorrect: {}", e.len())
        })?)
    } else {
        Err("key recovery failed: decrypted message was ASCII compliant".into())
    }
}

pub struct CbcIvEqKeyQueryOracle {
    oracle: CbcQueryOracle,
    key: [u8; 16],
}

impl CbcIvEqKeyQueryOracle {
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            oracle: CbcQueryOracle::new(key, key),
            key,
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        self.oracle.encrypt(msg)
    }

    pub fn decrypt_and_check_ascii(&self, ciphertext: &[u8]) -> Result<(), Vec<u8>> {
        let plaintext = decrypt_aes_128_cbc_unchecked_padding(ciphertext, &self.key, &self.key);
        if plaintext.iter().all(|&x| x < 128) {
            return Ok(());
        }
        Err(plaintext)
    }
}

fn decrypt_aes_128_cbc_unchecked_padding(
    ciphertext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(ciphertext.len());
    let mut cipher = AesCipher::new(key);

    let mut last_block = *iv;
    for ciphertext_block in ciphertext.iter().as_slice().chunks(16) {
        let ciphertext_buf: [u8; 16] = ciphertext_block.try_into().unwrap();
        let mut message_buf = [0u8; 16];
        cipher.decrypt_block(ciphertext_buf, &mut message_buf);
        message.extend_from_slice(&xor_bytes(&last_block, &message_buf));
        last_block = ciphertext_buf;
    }
    let _ = pkcs7_unpad(&mut message);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random_bytes_with_seed;

    #[test]
    fn recover_key_from_iv_eq_key_cbc_oracle_breaks_oracles_key() {
        let key = random_bytes_with_seed(101);
        let oracle = CbcIvEqKeyQueryOracle::new(key);

        let broken_key = recover_key_from_iv_eq_key_cbc_oracle(&oracle).unwrap();

        assert_eq!(broken_key, key);
    }
}
