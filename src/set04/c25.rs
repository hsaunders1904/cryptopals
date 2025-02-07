// Break "random access read/write" AES CTR

// AES-CTR mode works as follows:
//
//         nonce|counter0                nonce|counter1
//              ↓                             ↓
//     key → < AES >                 key → < AES >
//              ↓                             ↓                 ...
// plaintext →  ⊕               plaintext  →  ⊕
//              ↓                             ↓
//          ciphertext                    ciphertext
//
// Since each encryption block is independent, you can trivially seek into a
// given ciphertext and decrypt a specific block or blocks.

use crate::{aes_128_ctr, AesCipher};

const BLOCK_SIZE: usize = 16;

pub struct CtrEditOracle {
    key: [u8; 16],
    nonce: [u8; 8],
    ciphertext: Vec<u8>,
}

impl CtrEditOracle {
    pub fn new(key: [u8; 16], plaintext: &[u8]) -> Self {
        let nonce = [0u8; 8];
        Self {
            key,
            nonce,
            ciphertext: aes_128_ctr(plaintext, &key, &nonce, 0),
        }
    }

    pub fn edit(&self, new_text: &[u8], offset: usize) -> Vec<u8> {
        let mut buf = self.ciphertext.clone();
        edit_aes_ctr_ciphertext(&mut buf, &self.key, offset, new_text, &self.nonce);
        buf
    }
}

pub fn edit_aes_ctr_ciphertext(
    ciphertext: &mut [u8],
    key: &[u8; 16],
    offset: usize,
    new_text: &[u8],
    nonce: &[u8; 8],
) {
    if new_text.is_empty() || offset >= ciphertext.len() {
        return;
    }

    let ctr_start = offset / BLOCK_SIZE;
    let ctr_end = (offset + new_text.len() - 1) / BLOCK_SIZE;
    let mut nonce_ctr = [0u8; 16];
    nonce_ctr[..8].copy_from_slice(nonce);
    let mut cipher = AesCipher::new(key);
    let mut cipher_buf = [0u8; 16];

    let mut key_stream = Vec::with_capacity(new_text.len());
    for ctr_val in ctr_start..(ctr_end + 1) {
        nonce_ctr[8..].copy_from_slice(&ctr_val.to_le_bytes());
        cipher.encrypt_block(nonce_ctr, &mut cipher_buf);
        key_stream.extend_from_slice(&cipher_buf);
    }

    let block_offset = offset % BLOCK_SIZE;
    let new_ciphertext = new_text
        .iter()
        .zip(key_stream[block_offset..(block_offset + new_text.len())].iter())
        .map(|(pt, k)| pt ^ k)
        .collect::<Vec<_>>();
    ciphertext[offset..(offset + new_ciphertext.len())].copy_from_slice(&new_ciphertext);
}

/// Recover the plaintext from an AES CTR edit oracle.
///
/// As AES CTR mode is completely symmetric - you encrypt and decrypt using the
/// same function - if you simply edit the whole with the original ciphertext,
/// the oracle will decrypt it for you.
pub fn recover_ctr_edit_oracle_plaintext(oracle: &CtrEditOracle) -> Vec<u8> {
    // Make no edit, just get back the ciphertext.
    let ciphertext = oracle.edit(&Vec::new(), 0);
    // Get the oracle to decrypt the whole ciphertext.
    oracle.edit(&ciphertext, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{aes_128_ctr, base64_decode, decrypt_aes_128_ecb, random_bytes_with_seed};

    #[test]
    fn edit_aes_ctr_ciphertext_updates_ciphertext_in_place() {
        let plaintext = b"\0".repeat(37);
        let key = random_bytes_with_seed::<BLOCK_SIZE>(101);
        let nonce = [0u8; 8];
        let initial_value = 0;
        let mut ciphertext = aes_128_ctr(&plaintext, &key, &nonce, initial_value);

        edit_aes_ctr_ciphertext(&mut ciphertext, &key, 13, &b"A".repeat(21), &nonce);

        let new_plaintext = aes_128_ctr(&ciphertext, &key, &nonce, initial_value);
        assert_eq!(
            new_plaintext,
            [b"\0".repeat(13), b"A".repeat(21), b"\0".repeat(3)].concat()
        );
    }

    #[test]
    fn recover_ctr_edit_oracle_plaintext_recovers_plaintext() {
        // Decrypt ciphertext from previous challenge.
        // We'll re-encrypt it with AES-CTR.
        let data_file = std::path::Path::new("./data/set01/c07.b64");
        let b64_ciphertext = std::fs::read_to_string(data_file)
            .unwrap()
            .replace('\n', "");
        let ciphertext = base64_decode(&b64_ciphertext).unwrap();
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
        let plaintext = decrypt_aes_128_ecb(&ciphertext, &key);
        let oracle = CtrEditOracle::new(key, &plaintext);

        let recovered_plaintext = recover_ctr_edit_oracle_plaintext(&oracle);

        assert_eq!(recovered_plaintext, plaintext);
    }
}
