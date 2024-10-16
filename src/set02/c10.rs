/// Implement CBC mode
use crate::{aes::AesCipher, pkcs7_pad, xor_bytes};

use super::c09::pkcs7_unpad;

pub fn encrypt_aes_128_cbc(plaintext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len() + (plaintext.len() % 16));
    let mut cipher = AesCipher::new(key);

    let mut last_block = *iv;
    let n_blocks = plaintext.len() / 16;
    for (i, plaintext_block) in plaintext.iter().as_slice().chunks(16).enumerate() {
        let is_final_block = n_blocks == i;
        let message_buf: [u8; 16] = if !is_final_block {
            xor_bytes(plaintext_block.try_into().unwrap(), &last_block)
        } else {
            let padded_block = pkcs7_pad(&plaintext_block, 16);
            xor_bytes(&padded_block.try_into().unwrap(), &last_block)
        };
        let mut ciphertext_buf = [0u8; 16];
        cipher.encrypt_block(message_buf, &mut ciphertext_buf);
        ciphertext.extend_from_slice(&ciphertext_buf);
        last_block = ciphertext_buf;
    }
    ciphertext
}

pub fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
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
    pkcs7_unpad(&mut message);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{self, Engine};

    fn read_base64_file<P>(path: P) -> Vec<u8>
    where
        P: AsRef<std::path::Path>,
    {
        let b64_ciphertext = std::fs::read_to_string(path).unwrap().replace("\n", "");
        base64::engine::general_purpose::STANDARD
            .decode(b64_ciphertext)
            .unwrap()
    }

    #[test]
    fn decrypt_aes_128_cbc_returns_expected_ciphertext() {
        let ciphertext = read_base64_file("./data/set02/c10.b64");
        let iv: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();

        let plaintext = decrypt_aes_128_cbc(&ciphertext, &key, &iv);

        let message = String::from_utf8_lossy(&plaintext).to_string();
        let mut lines = message.trim().split("\n");
        assert_eq!(
            lines.next().unwrap(),
            "I'm back and I'm ringin' the bell ".to_string()
        );
        assert_eq!(lines.last().unwrap(), "Play that funky music".to_string());
    }

    #[test]
    fn decrypt_then_encrypt_returns_original_ciphertext() {
        let ciphertext = read_base64_file("./data/set02/c10.b64");
        let iv: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();

        let plaintext = decrypt_aes_128_cbc(&ciphertext, &key, &iv);
        let new_ciphertext = encrypt_aes_128_cbc(&plaintext, &key, &iv);

        assert_eq!(new_ciphertext, ciphertext);
    }
}
