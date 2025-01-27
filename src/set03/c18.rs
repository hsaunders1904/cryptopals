use crate::AesCipher;

pub fn aes_128_ctr(message: &[u8], key: &[u8; 16], nonce: &[u8; 8], initial_value: u64) -> Vec<u8> {
    let mut cipher = AesCipher::new(key);
    let mut output = Vec::with_capacity(message.len());
    let mut counter = initial_value;
    let mut ctr_block = [0; 16];
    ctr_block[..8].copy_from_slice(nonce);
    let mut buf = [0; 16];
    for message_block in message.iter().as_slice().chunks(key.len()) {
        // Make the CTR block by concatenating nonce and counter
        ctr_block[8..].copy_from_slice(&counter.to_le_bytes());

        // Encrypt the CTR block
        cipher.encrypt_block(ctr_block, &mut buf);

        // XOR with message block and append to output
        for byte in message_block.iter().zip(buf).map(|(p, c)| p ^ c) {
            output.push(byte);
        }

        counter += 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{base64_decode, base64_encode};

    #[test]
    fn aes_128_ctr_encrypts_to_expected_ciphertext() {
        let key = b"YELLOW SUBMARINE";
        let initial_value = 0u64;
        let nonce = [0u8; 8];
        let message = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";

        let ciphertext = aes_128_ctr(message, key, &nonce, initial_value);

        let expected_ciphertext =
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let encoded_ciphertext = base64_encode(&ciphertext);
        assert_eq!(encoded_ciphertext, expected_ciphertext);
    }

    #[test]
    fn aes_128_ctr_decrypts_to_expected_plaintext() {
        let key = b"YELLOW SUBMARINE";
        let initial_value = 0u64;
        let nonce = [0u8; 8];
        let encoded_ciphertext =
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let ciphertext = base64_decode(encoded_ciphertext).unwrap();

        let plaintext = aes_128_ctr(&ciphertext, key, &nonce, initial_value);

        let expected_plaintext = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
        assert_eq!(plaintext, expected_plaintext);
    }
}
