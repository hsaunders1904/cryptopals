use crate::aes::AesCipher;

pub fn decrypt_aes_128_ecb(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut cipher = AesCipher::new(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.iter().as_slice().chunks(key.len()) {
        plaintext.extend(vec![0; 16]);
        let range = (plaintext.len() - 16)..(plaintext.len());
        let mut ptext_buf: &mut [u8] = &mut plaintext.as_mut_slice()[range];

        cipher.decrypt_block(block.try_into().unwrap(), &mut ptext_buf);
    }
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::base64_decode;

    #[test]
    fn decrypt_text_aes_ecb() {
        let data_file = std::path::Path::new("./data/set01/c07.b64");
        let b64_ciphertext = std::fs::read_to_string(data_file)
            .unwrap()
            .replace("\n", "");
        let ciphertext = base64_decode(&b64_ciphertext).unwrap();
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();

        let plaintext = decrypt_aes_128_ecb(&ciphertext, &key);

        let message = String::from_utf8_lossy(&plaintext);
        assert_eq!(
            message.split('\n').next().unwrap().trim(),
            "I'm back and I'm ringin' the bell"
        );
    }
}
