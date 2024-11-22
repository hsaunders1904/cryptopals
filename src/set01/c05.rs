/// Encrypt a message using a repeating-key XOR cipher.

pub fn repeating_xor_cipher(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(message.len());
    message
        .iter()
        .as_slice()
        .chunks(key.len())
        .for_each(|chunk| {
            chunk
                .iter()
                .zip(key.iter())
                .for_each(|(m, b)| ciphertext.push(m ^ b))
        });
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hex_to_bytes;

    #[test]
    fn encrypts_message() {
        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let bytes = message.as_bytes();
        let key = "ICE";

        let ciphertext = repeating_xor_cipher(bytes, key.as_bytes());

        let expected_ciphertext =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527\
             2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(ciphertext, hex_to_bytes(expected_ciphertext).unwrap());
    }
}
