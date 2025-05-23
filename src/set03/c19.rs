use crate::brute_force_byte_xor_cipher;

pub fn brute_force_reused_nonce_aes_ctr_ciphertexts(ciphertexts: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut transposed_ciphertexts: Vec<Vec<u8>> = Vec::new();
    for slice in ciphertexts {
        for (byte_idx, byte) in slice.iter().enumerate() {
            if let Some(v) = transposed_ciphertexts.get_mut(byte_idx) {
                v.push(*byte);
            } else {
                transposed_ciphertexts.push(vec![*byte]);
            }
        }
    }

    let keystream: Vec<u8> = transposed_ciphertexts
        .iter()
        .map(|transposed_ciphertext| brute_force_byte_xor_cipher(transposed_ciphertext).key)
        .collect();

    ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .iter()
                .zip(keystream.iter())
                .map(|(c, k)| c ^ k)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{aes_128_ctr, base64_decode, random_bytes_with_seed};

    use std::io::BufRead;

    #[test]
    fn brute_force_reused_nonce_aes_ctr_ciphertexts_recovers_plaintexts() {
        let data_file = std::fs::File::open("./data/set03/c19.b64").unwrap();
        let plaintexts = std::io::BufReader::new(data_file)
            .lines()
            .map_while(|line| line.ok())
            .filter(|line| !line.trim().is_empty())
            .map(|line| base64_decode(&line).unwrap())
            .collect::<Vec<Vec<u8>>>();
        let nonce = [0; 8];
        let key = random_bytes_with_seed::<16>(101);
        let ciphertexts: Vec<Vec<u8>> = plaintexts
            .iter()
            .map(|plaintext| aes_128_ctr(plaintext, &key, &nonce, 0))
            .collect();

        let broken_plaintexts = brute_force_reused_nonce_aes_ctr_ciphertexts(
            &ciphertexts
                .iter()
                .map(|c| c.as_ref())
                .collect::<Vec<&[u8]>>(),
        );

        // This attack is based on gathering statistics that allow us to
        // identify English text across blocks of ciphertext. As some
        // ciphertexts are longer than others, when we try to crack the final
        // bytes of the longer ciphertexts we get worse statistics and the
        // attack breaks down. There is probably some clever stuff we can do
        // that uses previously cracked plaintext to help with subsequent
        // bytes, but we don't attempt that here.
        // Instead, only check we can crack the first N bytes, where we can
        // gather sufficient statistics. We still crack the majority of the
        // text and the un-cracked bytes are pretty clear to the human eye.
        // The maximum plaintext length in this example is 38 bytes.
        const N_CHARS_TO_MATCH: usize = 31;
        for (ptext, expected) in broken_plaintexts.iter().zip(plaintexts) {
            assert_eq!(ptext.len(), expected.len());
            let n_chars = N_CHARS_TO_MATCH.min(ptext.len());
            assert_eq!(
                String::from_utf8_lossy(&ptext[..n_chars]).to_lowercase(),
                String::from_utf8_lossy(&expected[..n_chars]).to_lowercase(),
            );
        }
    }
}
