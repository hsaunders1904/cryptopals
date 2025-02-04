// Detect AES in ECB mode

/// Return a score for how likely some bytes were encrypted using AES-128 ECB.
///
/// The score will be between 0 and 1, but does not indicate a probability.
/// The score is the ratio of repeated blocks to blocks. As the same plaintext
/// block will result in the same ciphertext when using ECB, you are likely to
/// get the same fraction of repeated blocks as you would in English. This
/// fraction will almost certainly be higher than some random string of bytes.
pub fn score_aes_ecb_likelihood(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.;
    }
    let n_block_repetitions = count_block_repetitions(bytes);
    n_block_repetitions as f64 / (bytes.len() / 16) as f64
}

fn count_block_repetitions(bytes: &[u8]) -> u32 {
    debug_assert!((bytes.len() % 16) == 0);

    let mut n_repetitions = 0;
    let mut seen_blocks = std::collections::HashSet::<u128>::new();
    for block in bytes.iter().as_slice().chunks(16) {
        let block_128 = u128_from_block(block.try_into().unwrap());
        if !seen_blocks.insert(block_128) {
            n_repetitions += 1;
        }
    }
    n_repetitions
}

fn u128_from_block(block: &[u8; 16]) -> u128 {
    let mut block_128 = 0u128;
    for (i, byte) in block.iter().enumerate() {
        block_128 |= *byte as u128;
        block_128 <<= block.len() - 1 - i;
    }
    block_128
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;

    use crate::hex_to_bytes;

    use super::*;

    fn read_lines<P>(
        filename: P,
    ) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>>
    where
        P: AsRef<std::path::Path>,
    {
        let file = std::fs::File::open(filename)?;
        Ok(std::io::BufReader::new(file).lines())
    }

    #[test]
    fn score_aes_ecb_likelihood_finds_encrypted_text() {
        let candidate_ciphertexts = read_lines("./data/set01/c08.hex")
            .unwrap()
            .map(|hex| hex_to_bytes(&hex.unwrap()).unwrap());

        let (most_likely_index, _) = candidate_ciphertexts
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                score_aes_ecb_likelihood(a).total_cmp(&score_aes_ecb_likelihood(b))
            })
            .unwrap();

        assert_eq!(most_likely_index, 132);
        // TODO(hsaunders1904): it would be interesting to try and crack the
        //  password for this ciphertext, assuming the plaintext is in English.
    }
}
