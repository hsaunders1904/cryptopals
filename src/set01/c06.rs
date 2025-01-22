use std::ops::Range;

use crate::{brute_force_byte_xor_cipher, repeating_xor_cipher, score_english_by_frequency};

pub fn brute_force_repeating_xor(bytes: &[u8], key_size_range: Range<usize>) -> (Vec<u8>, Vec<u8>) {
    // Get a best guess at the key size by finding the key size for which the
    // hamming (edit) distance between sets of key-sized blocks is the
    // smallest.
    let key_sizes = sorted_edit_distances(bytes, key_size_range)
        .into_iter()
        .map(|x| x.1);
    // Loop through our top N candidate key sizes and attempt to break the
    // cipher. We do this by:
    //   - Chunking the ciphertext into key-size blocks.
    //   - Transposing the blocks such that each new block contains the i-th
    //     byte from each original block.
    //   - Brute forcing each transposed block as a single byte-XOR cipher.
    //   - Combining each byte of the key we brute-forced to get the complete
    //     key.
    //   - Identifying the correct key using English language identification on
    //     the consequent plaintext.
    //
    // This works because the key being used to XOR the plaintext is repeated
    // for each key-sized block; therefore the bytes at common multiples of the
    // key size were all XOR-ed using the same byte. By splitting the
    // ciphertext into key-sized blocks and transposing, we group the bytes
    // that were XOR-ed with the same byte together. This provides us with
    // sufficient statistics to run our single-byte XOR cipher breaker.
    let mut candidate_messages = Vec::new();
    let mut keys = Vec::new();
    for key_size in key_sizes.take(3) {
        let key = (0..key_size)
            // Transpose the ciphertext to group all bytes that would have
            // been XOR-ed with the same byte of the key.
            .map(|byte_idx| {
                bytes
                    .iter()
                    .skip(byte_idx)
                    .step_by(key_size)
                    .copied()
                    .collect::<Vec<_>>()
            })
            // Brute force the i-th byte of the key.
            .map(|blocks| brute_force_byte_xor_cipher(&blocks).0)
            .collect::<Vec<u8>>();
        candidate_messages.push(repeating_xor_cipher(bytes, &key));
        keys.push(key);
    }

    let best_candidate = candidate_messages
        .iter()
        .zip(keys.iter())
        .map(|(msg, key)| (score_english_by_frequency(msg), msg, key))
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .unwrap();
    (best_candidate.1.to_vec(), best_candidate.2.to_vec())
}

fn sorted_edit_distances(bytes: &[u8], key_size_range: Range<usize>) -> Vec<(f32, usize)> {
    let n_bytes_to_compare = 4;
    let mut edit_distance: Vec<(f32, usize)> = key_size_range
        .map(|ks| (block_edit_distance(bytes, ks, n_bytes_to_compare), ks))
        .collect();
    edit_distance.sort_by(|a, b| a.0.total_cmp(&b.0));
    edit_distance
}

fn block_edit_distance(bytes: &[u8], key_size: usize, n_blocks_to_compare: usize) -> f32 {
    let bytes_it = bytes.iter().as_slice().chunks(key_size);
    let bytes_it_displaced = bytes.iter().as_slice().chunks(key_size).skip(1);
    bytes_it
        .zip(bytes_it_displaced.skip(1))
        .take(n_blocks_to_compare)
        .map(|(a, b)| hamming_distance(a, b))
        .sum::<u32>() as f32
        / n_blocks_to_compare as f32
        / key_size as f32
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::base64_decode;

    #[test]
    fn hamming_distance_finds_number_of_differing_bits() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();

        let dist = hamming_distance(a, b);

        assert_eq!(dist, 37);
    }

    #[test]
    fn decrypt_message() {
        let data_file = std::path::Path::new("./data/set01/c06.b64");
        let b64_ciphertext = std::fs::read_to_string(data_file)
            .unwrap()
            .replace('\n', "");
        let ciphertext = base64_decode(&b64_ciphertext).unwrap();

        let plaintext = brute_force_repeating_xor(&ciphertext, 8..33).0;

        let message = String::from_utf8_lossy(&plaintext).to_string();
        let mut message_lines = message.trim().split('\n');
        assert_eq!(
            message_lines.next().unwrap(),
            "I'm back and I'm ringin' the bell "
        );
        assert_eq!(message_lines.last().unwrap(), "Play that funky music");
    }
}
