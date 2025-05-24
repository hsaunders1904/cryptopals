// In this challenge we are given a ciphertext that was derived by XOR-ing
// every byte of message with a character. We must decipher the message and
// find the key.
//
// To do this we take a brute force approach and loop over each possible u8
// character to give us a candidate message. We must then inspect the
// candidates and decide which is most likely to be the original message. We
// know the message is in English, so we can use this fact.
//
// To help identify English text, we have a table of expected frequencies of
// characters in English. We can count the occurrences of each character in
// the message (ignoring characters we don't have statistics for) and
// compare them to the expected frequencies/distribution. A Chi-Squared test
// gives us a measure of how likely the text is to be in English.
//
// Note that in this solution we ignore uppercase letters instead of
// treating them as lowercase. We do this because upper and lowercase
// characters only differ by a single and specific bit, e.g,
//   'A' = 01000001  'X' = 01011000
//   'a' = 01100001  'x' = 01111000
// Because of this, using 'X' as the key would give the same ciphertext as
// using 'x', but in uppercase. Hence both ciphertexts would score the same in
// our scheme. Obviously this upper-lowercase problem only exists for
// characters a-z. The real message can be identified by examining the
// punctuation. However, I couldn't find any statistics including punctuation
// (although I admit I didn't look very hard), so I took the easy route and
// ignored uppercase characters. This might throw our statistics off slightly,
// as some letters are bound to be more likely to appear capitalised than
// others, but it shouldn't be a significant difference.

use rayon::prelude::*;

// http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
const LETTER_FREQUENCIES: [f64; 26] = [
    0.08551690673195275,   // A
    0.016047959168228293,  // B
    0.03164435380900101,   // C
    0.03871183735737418,   // D
    0.1209652247516903,    // E
    0.021815103969122528,  // F
    0.020863354250923158,  // G
    0.04955707280570641,   // H
    0.0732511860723129,    // I
    0.002197788956104563,  // J
    0.008086975227142329,  // K
    0.04206464329306453,   // L
    0.025263217360184446,  // M
    0.07172184876283856,   // N
    0.07467265410810447,   // O
    0.020661660788966266,  // P
    0.0010402453014323196, // Q
    0.0633271013284023,    // R
    0.06728203117491646,   // S
    0.08938126949659495,   // T
    0.026815809362304373,  // U
    0.01059346274662571,   // V
    0.018253618950416498,  // W
    0.0019135048594134572, // X
    0.017213606152473405,  // Y
    0.001137563214703838,  // Z
];
const PUNCTUATION_CHARS: &[char] = &[' ', ',', '.', '!', '?', '\'', '"', ':', ';'];

pub struct XorCrackResult {
    pub key: u8,
    pub message: String,
    pub score: f64,
}

pub fn brute_force_byte_xor_cipher(bytes: &[u8]) -> XorCrackResult {
    let mut candidates: Vec<(f64, u8, Vec<u8>)> = (0..=255u8)
        .into_par_iter()
        .map(|key| {
            let decrypted = xor_with_key(bytes, key);
            let score = score_english_by_frequency(&decrypted);
            (score, key, decrypted)
        })
        .filter(|(score, _, _)| !score.is_nan())
        .collect();

    candidates.par_sort_by(|a, b| b.0.total_cmp(&a.0));

    if let Some((score, key, message)) = candidates.first() {
        XorCrackResult {
            key: *key,
            message: String::from_utf8_lossy(message).to_string(),
            score: *score,
        }
    } else {
        XorCrackResult {
            key: 0,
            message: String::new(),
            score: 0.0,
        }
    }
}

fn xor_with_key(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|b| b ^ key).collect()
}

pub fn score_english_by_frequency(bytes: &[u8]) -> f64 {
    let mut counts = [0u64; 26];
    let mut relevant_chars = 0f64;

    for &b in bytes {
        let ch = (b as char).to_ascii_lowercase();
        if ch.is_ascii_lowercase() {
            counts[(ch as u8 - b'a') as usize] += 1;
            relevant_chars += 1.;
        } else if PUNCTUATION_CHARS.contains(&ch) {
            relevant_chars += 0.5;
        }
    }

    if bytes.is_empty() {
        return 0.0;
    }

    let chi = chi_squared(&counts, &LETTER_FREQUENCIES).abs();
    if chi == 0.0 {
        return 1.0;
    }

    // For short strings, put more weight on the number of relevant characters.
    // For longer strings, put more weight on the Chi-squared distribution.
    let weight = relevant_chars / bytes.len() as f64;
    let chi2_confidence = (bytes.len() as f64 / 40.0).min(1.0);
    let distribution_score = weight / chi;
    chi2_confidence * distribution_score + (1.0 - chi2_confidence) * weight
}

/// Computes the chi-squared score between observed and expected letter frequencies.
fn chi_squared(observed: &[u64], expected: &[f64]) -> f64 {
    let total: u64 = observed.iter().sum();
    if total == 0 {
        return f64::NAN;
    }

    let total_f = total as f64;
    observed
        .iter()
        .zip(expected.iter())
        .map(|(&obs, &exp)| {
            let expected_count = exp * total_f;
            (obs as f64 - expected_count).powi(2) / expected_count
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_to_bytes;

    #[test]
    fn brute_force_xor_recovers_plaintext() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes = hex_to_bytes(input).unwrap();

        let result = brute_force_byte_xor_cipher(&bytes);

        assert_eq!(result.key, 88);
        assert_eq!(result.message, "Cooking MC's like a pound of bacon");
    }
}
