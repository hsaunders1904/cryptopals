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

pub fn brute_force_byte_xor_cipher(bytes: &[u8]) -> (u8, String, f64) {
    let mut v: Vec<(f64, u8, Vec<u8>)> = (0..=255u8)
        .map(|ch| (ch, xor_with_char(bytes, ch)))
        .map(|(ch, msg)| (score_english_by_frequency(&msg), ch, msg))
        .filter(|(score, _, _)| !score.is_nan())
        .collect();
    v.sort_by(|(score1, _, _), (score2, _, _)| score2.total_cmp(score1));
    if v.is_empty() {
        return (0, "".to_string(), 0.0);
    }
    let (score, key, message) = v[0].clone();

    (key, String::from_utf8_lossy(&message).to_string(), score)
}

fn xor_with_char(bytes: &[u8], ch: u8) -> Vec<u8> {
    bytes.iter().map(|x| *x ^ ch).collect()
}

/// Return a score for how likely the chars are to be English text.
/// The higher the better.
pub fn score_english_by_frequency<'a, I>(chars: I) -> f64
where
    I: IntoIterator<Item = &'a u8>,
{
    let mut char_counts = [0u64; 26];
    let mut n_a_to_z = 0;
    let mut n_chars = 0;
    chars.into_iter().copied().for_each(|i| {
        n_chars += 1;
        if (97..=122).contains(&i) {
            if let Some(count) = char_counts.get_mut(i as usize - 97) {
                n_a_to_z += 1;
                *count += 1
            }
        }
        // Increase weight if we find common punctuation
        else if [' ', ',', '.', '!', '"', '\''].contains(&(i as char)) {
            n_a_to_z += 1;
        }
    });
    if n_chars == 0 {
        return 0.;
    }

    let inv_score = chi_squared(&char_counts, &LETTER_FREQUENCIES).abs();
    if inv_score == 0. {
        return 1.;
    }
    // Weight the scores by number of letters in the a-z range. This helps a
    // lot with shorter strings where the Chi-Square statistics can be a bit
    // unreliable.
    let weight = (n_a_to_z as f64) / (n_chars as f64);
    weight / inv_score
}

fn chi_squared(counts: &[u64], distribution: &[f64]) -> f64 {
    let n_observations: u64 = counts.iter().sum();
    if n_observations == 0 {
        return f64::NAN;
    }
    counts
        .iter()
        .map(|x| (*x as f64 / n_observations as f64)) // normalise
        .zip(distribution)
        .map(|(o, p)| (o - p).powi(2) / p)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hex_to_bytes;

    #[test]
    fn brute_force_single_byte_xor_cipher() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes = hex_to_bytes(input).unwrap();

        let out = brute_force_byte_xor_cipher(&bytes);

        assert_eq!(out.0, 88);
        assert_eq!(out.1, "Cooking MC's like a pound of bacon".to_string());
    }
}
