// Implementation of a padding oracle and a CBC padding oracle attach.
//
// The formula for CBC encryption is
//
//                  C_i = D(C_{i-1} ⊕ P_i).
//
// The formula for decryption is
//
//                 P_i = D(C_i) ⊕ C_{i-1}.
//
// The form of the decryption means that a single byte modification in block
// C_i will result in a single byte change in P_{i⊕1}.
//
// If we take a block we want to decrypt from our ciphertext, for example, C3,
// and prepend a block 'X' that we control, the formula for the decryption of
// the final block of this new ciphertext is:
//
//                     P'_3 = D(C_3) ⊕ X,
//                 where C_3 = E(P_3 ⊕ C_2).
//
// Hence P'_3 = D(E(P_3 ⊕ C_2)) ⊕ X = P_3 ⊕ C_2 ⊕ X and finally,
//
//                    P_3 = P'_3 ⊕ C_2 ⊕ X.
//
// We now have a formula for P_3 that involves no cryptographic operations, we
// do not need a key. P'_3 is still unknown, but we can find it using the
// padding oracle!
//
// We know that a valid decryption must have some padding, e.g., '\x01', or
// '\x02\x02', and so on. So we can use this fact to say, "maybe P'_3 is all
// padding" and "what would X have to be for this to be the case"? To brute
// force the final byte, the padding of P'_3 must be '\x01', so we vary the
// final byte of X and send C3|X to the oracle. If we have found the right
// value for the final byte of X, then the oracle will tell us we have valid
// padding! We then know the final byte of P'_3 is \x01 and we have found the
// final byte of X. From this we can find the final byte of P_3:
//
//                     P_3[15] = \x01 ⊕ C_2[15] ⊕ X[15]
//
// We can now do similar for the second-to-last byte of P_3. Our padding will
// be '\x02\x02' and we vary the second-to-last byte of X until the padding
// oracle tells us we have valid padding for C3|X. Then we have:
//
//                     P_3[14] = \x02 ⊕ C_2[14] ⊕ X[14]
//
// We can repeat this for each preceding byte and crack the whole block. The
// procedure can then be carried out for every block.
//
// Below we call 'X' a 'force IV block', as it acts as an IV to the
// single-block query we make to the oracle.
use crate::{base64_decode, decrypt_aes_128_cbc, encrypt_aes_128_cbc, random_bytes, Mt19937};

const PLAINTEXTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];
const BLOCK_SIZE: usize = 16;

pub struct PaddingOracle {
    key: [u8; 16],
    rng: Mt19937,
}

impl PaddingOracle {
    pub fn new(key: [u8; 16], seed: u32) -> Self {
        Self {
            key,
            rng: Mt19937::new(seed),
        }
    }

    pub fn encrypt_random_plaintext(&mut self) -> ([u8; 16], Vec<u8>) {
        let plaintext = self.random_plaintext();
        let iv = random_bytes::<16>();
        let ciphertext = encrypt_aes_128_cbc(&plaintext, &self.key, &iv);
        (iv, ciphertext)
    }

    pub fn ciphertext_padding_valid(&self, iv: &[u8; 16], ciphertext: &[u8]) -> bool {
        decrypt_aes_128_cbc(ciphertext, &self.key, iv).is_ok()
    }

    fn random_plaintext(&mut self) -> Vec<u8> {
        let idx = self.rng.generate_in_range(0, PLAINTEXTS.len() as u32 - 1);
        let encoded = PLAINTEXTS[idx as usize];
        base64_decode(encoded).unwrap()
    }
}

pub fn cbc_padding_oracle_attack(
    ciphertext: &[u8],
    iv: &[u8; BLOCK_SIZE],
    oracle: &PaddingOracle,
) -> Result<Vec<u8>, String> {
    let ciphertext_blocks = std::iter::once::<&[u8]>(iv)
        .chain(ciphertext.chunks(iv.len()))
        .collect::<Vec<_>>();
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
    for block_idx in 1..ciphertext_blocks.len() {
        let mut plaintext_block: Vec<u8> = Vec::with_capacity(BLOCK_SIZE);
        for padding_len in 1..=BLOCK_SIZE as u8 {
            if let Some(byte) = brute_force_byte(
                ciphertext_blocks[block_idx - 1],
                ciphertext_blocks[block_idx],
                padding_len,
                oracle,
                &plaintext_block,
            ) {
                plaintext_block.insert(0, byte);
            } else {
                return Err(format!(
                    "could not find plaintext byte {} for block {block_idx}",
                    BLOCK_SIZE - padding_len as usize
                ));
            }
        }
        plaintext.append(&mut plaintext_block);
    }

    Ok(plaintext)
}

fn make_forced_iv_block(
    iv: &[u8],
    candidate_byte: u8,
    padding_len: u8,
    found_plaintext: &[u8],
) -> [u8; BLOCK_SIZE] {
    let byte_index = iv.len() - padding_len as usize;
    let forced_char = iv[byte_index] ^ candidate_byte ^ padding_len;
    let mut forced_iv = [&iv[0..byte_index], &[forced_char]].concat();
    for (m, k) in ((BLOCK_SIZE - padding_len as usize + 1)..BLOCK_SIZE).enumerate() {
        let forced_char = iv[k] ^ found_plaintext[m] ^ padding_len;
        forced_iv.push(forced_char);
    }
    forced_iv.try_into().unwrap()
}

fn brute_force_byte(
    iv: &[u8],
    ciphertext_block: &[u8],
    padding_len: u8,
    oracle: &PaddingOracle,
    current_plaintext: &[u8],
) -> Option<u8> {
    let possible_last_bytes: Vec<u8> = (0..=255u8)
        .filter_map(|j| {
            let forced_iv = make_forced_iv_block(iv, j, padding_len, &current_plaintext);
            if oracle.ciphertext_padding_valid(&forced_iv, &ciphertext_block) {
                return Some(j);
            }
            None
        })
        .collect();

    if possible_last_bytes.len() > 1 {
        // If we find more than one possible byte, check the next byte
        // for each candidate.
        // If, for a given candidate, we find a valid byte on the next
        // go, then it's highly likely to be the byte we're looking
        // for.
        possible_last_bytes.iter().find_map(|byte| {
            for j in 0..=255u8 {
                let found_plaintext = [&[*byte], current_plaintext].concat();
                let forced_iv = make_forced_iv_block(iv, j, padding_len + 1, &found_plaintext);
                if oracle.ciphertext_padding_valid(&forced_iv, ciphertext_block) {
                    return Some(*byte);
                }
            }
            None
        })
    } else {
        possible_last_bytes.get(0).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pkcs7_unpad;

    #[test]
    fn cbc_padding_oracle_attack_recovers_plaintext() {
        let key = random_bytes::<16>();
        let mut oracle = PaddingOracle::new(key, 101);
        let (iv, ciphertext) = oracle.encrypt_random_plaintext();

        let mut plaintext = cbc_padding_oracle_attack(&ciphertext, &iv, &oracle).unwrap();
        pkcs7_unpad(&mut plaintext).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&plaintext),
            "000005I go crazy when I hear a cymbal".to_string()
        );
    }
}
