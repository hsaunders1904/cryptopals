// CTR bitflipping

use crate::aes_128_ctr;

pub fn forge_admin_ctr_ciphertext_with_bit_flipping_attack(
    oracle: &CtrQueryOracle,
) -> Option<Vec<u8>> {
    // Discover the length of the query prefix
    let c_0 = oracle.encrypt(b"0");
    let c_1 = oracle.encrypt(b"1");
    let prefix_len = c_0
        .iter()
        .zip(c_1.iter())
        .enumerate()
        .find(|(_, (a, b))| a != b)?
        .0;

    // By querying the oracle with some message, M, we can recover the part of
    // the XOR key stream used in the encryption:
    //   C = AES_k(nonce|ctr) ⊕ M
    //     -> AES_k(nonce|ctr) = C ⊕ M
    // With this, we can create a valid ciphertext forgery C_F with equal
    // length to M, decrypting to a plaintext forgery, F, by:
    //   C_F := M ⊕ F ⊕ C
    // Which when decrypted, will give us:
    //   AES_k(nonce|ctr) ⊕ C_F
    //     = AES_k(nonce|ctr) ⊕ M ⊕ F ⊕ C
    //     = AES_k(nonce|ctr) ⊕ M ⊕ F ⊕ (AES_k(nonce|ctr) ⊕ M)
    //     = F

    let plaintext_forgery = b";admin=true";
    let message = b"A".repeat(plaintext_forgery.len());
    let mut ciphertext = oracle.encrypt(&message);

    let forgery_block = message
        .iter()
        .zip(plaintext_forgery.iter())
        .map(|(p, f)| p ^ f);

    ciphertext[prefix_len..(prefix_len + message.len())]
        .iter_mut()
        .zip(forgery_block)
        .for_each(|(c, f)| *c ^= f);
    Some(ciphertext)
}

pub struct CtrQueryOracle {
    key: [u8; 16],
    nonce: [u8; 8],
    initial_value: u64,
}

impl CtrQueryOracle {
    const QUERY_PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const QUERY_SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    pub fn new(key: [u8; 16], nonce: [u8; 8], initial_value: u64) -> Self {
        Self {
            key,
            nonce,
            initial_value,
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let plaintext = [
            CtrQueryOracle::QUERY_PREFIX,
            msg.iter()
                .filter_map(|el| {
                    if [b'"', b';'].contains(el) {
                        None
                    } else {
                        Some(*el)
                    }
                })
                .collect::<Vec<u8>>()
                .as_slice(),
            CtrQueryOracle::QUERY_SUFFIX,
        ]
        .concat();
        aes_128_ctr(&plaintext, &self.key, &self.nonce, self.initial_value)
    }

    pub fn decrypt_and_check_admin(&self, ciphertext: &[u8]) -> bool {
        let plaintext = aes_128_ctr(ciphertext, &self.key, &self.nonce, self.initial_value);
        plaintext
            .split(|x| *x == b';')
            .any(|args| args == b"admin=true")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random_bytes_with_seed;

    #[test]
    fn forge_admin_ctr_ciphertext_with_bit_flipping_attack_forges_admin_query() {
        let key = random_bytes_with_seed::<16>(101);
        let nonce = random_bytes_with_seed::<8>(102);
        let initial_value = 0u64;
        let oracle = CtrQueryOracle::new(key, nonce, initial_value);

        let admin_forgery = forge_admin_ctr_ciphertext_with_bit_flipping_attack(&oracle).unwrap();

        assert!(oracle.decrypt_and_check_admin(&admin_forgery));
    }
}
