// CBC bitflipping attacks
use crate::{decrypt_aes_128_cbc, encrypt_aes_128_cbc, xor_slices};

pub fn forge_admin_cbc_ciphertext_with_bit_flipping_attack(oracle: &CbcQueryOracle) -> Vec<u8> {
    // Define a block of repeated bytes. This is the block before the block
    // we're trying to forge. We will flip the bits in this block in order to
    // influence the bits in the subsequent block.
    let garbage_block = b"G".repeat(16);
    let forgery_block = b"F".repeat(16);
    // Our plaintext has 3 blocks and reads:
    //    GGGGGGGGGGGGGGGG FFFFFFFFFFFFFFFF =isvalid@mail.uk
    // Eventually, using our bit flipping attack, we want our forged
    // (decrypted) ciphertext to read:
    //    <garbage bytes> ;admin=true;mail =anemail@mail.uk
    let plaintext = [
        garbage_block,
        forgery_block.clone(),
        b"=anemail@mail.uk".to_vec(),
    ]
    .concat();
    let ciphertext = oracle.encrypt(&plaintext);
    // Now XOR the 'flip block' of our genuine ciphertext with the XOR of our
    // 'flip block' and our forgery. To see how this works, notice that, when
    // decrypting in CBC, the second block (the block we're trying to forge) is
    // computed using:
    //    P2 = Dec(C2) ⊕ C1
    // Let F be our forgery, then we want
    //    F = P2 = C1 ⊕ Dec(C2).
    // Hence, if we make
    //    C1 := Dec(C2) ⊕ F,
    // then we can create the desired forgery.
    let forgery = b";admin=true;mail";
    let forgery_xor = xor_slices(&forgery_block, forgery).unwrap();
    let mut ciphertext_xor = [
        vec![0u8; CbcQueryOracle::QUERY_PREFIX.len()],
        forgery_xor.to_vec(),
    ]
    .concat();
    ciphertext_xor.resize(ciphertext.len(), 0u8);

    xor_slices(&ciphertext, &ciphertext_xor).unwrap()
}

pub struct CbcQueryOracle {
    key: [u8; 16],
    iv: [u8; 16],
}

impl CbcQueryOracle {
    const QUERY_PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const QUERY_SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let plaintext = [
            CbcQueryOracle::QUERY_PREFIX,
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
            CbcQueryOracle::QUERY_SUFFIX,
        ]
        .concat();
        encrypt_aes_128_cbc(&plaintext, &self.key, &self.iv)
    }

    pub fn decrypt_and_check_admin(&self, ciphertext: &[u8]) -> bool {
        let plaintext = decrypt_aes_128_cbc(ciphertext, &self.key, &self.iv).unwrap();
        plaintext
            .split(|x| *x == b';')
            .any(|args| args == b"admin=true")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random_bytes;

    #[test]
    fn forges_valid_admin_ciphertext() {
        let key = random_bytes::<16>();
        let iv = random_bytes::<16>();
        let oracle = CbcQueryOracle::new(key, iv);

        let admin_forgery = forge_admin_cbc_ciphertext_with_bit_flipping_attack(&oracle);

        assert!(oracle.decrypt_and_check_admin(&admin_forgery));
    }
}
