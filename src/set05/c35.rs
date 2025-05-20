// Implement DH with negotiated groups, and break with malicious "g" parameters

use crate::{decrypt_aes_128_cbc, Person, Sha1};

use num_bigint::BigUint;

pub enum MaliciousG {
    One,       // g = 1
    P,         // g = p
    PMinusOne, // g = p - 1
}

impl MaliciousG {
    fn value_from_p(&self, p: &BigUint) -> BigUint {
        match self {
            MaliciousG::One => BigUint::from(1u64),
            MaliciousG::P => p.clone(),
            MaliciousG::PMinusOne => p - 1u64,
        }
    }

    fn possible_shared_secrets(&self, p: &BigUint) -> Vec<Vec<u8>> {
        // Here we enumerate what the forced shared secrets given our value of
        // g.
        // Consider the derivation of Alice's shared secret, let 'a' be Alice's
        // private key, and 'B' and 'b' be Bob's public and private keys:
        //   s = B ^ a mod p, where
        //   B = g ^ b mod p
        match self {
            MaliciousG::One => {
                // We've set g := 1, hence
                //    B = 1 ^ b mod p
                //      = 1
                // Hence, Alice's shared secret 's' is derived using:
                //  s = B ^ a mod p
                //    = 1
                vec![vec![1]]
            }
            MaliciousG::P => {
                // We've set g := p, hence
                //    B = p ^ b mod p
                //      = 0
                // Hence, Alice's shared secret 's' is derived using:
                //  s = B ^ a mod p
                //    = 0
                vec![vec![0]]
            }
            MaliciousG::PMinusOne => {
                // We've set g = p - 1, hence
                //   B = (p - 1) ^ b mod p    (1)
                //
                // Note the identity:
                //
                //   (p − 1) ≡ (-1) mod p
                //   => (p - 1) ^ a ≡ ((-1) ^ a) mod p
                //
                // Hence, from (1):
                //
                //   B = ((-1) ^ b) mod p
                //     =  p - 1 if b is odd
                //     =  1     if b is even
                //
                // Therefore
                //   s = (1 ^ a) mod p       = 1
                // or
                //   s = ((p - 1) ^ a) mod p = p - 1
                vec![vec![1], (p - 1u64).to_bytes_be()]
            }
        }
    }
}

pub fn simulate_dh_g_injection_attack(
    alice: &mut Person,
    bob: &mut Person,
    malicious_g: MaliciousG,
) -> Result<Vec<u8>, String> {
    // Alice sends 'p' and 'g' to Bob. However, the attacker intercepts these
    // and forwards a spoofed 'g' on to Bob.
    let spoofed_g = malicious_g.value_from_p(&alice.p());
    bob.recv_g(spoofed_g);

    // Alice and Bob then exchange public keys and generate a session AES key.
    // Note that because Alice and Bob have different values for g, they
    // will not generate the same session key, so will not be able to
    // communicate.
    let bob_pub_key = bob.public_key();

    // Alice sends an encrypted message to Bob.
    let alices_message = alice.encrypt_message(&bob_pub_key);

    // The attacker can intercept the message and decrypt it.
    for shared_secret in malicious_g.possible_shared_secrets(&alice.p()) {
        let digest = Sha1::digest_message(&shared_secret);
        let aes_key: [u8; 16] = digest[..16].try_into().unwrap();
        if let Ok(decrypted) =
            decrypt_aes_128_cbc(&alices_message.msg, &aes_key, &alices_message.iv)
        {
            return Ok(decrypted);
        }
    }
    Err("Failed to recover message".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mt19937;

    use num_traits::Num;
    use std::sync::LazyLock;

    static P: LazyLock<BigUint> = LazyLock::new(|| {
        BigUint::from_str_radix(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
            e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
            3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
            6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
            24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
            c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
            bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
            fffffffffffff",
            16,
        )
        .unwrap()
    });

    fn setup_people() -> (Person, Person) {
        let g = BigUint::from(2u64);
        let alice = Person::new(
            Mt19937::new(2),
            "Vive la resistance".to_string(),
            P.clone(),
            g.clone(),
        );
        let bob = Person::new(
            Mt19937::new(3),
            "Vive la France".to_string(),
            P.clone(),
            g.clone(),
        );
        (alice, bob)
    }

    #[test]
    fn simulate_dh_g_eq_1_injection_attack_recovers_message() {
        let (mut alice, mut bob) = setup_people();

        let a_msg = simulate_dh_g_injection_attack(&mut alice, &mut bob, MaliciousG::One).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a_msg),
            "Vive la resistance".to_string(),
        );
    }

    #[test]
    fn simulate_dh_g_eq_p_injection_attack_recovers_message() {
        let (mut alice, mut bob) = setup_people();

        let a_msg = simulate_dh_g_injection_attack(&mut alice, &mut bob, MaliciousG::P).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a_msg),
            "Vive la resistance".to_string(),
        );
    }

    #[test]
    fn simulate_dh_g_eq_p_minus_1_injection_attack_recovers_message() {
        let (mut alice, mut bob) = setup_people();

        let a_msg =
            simulate_dh_g_injection_attack(&mut alice, &mut bob, MaliciousG::PMinusOne).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a_msg),
            "Vive la resistance".to_string(),
        );
    }
}
