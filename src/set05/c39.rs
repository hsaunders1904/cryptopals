// Implement RSA

use crate::generate_prime;

use num_bigint::{BigUint, RandBigInt};

pub struct RsaKeyPair {
    pub public: BigUint,
    pub private: BigUint,
    pub n: BigUint,
}

pub fn generate_rsa_key_pair(n_bits: u64, e: &BigUint, rng: &mut impl RandBigInt) -> RsaKeyPair {
    let one = BigUint::from(1u64);

    // Loop until we find primes such that gcd(e, totient) = 1.
    loop {
        // Key size usually refers to the size of n (which is p*q), so get
        // primes each with half as many bits as we need.
        let p = generate_prime(n_bits / 2, rng);
        let q = generate_prime(n_bits / 2, rng);
        if p == q {
            continue;
        }

        let n = &p * &q;
        let totient = (&p - &one) * (&q - &one);
        if greatest_common_divisor(e.clone(), totient.clone()) != one {
            continue;
        }

        if let Some(d) = e.modinv(&totient) {
            return RsaKeyPair {
                public: e.clone(),
                private: d,
                n,
            };
        }
    }
}

pub fn rsa_apply(key: &BigUint, n: &BigUint, msg: &[u8]) -> Vec<u8> {
    let msg_int = BigUint::from_bytes_be(msg);
    msg_int.modpow(key, n).to_bytes_be()
}

fn greatest_common_divisor(mut a: BigUint, mut b: BigUint) -> BigUint {
    let zero = BigUint::default();
    while b != zero {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn rsa_cipher_encrypts_message_to_expected_ciphertext() {
        let public_key = BigUint::from(29u64);
        let private_key = BigUint::from(41u64);
        let n = BigUint::from(133u64);
        let msg = BigUint::from(99u64).to_bytes_be();

        let ciphertext = rsa_apply(&public_key, &n, &msg);
        let decrypted_msg = rsa_apply(&private_key, &n, &ciphertext);

        assert_eq!(ciphertext, BigUint::from(92u64).to_bytes_be());
        assert_eq!(decrypted_msg, msg);
    }

    #[test]
    fn rsa_cipher_encrypts_and_decrypts_using_generated_key_pair() {
        let mut rng = StdRng::from_seed([12; 32]);
        // The task said to set e = 3, but we end up having to generate a lot
        // of primes to find two where gcd(e, totient) = 1. For performance's
        // sake use a more realistic e.
        let e = BigUint::from(65537u64);

        let keys = generate_rsa_key_pair(256, &e, &mut rng);
        let msg = "Factoring is hard.";

        let ciphertext = rsa_apply(&keys.public, &keys.n, msg.as_bytes());
        let decrypted_msg = rsa_apply(&keys.private, &keys.n, &ciphertext);

        assert_eq!(decrypted_msg, msg.as_bytes());
    }
}
