// Implement an E=3 RSA Broadcast attack

use num_bigint::BigUint;
use rand::rngs::StdRng;

use crate::{generate_rsa_key_pair, rsa_apply};

pub struct RsaOracle {
    secret: Vec<u8>,
    rng: StdRng,
}

impl RsaOracle {
    pub fn new(secret: Vec<u8>, rng: StdRng) -> Self {
        Self { secret, rng }
    }

    pub fn encrypt_secret_message(&mut self) -> (Vec<u8>, BigUint, BigUint) {
        let keys = generate_rsa_key_pair(256, &BigUint::from(3u64), &mut self.rng);
        let ciphertext = rsa_apply(&keys.public, &keys.n, &self.secret);
        (ciphertext, keys.public, keys.n)
    }
}

pub fn rsa_broadcast_attack(oracle: &mut RsaOracle) -> Vec<u8> {
    // The attacker gets the oracle to encrypt the same secret with 3 different
    // public keys.
    let (c_1, _, n_1) = oracle.encrypt_secret_message();
    let (c_2, _, n_2) = oracle.encrypt_secret_message();
    let (c_3, _, n_3) = oracle.encrypt_secret_message();

    // The attacker can now use the Chinese Remainder Theorem (CRT) to solve
    // for the message.
    //
    // The attack works because each encryption uses the same e = 3, and
    // a different modulus n_i. Each ciphertext is:
    //
    //   c_i = m ** 3 mod n_i
    //
    // where m is the plaintext.
    //
    // If we collect e ciphertexts, in this case, 3 of them, we can use the
    // Chinese Remainder Theorem (CRT) to reconstruct m ** 3 modulo N, where:
    //
    //   N = n_1 * n_2 * n_3
    //
    // If all m < n_i, then m ** 3 < N, we can reconstruct the value of m ** 3
    // without a modular wrap occurring. From that, we can cube root to recover
    // m. For larger values of e you'll need more ciphertexts.
    let big_n = &n_1 * &n_2 * &n_3;
    let n_i = [&n_1, &n_2, &n_3];

    // Compute N_i = N / n_i for each modulus
    let big_n_i = n_i.map(|n| &big_n / n);

    // Compute the modular inverse y_i = (N_i ** -1) mod n_i
    let y_i = big_n_i
        .iter()
        .zip(n_i.iter())
        .map(|(big_n, n)| big_n.modinv(n).unwrap());

    // Reconstruct m ** 3 using:
    //   m ** 3 = SUM_i(c_i * N_i * y_i) mod N
    let p_cubed: BigUint = [&c_1, &c_2, &c_3]
        .iter()
        .map(|c| BigUint::from_bytes_be(c))
        .zip(big_n_i.iter())
        .zip(y_i)
        .map(|((c, big_n), y)| c * big_n * y)
        .sum::<BigUint>()
        % &big_n;
    (p_cubed).cbrt().to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;

    #[test]
    fn rsa_broadcast_attack_recovers_plaintext_from_oracle() {
        let rng = StdRng::from_seed([101; 32]);
        let secret = b"The admin password is 'ILoveJS'".to_vec();
        let mut oracle = RsaOracle::new(secret.clone(), rng);

        let broken_plaintext = rsa_broadcast_attack(&mut oracle);

        assert_eq!(broken_plaintext, secret);
    }
}
