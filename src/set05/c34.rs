// Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
use num_bigint::BigUint;
use num_traits::Num;
use rand::SeedableRng;

use crate::{
    decrypt_aes_128_cbc, encrypt_aes_128_cbc, generate_modexp_keypair, Hasher, ModExpKeyPair,
    Mt19937, Sha1,
};

pub struct EncryptedMessage {
    pub msg: Vec<u8>,
    pub iv: [u8; 16],
}

pub struct Person {
    rng: Mt19937,
    keys: ModExpKeyPair,
    secret_message: String,
}

impl Person {
    pub fn new(mut rng: Mt19937, msg: String, p: BigUint, g: BigUint) -> Self {
        let keys = Self::generate_keys(&mut rng, p, g);
        Self {
            rng,
            keys,
            secret_message: msg,
        }
    }

    pub fn encrypt_message(&mut self, public_key: &BigUint) -> EncryptedMessage {
        let session_key = self.generate_session_key(public_key);
        let aes_key: [u8; 16] = Sha1::digest_message(&session_key.to_bytes_be())[..16]
            .try_into()
            .unwrap();
        let iv: [u8; 16] = std::array::from_fn(|_| self.rng.generate_in_range(0, 255) as u8);
        EncryptedMessage {
            msg: encrypt_aes_128_cbc(self.secret_message.as_bytes(), &aes_key, &iv),
            iv,
        }
    }

    pub fn p(&self) -> BigUint {
        self.keys.p.clone()
    }

    pub fn public_key(&self) -> BigUint {
        self.keys.pub_key.clone()
    }

    pub fn recv_g(&mut self, g: BigUint) {
        self.keys = Self::generate_keys(&mut self.rng, self.keys.p.clone(), g);
    }

    fn generate_keys(rng: &mut Mt19937, p: BigUint, g: BigUint) -> ModExpKeyPair {
        let big_rng_seed: [u8; 32] = std::array::from_fn(|_| rng.generate_in_range(0, 255) as u8);
        let mut big_rng = rand::rngs::StdRng::from_seed(big_rng_seed);
        generate_modexp_keypair(p, g, &mut big_rng)
    }

    fn generate_session_key(&self, public_key: &BigUint) -> BigUint {
        public_key.modpow(&self.keys.priv_key, &self.keys.p)
    }
}

pub fn simulate_dh_parameter_injection_attack(
    alice: &mut Person,
    bob: &mut Person,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Alice sends her public key to Bob, but it's intercepted by the attacker.
    // The attacker sends a spoofed key on to Bob. This spoofed key equals 'p',
    // which was used in the key-pair generation (and is public).
    let spoofed_key = BigUint::from_str_radix(
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
    .unwrap();

    // Bob receives the spoofed key and uses it to generate a session key.
    // He uses the session key to encrypt a message and sends it to Alice.
    let bobs_message = bob.encrypt_message(&spoofed_key);

    // The attacker intercepts Bob's message and can now decrypt it.
    // Consider how the session key was derived; let 'b' be Bob's private key,
    // and 'A' be Alice's public key:
    //  s = SHA1(A ^ b mod p), but we've spoofed A such that A = p
    //    = SHA1(p ^ b mod p)
    //    = SHA1(0)
    // Hence the session key was SHA1(0)!
    let forced_key: [u8; 16] = Sha1::digest_message(&[0])[..16].try_into().unwrap();
    let bob_recovered_msg = decrypt_aes_128_cbc(&bobs_message.msg, &forced_key, &bobs_message.iv)?;

    // We can do similar to recover Alice's message.
    let alices_message = alice.encrypt_message(&spoofed_key);
    let alice_recovered_msg =
        decrypt_aes_128_cbc(&alices_message.msg, &forced_key, &alices_message.iv)?;

    Ok((alice_recovered_msg, bob_recovered_msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_recovered_using_mitm_parameter_injection_attack() {
        let p = BigUint::from_str_radix(
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
        .unwrap();
        let g = BigUint::from(2u64);
        let mut alice = Person::new(
            Mt19937::new(101),
            "Vive la resistance".to_string(),
            p.clone(),
            g.clone(),
        );
        let mut bob = Person::new(
            Mt19937::new(101),
            "Vive la France".to_string(),
            p.clone(),
            g.clone(),
        );

        let (a, b) = simulate_dh_parameter_injection_attack(&mut alice, &mut bob).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a),
            "Vive la resistance".to_string(),
        );
        assert_eq!(String::from_utf8_lossy(&b), "Vive la France".to_string());
    }
}
