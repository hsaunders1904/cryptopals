use crate::{generate_modexp_keypair, Hasher, HmacSha256, ModExpKeyPair, Sha256};

use num_bigint::BigUint;
use rand::{rngs::StdRng, RngCore};

use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Verifier {
    pub salt: [u8; 16],
    pub verifier: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordVerificationResponse {
    Ok,
    Failed,
}

#[derive(Debug, Clone)]
pub struct SrpServer {
    k: BigUint,
    verifiers: HashMap<String, Verifier>,
    rng: StdRng,
    keys: ModExpKeyPair,
}

impl SrpServer {
    pub fn new(g: BigUint, n_prime: BigUint, k: BigUint, mut rng: StdRng) -> Self {
        let keys = generate_modexp_keypair(n_prime, g, &mut rng);
        Self {
            k,
            verifiers: HashMap::default(),
            rng,
            keys,
        }
    }

    pub fn register_user(&mut self, id: &str, password: &str) {
        let mut salt = [0u8; 16];
        self.rng.fill_bytes(&mut salt);
        let x_h = Sha256::digest_message(&[&salt, password.as_bytes()].concat());
        let x = BigUint::from_bytes_be(&x_h);
        let verifier = self.keys.g.modpow(&x, &self.keys.p);
        self.verifiers
            .insert(id.to_string(), Verifier { salt, verifier });
    }

    pub fn send_user_key(&self, user_id: &str) -> Result<([u8; 16], BigUint), String> {
        let verifier = self.user_verifier(user_id)?;
        let big_b = (&self.k * &verifier.verifier + &self.keys.pub_key) % &self.keys.p;
        Ok((verifier.salt, big_b))
    }

    pub fn validate_session(
        &self,
        user_id: &str,
        user_pub_key: &BigUint,
        client_mac: &[u8],
    ) -> Result<PasswordVerificationResponse, String> {
        let expected_key = self.compute_session(user_id, user_pub_key)?;
        let salt = self.user_verifier(user_id)?.salt;
        let expected_mac = HmacSha256::digest_message(&expected_key, &salt);
        if client_mac == expected_mac {
            Ok(PasswordVerificationResponse::Ok)
        } else {
            Ok(PasswordVerificationResponse::Failed)
        }
    }

    fn compute_session(&self, user_id: &str, user_pub_key: &BigUint) -> Result<[u8; 32], String> {
        let verifier = self.user_verifier(user_id)?;
        let big_b = (&self.k * &verifier.verifier + &self.keys.pub_key) % &self.keys.p;
        let u_h =
            Sha256::digest_message(&[user_pub_key.to_bytes_be(), big_b.to_bytes_be()].concat());
        let u = BigUint::from_bytes_be(&u_h);
        let big_s = (user_pub_key * verifier.verifier.modpow(&u, &self.keys.p))
            .modpow(&self.keys.priv_key, &self.keys.p);
        Ok(Sha256::digest_message(&big_s.to_bytes_be()))
    }

    fn user_verifier(&self, user_id: &str) -> Result<&Verifier, String> {
        self.verifiers
            .get(user_id)
            .ok_or_else(|| format!("No user registered with id '{}'", user_id))
    }
}
