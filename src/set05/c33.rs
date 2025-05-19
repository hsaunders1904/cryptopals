// Implement Diffie-Hellman
use num_bigint::{BigUint, RandBigInt};

pub struct ModExpKeyPair {
    pub pub_key: BigUint,
    pub priv_key: BigUint,
}

pub fn generate_modexp_keypair<R: RandBigInt>(
    p: &BigUint,
    g: &BigUint,
    rng: &mut R,
) -> ModExpKeyPair {
    let priv_key = rng.gen_biguint(p.bits()).modpow(&BigUint::from(1u64), p);
    let pub_key = g.modpow(&priv_key, p);
    ModExpKeyPair { pub_key, priv_key }
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_traits::Num;
    use rand::SeedableRng;

    #[test]
    fn modexp_keypairs_can_be_used_to_generate_session_key() {
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
        let mut rng = rand::rngs::StdRng::from_seed([101; 32]);

        let alice_kp = generate_modexp_keypair(&p, &g, &mut rng);
        let bob_kp = generate_modexp_keypair(&p, &g, &mut rng);
        let alice_session_key = bob_kp.pub_key.modpow(&alice_kp.priv_key, &p);
        let bob_session_key = alice_kp.pub_key.modpow(&bob_kp.priv_key, &p);

        assert_eq!(alice_session_key, bob_session_key);
    }
}
