// Implement DH with negotiated groups, and break with malicious "g" parameters

use crate::{decrypt_aes_128_cbc, Person, Sha1};

use num_bigint::BigUint;

pub fn simulate_dh_g_eq_1_injection_attack(
    alice: &mut Person,
    bob: &mut Person,
) -> Result<Vec<u8>, String> {
    // Alice sends 'p' and 'g' to Bob. However, the attacker intercepts these
    // and forwards a spoofed 'g' on to Bob.
    let spoofed_g = BigUint::from(1u64);
    bob.recv_g(spoofed_g);

    // Alice and Bob then exchange public keys and generate a session AES key.
    // Note that because Alice and Bob have different values for g, they
    // will not generate the same session key, so will not be able to
    // communicate.
    let bob_pub_key = bob.public_key();

    // Consider the derivation of Alice's session key, let 'a' be Alice's private
    // key, and 'B' be Bob's public key:
    //  B = g ^ a mod p, where we've set g := 1
    //    = 1
    // Alice's session key 's' is derived using:
    //  s = SHA1(B ^ a mod p)[0:16]
    //    = SHA1(1)[0:16]

    // Alice sends an encrypted message to Bob.
    let alices_message = alice.encrypt_message(&bob_pub_key);

    // The attacker can intercept this and decrypt it.
    let forced_key: [u8; 16] = Sha1::digest_message(&[1])[..16].try_into().unwrap();
    let alice_recovered_message =
        decrypt_aes_128_cbc(&alices_message.msg, &forced_key, &alices_message.iv)?;

    Ok(alice_recovered_message)
}

pub fn simulate_dh_g_eq_p_injection_attack(
    alice: &mut Person,
    bob: &mut Person,
) -> Result<Vec<u8>, String> {
    // Alice sends 'p' and 'g' to Bob. However, the attacker intercepts these
    // and forwards a spoofed 'g' on to Bob.
    let spoofed_g = alice.p();
    bob.recv_g(spoofed_g);

    // Alice and Bob then exchange public keys and generate a session AES key.
    // Note that because Alice and Bob have different values for g, they
    // will not generate the same session key, so will not be able to
    // communicate.
    let bob_pub_key = bob.public_key();

    // Consider the derivation of Alice's session key, let 'a' be Alice's private
    // key, and 'B' be Bob's public key:
    //  B = g ^ a mod p, where we've set g := p
    //    = p ^ a mod p
    //    = 0
    // Alice's session key 's' is derived using:
    //  s = SHA1(0 ^ a mod p)[0:16]
    //    = SHA1(0)[0:16]

    // Alice sends an encrypted message to Bob.
    let alices_message = alice.encrypt_message(&bob_pub_key);

    // The attacker can intercept this and decrypt it.
    let forced_key: [u8; 16] = Sha1::digest_message(&[0])[..16].try_into().unwrap();
    let alice_recovered_message =
        decrypt_aes_128_cbc(&alices_message.msg, &forced_key, &alices_message.iv)?;

    Ok(alice_recovered_message)
}

pub fn simulate_dh_g_eq_p_minus_1_injection_attack(
    alice: &mut Person,
    bob: &mut Person,
) -> Result<Vec<u8>, String> {
    // Alice sends 'p' and 'g' to Bob. However, the attacker intercepts these
    // and forwards a spoofed 'g' on to Bob.
    let spoofed_g = alice.p() - 1u64;
    bob.recv_g(spoofed_g);

    // Alice and Bob then exchange public keys and generate a session AES key.
    // Note that because Alice and Bob have different values for g, they
    // will not generate the same session key, so will not be able to
    // communicate.
    let bob_pub_key = bob.public_key();

    // Consider the derivation of Alice's session key, let 'a' be Alice's
    // private key, and 'B' be Bob's public key:
    //
    //   B = g ^ a mod p, where we've set g := p - 1
    //     = (p - 1) ^ a mod p    (1)
    //
    // Note the identity:
    //
    //   (p − 1) ≡ (-1) mod p
    //   => (p - 1) ^ a ≡ ((-1) ^ a) mod p
    //
    // Hence, from (1):
    //
    //   B = ((-1) ^ a) mod p
    //     =  p - 1 if a is odd
    //     =  1     if a is even

    // Therefore, Alice's session key 's' is derived using either
    //   s = SHA1(p - 1)[0:16]
    // or
    //   s = SHA1(1)[0:16]

    // Alice sends an encrypted message to Bob.
    let alices_message = alice.encrypt_message(&bob_pub_key);

    // The attacker can intercept this and decrypt it.
    let forced_key: [u8; 16] = Sha1::digest_message(&(alice.p() - 1u64).to_bytes_le())[..16]
        .try_into()
        .unwrap();
    if let Ok(recovered_msg) =
        decrypt_aes_128_cbc(&alices_message.msg, &forced_key, &alices_message.iv)
    {
        return Ok(recovered_msg);
    }
    let forced_key2: [u8; 16] = Sha1::digest_message(&[1])[..16].try_into().unwrap();
    if let Ok(recovered_msg) =
        decrypt_aes_128_cbc(&alices_message.msg, &forced_key2, &alices_message.iv)
    {
        return Ok(recovered_msg);
    }
    Err("failed to recover message".to_string())
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

    #[test]
    fn simulate_dh_g_eq_1_injection_attack_recovers_message() {
        let default_g = BigUint::from(2u64);
        let mut alice = Person::new(
            Mt19937::new(101),
            "Vive la resistance".to_string(),
            P.clone(),
            default_g.clone(),
        );
        let mut bob = Person::new(
            Mt19937::new(101),
            "Vive la France".to_string(),
            P.clone(),
            default_g.clone(),
        );

        let a = simulate_dh_g_eq_1_injection_attack(&mut alice, &mut bob).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a),
            "Vive la resistance".to_string(),
        );
    }

    #[test]
    fn simulate_dh_g_eq_p_injection_attack_recovers_message() {
        let default_g = BigUint::from(2u64);
        let mut alice = Person::new(
            Mt19937::new(101),
            "Vive la resistance".to_string(),
            P.clone(),
            default_g.clone(),
        );
        let mut bob = Person::new(
            Mt19937::new(101),
            "Vive la France".to_string(),
            P.clone(),
            default_g.clone(),
        );

        let a = simulate_dh_g_eq_p_injection_attack(&mut alice, &mut bob).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a),
            "Vive la resistance".to_string(),
        );
    }

    #[test]
    fn simulate_dh_g_eq_p_minus_1_injection_attack_recovers_message() {
        let default_g = BigUint::from(2u64);
        let mut alice = Person::new(
            Mt19937::new(101),
            "Vive la resistance".to_string(),
            P.clone(),
            default_g.clone(),
        );
        let mut bob = Person::new(
            Mt19937::new(101),
            "Vive la France".to_string(),
            P.clone(),
            default_g.clone(),
        );

        let a = simulate_dh_g_eq_p_minus_1_injection_attack(&mut alice, &mut bob).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&a),
            "Vive la resistance".to_string(),
        );
    }
}
