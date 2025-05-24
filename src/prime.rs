// Functions related to identification and generation of prime numbers.

use crate::prime_tables::SMALL_ODD_PRIMES;

use num_bigint::{BigUint, RandBigInt};
use rand::rngs::StdRng;

const MILLER_RABIN_ROUNDS: u32 = 5;

pub fn is_likely_prime(candidate_prime: &BigUint, miller_rabin_rng: &mut StdRng) -> bool {
    let zero = BigUint::default();
    let one = BigUint::from(1u64);
    if candidate_prime == &zero || candidate_prime == &one {
        return false;
    }
    let two = BigUint::from(2u64);
    if candidate_prime == &two {
        return true;
    }

    if candidate_prime.modpow(&one, &two) == zero {
        return false;
    }

    for small_prime in SMALL_ODD_PRIMES {
        let x = BigUint::from(small_prime);
        if candidate_prime == &x {
            return true;
        }
        if candidate_prime.modpow(&one, &x) == zero {
            return false;
        }
    }

    miller_rabin(candidate_prime, MILLER_RABIN_ROUNDS, miller_rabin_rng)
}

fn miller_rabin(candidate_prime: &BigUint, n_rounds: u32, rng: &mut StdRng) -> bool {
    let zero = BigUint::default();
    let one = BigUint::from(1u64);
    let two = BigUint::from(2u64);

    let mut d: BigUint = candidate_prime - &one;
    let mut r = 0;
    while d.modpow(&one, &two) == zero {
        d /= &two;
        r += 1;
    }
    for _ in 0..n_rounds {
        let a = rng.gen_biguint_range(&two, &(candidate_prime - &two));
        let mut x = a.modpow(&d, candidate_prime);
        if x == one || x == candidate_prime - &one {
            continue;
        }
        for _ in 0..(r - 1) {
            x = x.modpow(&two, candidate_prime);
            if x == candidate_prime - &one {
                break;
            }
        }
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_traits::Num;
    use rand::SeedableRng;
    use rstest::rstest;

    #[rstest]
    #[case(BigUint::from(2u64))]
    #[case(BigUint::from(37u64))]
    #[case(BigUint::from_str_radix(
        "122918091607895345462109112013423411099284103879272281586\
        0819946412949055199827238447096054805339148543003066133719\
        9085275880150614723662649630584506204331", 10).unwrap())
    ]
    #[case(BigUint::from_str_radix(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
            e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
            3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
            6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
            24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
            c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
            bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
            fffffffffffff", 16).unwrap())]
    fn is_likely_prime_identifies_primes(#[case] prime: BigUint) {
        let mut rng = StdRng::from_seed([101; 32]);

        assert!(is_likely_prime(&prime, &mut rng));
    }

    #[rstest]
    #[case(BigUint::from(0u64))]
    #[case(BigUint::from(1u64))]
    #[case(BigUint::from(4u64))]
    #[case(BigUint::from(1024u64))]
    #[case(BigUint::from(1025u64))]
    fn is_likely_prime_identifies_non_primes(#[case] non_prime: BigUint) {
        let mut rng = StdRng::from_seed([101; 32]);

        assert!(!is_likely_prime(&non_prime, &mut rng));
    }
}
