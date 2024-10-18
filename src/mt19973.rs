/// MT19937 pseudo-random number generator

const N: usize = 624;
const M: usize = 397;
const W: u32 = 32;
const UMASK: u32 = 0xffffffff << (W - 1);
const LMASK: u32 = 0xffffffff >> 1;
const A: u32 = 0x9908b0df;
const U: u32 = 11;
const S: u32 = 7;
const T: u32 = 15;
const L: u32 = 18;
const B: u32 = 0x9d2c5680;
const C: u32 = 0xefc60000;
const F: u32 = 1812433253;

pub struct Mt19937 {
    state: [u32; N as usize],
    state_idx: usize,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        Self {
            state: Self::seed_state(seed),
            state_idx: 0,
        }
    }

    pub fn generate(&mut self) -> u32 {
        let k: usize = self.state_idx;
        let mut j: usize = k.checked_sub(N - 1).unwrap_or(k + 1);
        let mut x: u32 = (self.state[k] & UMASK) | (self.state[j] & LMASK);
        let mut x_a: u32 = x >> 1;
        if x & 1 > 0 {
            x_a ^= A;
        }
        j = k.checked_sub(N - M).unwrap_or(k + M);
        x = self.state[j] ^ x_a;
        self.state[k] = x;
        self.state_idx = (k + 1) % N;

        // Tempering
        let mut y: u32 = x ^ (x >> U);
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^ (y >> L)
    }

    fn seed_state(mut seed: u32) -> [u32; N] {
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            seed = F.wrapping_mul(seed ^ (seed >> (W - 2))) + i as u32;
            state[i] = seed;
        }
        state
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(0, [2357136044, 2546248239, 3071714933])]
    #[case(19650218, [2325592414, 482149846, 4177211283])]
    #[case(101, [2217915231, 2373142027, 2450998609])]
    fn mt19937_returns_correct_value_for_seed(#[case] seed: u32, #[case] values: [u32; 3]) {
        let mut rng = Mt19937::new(seed);

        assert_eq!(rng.generate(), values[0]);
        assert_eq!(rng.generate(), values[1]);
        assert_eq!(rng.generate(), values[2]);
    }
}
