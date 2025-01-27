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
    state: [u32; N],
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

    /// Generate a u32 in the given range (inclusive).
    pub fn generate_in_range(&mut self, min: u32, max: u32) -> u32 {
        if min == max {
            return min;
        }
        let real_min = min.min(max);
        let real_max = min.max(max) + 1;
        let frac = self.generate_float();
        real_min + ((real_max - real_min) as f32 * frac) as u32
    }

    /// Generate a float in range [0, 1].
    pub fn generate_float(&mut self) -> f32 {
        self.generate() as f32 / u32::MAX as f32
    }

    fn seed_state(mut seed: u32) -> [u32; N] {
        let mut state = [0; N];
        state[0] = seed;
        for (i, state_element) in state.iter_mut().enumerate().skip(1) {
            seed = F.wrapping_mul(seed ^ (seed >> (W - 2))) + i as u32;
            *state_element = seed;
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(0, [2357136044, 2546248239, 3071714933])]
    #[case(19650218, [2325592414, 482149846, 4177211283])]
    #[case(101, [2217915231, 2373142027, 2450998609])]
    fn generate_returns_correct_value_for_seed(#[case] seed: u32, #[case] values: [u32; 3]) {
        let mut rng = Mt19937::new(seed);

        assert_eq!(rng.generate(), values[0]);
        assert_eq!(rng.generate(), values[1]);
        assert_eq!(rng.generate(), values[2]);
    }

    #[test]
    fn generate_in_range_returns_value_in_range_with_equal_probability() {
        let mut rng = Mt19937::new(19650218);

        let mut counts = [0usize; 12];
        for _ in 0..2000 {
            let v = rng.generate_in_range(1, 12);
            assert!(v >= 1);
            assert!(v <= 12);
            counts[v as usize - 1] += 1;
        }

        let p = 1. / 12.;
        let n = counts.iter().sum::<usize>();
        let chi_squared = counts
            .iter()
            .map(|x| *x as f64 / n as f64)
            .map(|o| (o - p).powi(2) / p)
            .sum::<f64>()
            / (n - 1) as f64;
        assert!(chi_squared < 1e-5);
    }
}
