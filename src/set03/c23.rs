use crate::Mt19937;

pub fn clone_mt19937_from_output(rng: &mut Mt19937) -> Mt19937 {
    let state: [u32; 624] = std::array::from_fn(|_| untemper(rng.generate()));
    Mt19937::new_from_state(state)
}

fn untemper(value: u32) -> u32 {
    const U: u32 = 11;
    const S: u32 = 7;
    const T: u32 = 15;
    const L: u32 = 18;
    const B: u32 = 0x9d2c5680;
    const C: u32 = 0xefc60000;

    let mut v = invert_right_shift_xor(value, L);
    v = invert_left_shift_and_xor(v, T, C);
    v = invert_left_shift_and_xor(v, S, B);
    invert_right_shift_xor(v, U)
}

// Here we're reversing the operation:
//      x = y ^ (y >> L):
// Bitwise this gives us:
//      x[i] = y[i] ^ y[i - L]
//   -> y[i] = x[i] ^ y[i - L]
// When we shift Y right by L, the most significant L bits are 0, which means
// the most significant L bits of x are y ^ 0 = y.
// So we have:
//   for i < L:
//      y[i] = x[i]
//   and, for i >= L:
//      y[i] = x[i] ^ y[i - L]
//
// Note that index 0 is the most significant bit.
fn invert_right_shift_xor(x: u32, shift: u32) -> u32 {
    let mut y = x;
    for i in (0..(32 - shift)).rev() {
        let recovered_bit = (y >> (i + shift)) & 1;
        y ^= recovered_bit << i;
    }
    y
}

// Here we're reversing the operation:
//     x = y ^ ((y << T) & C)
// Bitwise, this is:
//     x[i] = y[i] ^ (y[i + T] & C[i])
// When we shift y left by T, the T least significant bits are 0, hence
// for i < T:
//     x[i] = y[i] ^ (0 & C[i])
//  -> y[i] = x[i]
// and, for i >= T:
//     y[i] = x[i] ^ (y[i + T] & C[i])
fn invert_left_shift_and_xor(x: u32, shift: u32, and_op: u32) -> u32 {
    let mut y = x;
    for i in shift..32 {
        let recovered_bit = y >> (i - shift);
        let and_bit = and_op >> i;
        y ^= ((recovered_bit & and_bit) & 1) << i;
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_mt19937_from_rng_copies_rng_state() {
        let mut base_rng = Mt19937::new(101);

        let mut new_rng = clone_mt19937_from_output(&mut base_rng);

        for _ in 0..624 {
            assert_eq!(new_rng.generate(), base_rng.generate());
        }
    }
}
