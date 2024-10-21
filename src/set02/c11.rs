/// An ECB/CBC detection oracle
use crate::mt19973::Mt19937;

pub fn random_key<const N: usize>() -> [u8; N] {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH.into())
        .unwrap()
        .as_nanos() as u32;
    let mut rng = Mt19937::new(seed);
    let mut key = [0u8; N];
    key.iter_mut()
        .for_each(|byte| *byte = random_byte(&mut rng));
    key
}

fn random_byte(rng: &mut Mt19937) -> u8 {
    let u32_val = rng.generate();
    (u32_val & 0b11111111) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_key_generates_different_bytes() {
        let key_1 = random_key::<16>();
        let key_2 = random_key::<16>();

        assert_ne!(key_1, key_2);
    }
}
