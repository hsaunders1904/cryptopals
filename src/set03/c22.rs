use crate::Mt19937;

const MAX_ATTEMPTS: usize = 10_000;

/// Find the seed used to generate the given random number.
/// We assume the MT19937 RNG was seeded with a monotonically increasing counter
/// (e.g., UNIX timestamp) and we assume the counter has increased by a
/// relatively small amount since the random number was generated.
pub fn break_time_dependent_mt19937_seed(target_random_number: u32, current_counter: u32) -> u32 {
    let mut candidate_seed = current_counter + 1;
    let mut rng = Mt19937::new(candidate_seed);
    let mut n_attempts = 0;
    while rng.generate() != target_random_number && n_attempts < MAX_ATTEMPTS {
        candidate_seed -= 1;
        rng = Mt19937::new(candidate_seed);
        n_attempts += 1;
    }
    candidate_seed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_current_time() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap()
    }

    #[test]
    fn break_mt19937_seed_recovers_original_seed() {
        // This is the time at which we sent our initial request for a random
        // number.
        let initial_time = get_current_time() - 1001;
        // Simulate 40 - 1001 seconds passing for us to receive the random
        // number.
        let timestamp_seed =
            Mt19937::new(0).generate_in_range(initial_time + 40, initial_time + 1000);
        let random_number = Mt19937::new(timestamp_seed).generate();

        let cracked_seed = break_time_dependent_mt19937_seed(random_number, get_current_time());

        assert_eq!(cracked_seed, timestamp_seed);
    }
}
