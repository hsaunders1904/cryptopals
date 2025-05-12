use reqwest::StatusCode;

const HMAC_DIGEST_SIZE: usize = 20;

pub async fn hmac_sha1_timing_attack_with_rounds(
    file: &str,
    address: &str,
    n_rounds: usize,
) -> Result<[u8; HMAC_DIGEST_SIZE], [u8; HMAC_DIGEST_SIZE]> {
    let mut candidate_signature = [0u8; 20];

    for i in 0..candidate_signature.len() {
        let mut max_time: u128 = 0;
        let mut timings = [(0, 0); u8::MAX as usize + 1];
        for (candidate_byte, request_duration) in (0..=u8::MAX).zip(timings.iter_mut()) {
            candidate_signature[i] = candidate_byte;
            let signature_hex = bytes_to_hex(&candidate_signature);
            let uri = format!("{}/test?file={}&signature={}", address, file, signature_hex);

            let mut times = Vec::new();
            for _ in 0..n_rounds {
                let req_start = std::time::Instant::now();
                let req = reqwest::get(uri.clone()).await.unwrap();
                let duration = std::time::Instant::now()
                    .duration_since(req_start)
                    .as_micros();
                if req.status() == StatusCode::OK {
                    return Ok(candidate_signature);
                }
                times.push(duration);
            }

            let median_duration = trimmed_mean(&times, 0.20);
            *request_duration = (median_duration, candidate_byte);
            max_time = max_time.max(median_duration);
        }
        candidate_signature[i] = timings.iter().max().unwrap().1;
        println!("candidate_signature: {:?}", candidate_signature);
    }
    Err(candidate_signature)
}

fn trimmed_mean(values: &[u128], trim_percent: f32) -> u128 {
    let mut v = values.to_vec();
    v.sort();
    let trim = (v.len() as f32 * trim_percent) as usize;
    let trimmed = &v[trim..v.len() - trim];
    trimmed.iter().copied().sum::<u128>() / trimmed.len() as u128
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .fold(String::new(), |s, hb| s + &hb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{random_bytes_with_seed, server, HmacSha1};

    // This takes a long time (like hours), so skip it when running tests.
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn hmac_sha1_timing_attack_generates_valid_mac_for_message_with_short_delay() {
        let key = random_bytes_with_seed::<64>(101);
        let compare_delay = std::time::Duration::from_millis(5);
        let request_handler = server::HmacSha1RequestHandler::new(&key, compare_delay);
        let addr = server::spawn_server("127.0.0.1:9001", &request_handler).await;
        let file = "file";
        let n_rounds = 10;

        let expected_mac = HmacSha1::digest_message(&key, file.as_bytes());
        println!("expected_mac: {:?}", expected_mac);
        let mac = hmac_sha1_timing_attack_with_rounds(file, addr.as_str(), n_rounds).await;

        assert_eq!(mac, Ok(expected_mac));
    }
}
