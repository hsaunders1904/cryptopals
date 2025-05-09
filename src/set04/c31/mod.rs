// Implement and break HMAC-SHA1 with an artificial timing leak
pub mod server;

use futures::future::join_all;
use reqwest::StatusCode;

const HMAC_DIGEST_SIZE: usize = 20;

pub async fn hmac_sha1_timing_attack(
    file: &str,
    address: &str,
    n_workers: usize,
) -> Option<[u8; HMAC_DIGEST_SIZE]> {
    let mut signature = [0u8; HMAC_DIGEST_SIZE];

    for i in 0..HMAC_DIGEST_SIZE {
        let mut best_byte = 0u8;
        let mut best_duration = 0u128;

        let candidates: Vec<u8> = (0..=255).collect();
        for chunk in candidates.chunks(256 / n_workers) {
            let mut tasks = Vec::with_capacity(chunk.len());

            for &candidate in chunk {
                let mut sig_try = signature;
                sig_try[i] = candidate;
                let hex_sig = bytes_to_hex(&sig_try);
                let uri = format!("{}/test?file={}&signature={}", address, file, hex_sig);

                let task = tokio::spawn(async move {
                    let start = tokio::time::Instant::now();
                    let response = reqwest::get(&uri).await.ok();
                    let duration = start.elapsed().as_millis();
                    (candidate, duration, response)
                });

                tasks.push(task);
            }

            let results = join_all(tasks).await;
            for res in results.into_iter().flatten() {
                if let (candidate, duration, Some(response)) = res {
                    if response.status() == StatusCode::OK {
                        let mut found = signature;
                        found[i] = candidate;
                        return Some(found);
                    }

                    if duration > best_duration {
                        best_duration = duration;
                        best_byte = candidate;
                    }
                }
            }
        }

        signature[i] = best_byte;
        println!("candidate_signature: {:?}", signature);
    }

    None
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_valid_signature() {
        // 8 worker threads to match the number of tokio threads. If this isn't
        // exact, requests end up queuing, which completely ruins the timing of
        // the requests.
        let worker_threads = 8;
        let key = random_bytes_with_seed::<64>(101);
        let compare_delay = std::time::Duration::from_millis(50);
        let request_handler = server::HmacSha1RequestHandler::new(&key, compare_delay);
        let addr = server::spawn_server("127.0.0.1:9000", &request_handler).await;
        let file = "file";

        let expected_mac = HmacSha1::digest_message(&key, file.as_bytes());
        println!("expected_mac: {:?}", expected_mac);

        let mac = hmac_sha1_timing_attack(file, addr.as_str(), worker_threads)
            .await
            .unwrap();

        assert_eq!(mac, expected_mac);
    }
}
