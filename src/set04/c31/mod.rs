pub mod server;

use reqwest::StatusCode;

pub async fn hmac_sha1_timing_attack(file: &str, address: &str) -> Option<[u8; 20]> {
    let mut candidate_signature = [0u8; 20];

    for i in 0..candidate_signature.len() {
        let mut max_time: u128 = 0;
        let mut timings = [(0, 0); u8::MAX as usize + 1];
        for (candidate_byte, request_duration) in (0..=u8::MAX).zip(timings.iter_mut()) {
            candidate_signature[i] = candidate_byte;
            let signature_hex = bytes_to_hex(&candidate_signature);
            let uri = format!("{}/test?file={}&signature={}", address, file, signature_hex);

            let req_start = std::time::Instant::now();
            let req = reqwest::get(uri).await.unwrap();
            let duration = std::time::Instant::now()
                .duration_since(req_start)
                .as_micros();
            if req.status() == StatusCode::OK {
                return Some(candidate_signature);
            }

            if max_time != 0 && duration > max_time + 25_000 {
                *request_duration = (duration, candidate_byte);
                break;
            }
            *request_duration = (duration, candidate_byte);
            max_time = max_time.max(duration);
        }
        candidate_signature[i] = timings.iter().max().unwrap().1;
        println!("candidate_signature: {:?}", candidate_signature);
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

    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    async fn spawn_test_server() -> String {
        let app = Router::new().route("/test", get(server::handle_request));
        let listener = TcpListener::bind("127.0.0.1:9000").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_valid_signature() {
        let addr = spawn_test_server().await;

        use crate::HmacSha1;

        let expected_mac = HmacSha1::digest_message(b"secret", b"file");
        println!("expected_mac: {:?}", expected_mac);
        // [255, 121, 211, 89, 84, 173, 130, 202, 217, 49, 64, 47, 142, 184, 129, 225, 119, 13, 83, 221]

        let mac = hmac_sha1_timing_attack("file", addr.as_str())
            .await
            .unwrap();

        assert_eq!(mac, expected_mac);
    }
}
