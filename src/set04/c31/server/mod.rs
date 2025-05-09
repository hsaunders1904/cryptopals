use crate::{hex_to_bytes, HmacSha1};

use axum::{extract::Query, http::StatusCode, response::IntoResponse};

use std::collections::HashMap;

fn insecure_compare(bytes_a: &[u8], bytes_b: &[u8]) -> bool {
    for (&a, &b) in bytes_a.iter().zip(bytes_b) {
        std::thread::sleep(std::time::Duration::from_millis(25));
        if a != b {
            return false;
        }
    }
    true
}

pub async fn handle_request(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let file = match params.get("file") {
        Some(f) => f,
        None => return (StatusCode::BAD_REQUEST, "Missing 'file' parameter").into_response(),
    };

    let signature = match params.get("signature") {
        Some(s) => match hex_to_bytes(s) {
            Ok(s) => s,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("Illegal signature: {}", e))
                    .into_response()
            }
        },
        None => return (StatusCode::BAD_REQUEST, "Missing 'signature' parameter").into_response(),
    };

    let secret_key = b"secret";
    let mac = HmacSha1::digest_message(secret_key, file.as_bytes());
    if insecure_compare(&mac, &signature) {
        (StatusCode::OK, "Signature is valid").into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Invalid signature").into_response()
    }
}
