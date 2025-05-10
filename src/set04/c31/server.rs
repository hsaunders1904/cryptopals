use crate::{hex_to_bytes, HmacSha1};

use axum::{extract::Query, http::StatusCode, response::IntoResponse, routing::get, Router};
use tokio::net::{TcpListener, ToSocketAddrs};

use std::{collections::HashMap, sync::Arc};

pub async fn spawn_server(
    address: impl ToSocketAddrs,
    request_handler: &HmacSha1RequestHandler,
) -> String {
    let app = Router::new().route(
        "/test",
        get({
            let handler = Arc::new(request_handler.clone());
            async move |query| handler.handle_request(query).await
        }),
    );
    let listener = TcpListener::bind(address).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

#[derive(Debug, Clone)]
pub struct HmacSha1RequestHandler {
    key: Vec<u8>,
    compare_delay: std::time::Duration,
}

impl HmacSha1RequestHandler {
    pub fn new(key: &[u8], compare_delay: std::time::Duration) -> Self {
        Self {
            key: key.to_vec(),
            compare_delay,
        }
    }

    pub async fn handle_request(
        &self,
        Query(params): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
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
            None => {
                return (StatusCode::BAD_REQUEST, "Missing 'signature' parameter").into_response()
            }
        };

        let mac = HmacSha1::digest_message(&self.key, file.as_bytes());
        if insecure_compare(&mac, &signature, self.compare_delay)
            .await
            .await
        {
            (StatusCode::OK, "Signature is valid").into_response()
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, "Invalid signature").into_response()
        }
    }
}

async fn insecure_compare<'a>(
    a: &'a [u8],
    b: &'a [u8],
    delay: std::time::Duration,
) -> impl std::future::Future<Output = bool> + 'a {
    async move {
        for (&a_byte, &b_byte) in a.iter().zip(b) {
            tokio::time::sleep(delay).await;
            if a_byte != b_byte {
                return false;
            }
        }
        true
    }
}
