use cryptopals::server;

use axum::{routing::get, Router};

use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let request_handler =
        server::HmacSha1RequestHandler::new(b"secret_key", std::time::Duration::from_millis(50));
    let app = Router::new().route(
        "/test",
        get({
            let handler = Arc::new(request_handler.clone());
            async move |query| handler.handle_request(query).await
        }),
    );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
