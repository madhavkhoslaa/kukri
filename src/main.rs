use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Serialize;

mod bpf;

use bpf::KukriSkel;

#[derive(Serialize)]
struct Stats {
    exec_count: u64,
}

struct AppState {
    skel: Mutex<KukriSkel<'static>>,
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<Stats> {
    let exec_count = bpf::exec_count(&state.skel.lock().unwrap());
    Json(Stats { exec_count })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skel = bpf::load()?;
    let state = Arc::new(AppState {
        skel: Mutex::new(skel),
    });

    let app = Router::new().route("/stats", get(stats)).with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
