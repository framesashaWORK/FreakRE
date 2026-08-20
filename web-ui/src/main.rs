#![allow(dead_code, unused_assignments)]
use askama::Template;
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tower_http::services::ServeDir;
use uuid::Uuid;

mod scanner_wrapper;

// ─── State ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    reports: Arc<RwLock<HashMap<String, ScanResult>>>,
}

#[derive(Clone, Serialize)]
struct ScanResult {
    id: String,
    filename: String,
    report: bibleteks_scanner::report::FileReport,
    scanned_at: String,
}

// Re-export Verdict for use in Askama templates
use bibleteks_scanner::report::Verdict;

// ─── Custom Askama filters ────────────────────────────────────────────

mod filters {
    pub fn filesize(bytes: &u64) -> ::askama::Result<String> {
        let b = *bytes;
        if b >= 1_073_741_824 {
            Ok(format!("{:.1} GB", b as f64 / 1_073_741_824.0))
        } else if b >= 1_048_576 {
            Ok(format!("{:.1} MB", b as f64 / 1_048_576.0))
        } else if b >= 1024 {
            Ok(format!("{:.1} KB", b as f64 / 1024.0))
        } else {
            Ok(format!("{} B", b))
        }
    }
}

// ─── Templates ────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    results: Vec<ScanResult>,
    mal_count: usize,
    sus_count: usize,
    clean_count: usize,
}

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    scan: ScanResult,
    verdict_str: String,
}

/// HTMX fragment returned after upload (not a full page)
#[derive(Template)]
#[template(path = "upload_success.html")]
struct UploadSuccessFragment {
    id: String,
    filename: String,
    verdict: String,
    score: f64,
    findings_count: usize,
}

// ─── Handlers ─────────────────────────────────────────────────────────

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let reports = match state.reports.read() {
        Ok(r) => r,
        Err(poisoned) => {
            tracing::error!("RwLock poisoned in index handler, recovering");
            poisoned.into_inner()
        }
    };
    let mut results: Vec<ScanResult> = reports.values().cloned().collect();
    results.sort_by(|a, b| b.scanned_at.cmp(&a.scanned_at));
    let mal_count = results.iter().filter(|r| matches!(r.report.verdict, Verdict::Malicious)).count();
    let sus_count = results.iter().filter(|r| matches!(r.report.verdict, Verdict::Suspicious)).count();
    let clean_count = results.iter().filter(|r| matches!(r.report.verdict, Verdict::Clean)).count();
    Html(
        IndexTemplate {
            results,
            mal_count,
            sus_count,
            clean_count,
        }
        .render()
        .unwrap(),
    )
}

/// Sanitize filename to prevent path traversal attacks.
/// Strips directory components and dangerous characters.
fn sanitize_filename(filename: &str) -> String {
    use std::path::Path;
    // Extract only the file name component, stripping any directory paths
    let name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    
    // Remove any remaining path separators or parent directory references
    let safe: String = name
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    
    if safe.is_empty() || safe == "." || safe == ".." {
        "unknown".to_string()
    } else {
        safe
    }
}

async fn upload(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let raw_filename = field.file_name().unwrap_or("unknown").to_string();
        let filename = sanitize_filename(&raw_filename);
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Save to temp and scan
        let id = Uuid::new_v4().to_string();
        let tmp_dir = std::env::temp_dir().join("bibleteks");
        std::fs::create_dir_all(&tmp_dir).ok();
        // Use sanitized filename + UUID prefix to prevent collision/traversal
        let tmp_path = tmp_dir.join(format!("{}_{}", &id[..8], &filename));
        if std::fs::write(&tmp_path, &data).is_err() {
            continue;
        }

        // Use spawn_blocking to avoid blocking the async runtime during CPU-intensive scan
        let tmp_path_clone = tmp_path.clone();
        let report = match tokio::task::spawn_blocking(move || {
            let scanner = scanner_wrapper::ScannerWrapper::new();
            scanner.scan_file(&tmp_path_clone)
        }).await {
            Ok(report) => report,
            Err(e) => {
                tracing::error!("Scan task panicked: {}", e);
                continue;
            }
        };

        // Cleanup temp file immediately after scanning to prevent disk DoS
        let _ = std::fs::remove_file(&tmp_path);

        let result = ScanResult {
            id: id.clone(),
            filename: filename.clone(),
            report,
            scanned_at: timestamp_now(),
        };

        let mut write_guard = match state.reports.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!("RwLock poisoned in upload handler, recovering");
                poisoned.into_inner()
            }
        };
        write_guard.insert(id.clone(), result.clone());
        drop(write_guard);

        // Return HTMX fragment instead of full page redirect
        return Html(
            UploadSuccessFragment {
                id,
                filename,
                verdict: format!("{:?}", result.report.verdict),
                score: result.report.suspicion_score,
                findings_count: result.report.findings.len(),
            }
            .render()
            .unwrap(),
        )
        .into_response();
    }

    (StatusCode::BAD_REQUEST, "No file uploaded").into_response()
}

async fn view_report(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let reports = match state.reports.read() {
        Ok(r) => r,
        Err(poisoned) => {
            tracing::error!("RwLock poisoned in view_report handler, recovering");
            poisoned.into_inner()
        }
    };
    match reports.get(&id) {
        Some(result) => Html(
            ReportTemplate {
                verdict_str: format!("{:?}", result.report.verdict),
                scan: result.clone(),
            }
            .render()
            .unwrap(),
        )
        .into_response(),
        None => (StatusCode::NOT_FOUND, "Report not found").into_response(),
    }
}

// ─── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,tower_http=debug")
        .init();

    let state = AppState {
        reports: Arc::new(RwLock::new(HashMap::new())),
    };

    // Background task: cleanup old reports every 30 minutes to prevent memory leak
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800));
        loop {
            interval.tick().await;
            let count = match cleanup_state.reports.read() {
                Ok(r) => r.len(),
                Err(p) => p.into_inner().len(),
            };
            if count > 1000 {
                // Evict oldest half
                let mut reports = match cleanup_state.reports.write() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let mut entries: Vec<(String, String)> = reports
                    .iter()
                    .map(|(k, v)| (k.clone(), v.scanned_at.clone()))
                    .collect();
                entries.sort_by(|a, b| a.1.cmp(&b.1));
                let to_remove = entries.len() / 2;
                for (key, _) in entries.into_iter().take(to_remove) {
                    reports.remove(&key);
                }
                tracing::info!("Cleaned up {} old reports", to_remove);
            }
        }
    });

    // Limit request body size to prevent memory exhaustion DoS (100 MB max)
    let app = Router::new()
        .route("/", get(index))
        .route("/upload", post(upload))
        .route("/report/{id}", get(view_report))
        .nest_service("/static", ServeDir::new("static"))
        .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024))
        .with_state(state);

    // Bind to localhost only to prevent remote exploitation without auth
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("🚀 BibleTeks Web UI running on http://127.0.0.1:3000 (localhost only)");
    axum::serve(listener, app).await.unwrap();
}

fn timestamp_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}


