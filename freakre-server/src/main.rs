use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

// ---------- CLI ----------

#[derive(Parser, Debug)]
#[command(
    name = "freakre-server",
    about = "FreakRE HTTP API for AI agents — JSON on :8080",
    version
)]
struct Cli {
    /// Host to bind
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to bind
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Optional YARA rules file
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Max upload size in MB
    #[arg(long, default_value_t = 100)]
    max_mb: usize,
}

// ---------- State ----------

struct AppState {
    yara_rules_path: Option<PathBuf>,
    jobs: Arc<tokio::sync::RwLock<HashMap<String, JobState>>>,
    next_job_id: AtomicU64,
}

#[derive(Clone, Serialize)]
struct JobState {
    id: String,
    kind: String,
    status: String,
    phase: String,
    progress: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AppState {
    fn new(yara_rules_path: Option<PathBuf>) -> Self {
        Self {
            yara_rules_path,
            jobs: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            next_job_id: AtomicU64::new(1),
        }
    }

    fn allocate_job_id(&self) -> String {
        format!("job-{}", self.next_job_id.fetch_add(1, Ordering::Relaxed))
    }
}

impl AppState {
    fn scanner(&self) -> Result<freakre_scanner::Scanner, String> {
        match &self.yara_rules_path {
            Some(p) => freakre_scanner::Scanner::new().with_yara_rules(p),
            None => Ok(freakre_scanner::Scanner::new()),
        }
    }
}

// ---------- Root & Health ----------

async fn root() -> axum::response::Html<String> {
    axum::response::Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>FreakRE API</title></head><body style="font-family:monospace;padding:24px">
<h1>FreakRE Server v{}</h1>
<p>Сервер работает. Открой <a href="/health">/health</a> или <a href="/api/capabilities">/api/capabilities</a></p>
<h3>Эндпоинты:</h3>
<ul>
<li>GET /health</li>
<li>GET /api/capabilities</li>
<li>POST /api/scan — multipart file=@bin</li>
<li>POST /api/scan/base64 — json {{"filename","data_base64"}}</li>
<li>POST /api/scan/path — json {{"path"}}</li>
<li>POST /api/strings — multipart file=@bin</li>
<li>POST /api/entropy — multipart file=@bin</li>
<li>POST /api/xrefs — multipart file=@bin</li>
<li>POST /api/decompile — multipart file=@bin</li>
</ul>
<h3>Примеры:</h3>
<pre>curl http://localhost:8080/health
curl http://localhost:8080/api/capabilities
curl -X POST http://localhost:8080/api/scan -F "file=@sample.exe"</pre>
</body></html>"#,
        env!("CARGO_PKG_VERSION")
    ))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "freakre-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct AsyncScanRequest {
    path: PathBuf,
}

#[derive(Deserialize)]
struct BinaryDiffRequest {
    a: Vec<diffing::DiffFunction>,
    b: Vec<diffing::DiffFunction>,
    threshold: Option<f64>,
}

async fn binary_diff(
    Json(req): Json<BinaryDiffRequest>,
) -> Result<Json<diffing::DiffResult>, (StatusCode, Json<serde_json::Value>)> {
    let differ = req.threshold.map_or_else(diffing::BinaryDiffer::new, |threshold| {
        diffing::BinaryDiffer::new().with_threshold(threshold)
    });
    differ.diff_functions(&req.a, &req.b).map(Json).map_err(|error| (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"error": error.to_string()})),
    ))
}

#[derive(Deserialize)]
struct HtmlReportRequest {
    path: PathBuf,
}

fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn html_report(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<HtmlReportRequest>,
) -> Result<axum::response::Html<String>, (StatusCode, Json<serde_json::Value>)> {
    if !req.path.is_file() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("file not found: {}", req.path.display())
        }))));
    }
    let scanner = state.scanner().map_err(|error| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": error})),
    ))?;
    let report = scanner.scan_file(&req.path);
    let json = serde_json::to_string(&report).map_err(|error| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": error.to_string()})),
    ))?.replace("</", "<\\/");
    let title = escape_html(&req.path.to_string_lossy());
    Ok(axum::response::Html(format!(
        r#"<!doctype html><meta charset="utf-8"><title>FreakRE report: {title}</title>
<style>body{{font:14px system-ui;background:#10141c;color:#e7edf5;margin:2rem}}pre{{white-space:pre-wrap;background:#18202c;padding:1rem;border-radius:8px}}h1{{font-size:1.3rem}}button{{padding:.5rem}}</style>
<h1>FreakRE report: {title}</h1><button onclick="download()">Download JSON</button><pre id="report"></pre>
<script>const report={json};document.querySelector('#report').textContent=JSON.stringify(report,null,2);function download(){{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{{type:'application/json'}}));a.download='freakre-report.json';a.click();}}</script>"#
    )))
}

async fn start_scan_job(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<AsyncScanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !req.path.is_file() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("file not found: {}", req.path.display())
        }))));
    }
    let id = state.allocate_job_id();
    let initial = JobState {
        id: id.clone(),
        kind: "scan".into(),
        status: "queued".into(),
        phase: "queued".into(),
        progress: 0,
        partial: None,
        error: None,
    };
    {
        let mut jobs = state.jobs.write().await;
        if jobs.len() >= 256 {
            if let Some(oldest) = jobs.keys().next().cloned() {
                jobs.remove(&oldest);
            }
        }
        jobs.insert(id.clone(), initial);
    }
    let jobs = Arc::clone(&state.jobs);
    let yara_rules_path = state.yara_rules_path.clone();
    let job_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let update = |state: JobState| {
            let mut jobs = jobs.blocking_write();
            jobs.insert(job_id.clone(), state);
        };
        update(JobState {
            id: job_id.clone(), kind: "scan".into(), status: "running".into(),
            phase: "scanning".into(), progress: 25, partial: None, error: None,
        });
        let result = (|| -> Result<serde_json::Value, String> {
            let scanner = match yara_rules_path {
                Some(path) => freakre_scanner::Scanner::new().with_yara_rules(&path)?,
                None => freakre_scanner::Scanner::new(),
            };
            let report = scanner.scan_file(&req.path);
            serde_json::to_value(report).map_err(|e| e.to_string())
        })();
        match result {
            Ok(report) => update(JobState {
                id: job_id.clone(), kind: "scan".into(), status: "completed".into(),
                phase: "complete".into(), progress: 100, partial: Some(report), error: None,
            }),
            Err(error) => update(JobState {
                id: job_id.clone(), kind: "scan".into(), status: "failed".into(),
                phase: "error".into(), progress: 100, partial: None, error: Some(error),
            }),
        }
    });
    Ok(Json(serde_json::json!({"job_id": id, "status": "queued"})))
}

async fn get_job(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<JobState>, (StatusCode, Json<serde_json::Value>)> {
    state.jobs.read().await.get(&id).cloned().map(Json).ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "job not found", "job_id": id})),
    ))
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Not Found",
            "hint": "Попробуй GET / , GET /health , GET /api/capabilities , POST /api/scan",
            "docs": "см. freakre-server/README.md и .opencode/skills/freakre-ai/SKILL.md"
        })),
    )
}

async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "freakre-server",
        "version": env!("CARGO_PKG_VERSION"),
        "modules": [
            "pe-parser", "elf-parser", "macho-parser", "coff-parser", "dex-parser", "wasm-parser", "flat-binary",
            "entropy-rs", "str-extract", "import-analyzer", "yara-lite",
            "backdoor-analyzer", "shellcode-analyzer", "xrefs", "cfg-builder", "func-sigs", "ml-detection"
        ],
        "endpoints": {
            "GET /health": "health check",
            "GET /api/capabilities": "this",
            "POST /api/scan": "scan file: multipart file=... or JSON {path, profile, min_severity, suppress_rules}",
            "POST /api/scan/base64": "scan base64: {filename, data_base64, min_severity}",
            "POST /api/strings": "extract strings: multipart file=...",
            "POST /api/entropy": "entropy: multipart file=...",
            "POST /api/xrefs": "xrefs: multipart file=...",
            "POST /api/decompile": "decompile: multipart file=..., address=0x401000 (optional; returns status ok with c_code)"
            ,"POST /api/explain": "explain a backdoor finding: JSON {path, rule_id}"
            ,"POST /api/sarif": "emit SARIF 2.1.0 for a file: JSON {path, profile, suppress_rules}",
            "profiles": ["quick", "malware", "deep", "firmware", "decompiler"]
        },
        "cli_equivalent": "./target/release/freakre -f json <file>"
    }))
}

// ---------- Scan: JSON with path ----------

#[derive(Deserialize)]
struct ScanPathRequest {
    path: PathBuf,
    min_severity: Option<String>,
    findings_only: Option<bool>,
    #[serde(default)]
    suppress_rules: Vec<String>,
    #[serde(default)]
    profile: Option<String>,
}

fn configure_scanner(
    scanner: freakre_scanner::Scanner,
    profile: Option<&str>,
) -> freakre_scanner::Scanner {
    let Some(profile) = profile.map(str::to_ascii_lowercase) else { return scanner };
    let profile = match profile.as_str() {
        "quick" => freakre_scanner::AnalysisProfile::Quick,
        "deep" => freakre_scanner::AnalysisProfile::Deep,
        "firmware" => freakre_scanner::AnalysisProfile::Firmware,
        "decompiler" => freakre_scanner::AnalysisProfile::Decompiler,
        _ => freakre_scanner::AnalysisProfile::Malware,
    };
    scanner.with_profile(profile)
}

#[derive(Deserialize)]
struct ExplainPathRequest {
    path: PathBuf,
    rule_id: String,
}

async fn explain_path(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<ExplainPathRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !req.path.exists() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("path not found: {}", req.path.display())
        }))));
    }
    let scanner = state.scanner().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e})),
    ))?;
    let scanner = configure_scanner(scanner, None);
    let report = scanner.scan_file(&req.path);
    let Some(backdoor) = report.backdoor_analysis else {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "backdoor analysis is unavailable for this file"
        }))));
    };
    let rule = backdoor.findings.iter().find(|finding| {
        finding.rule_id.to_string().eq_ignore_ascii_case(&req.rule_id)
    }).map(|finding| finding.rule_id);
    let Some(rule) = rule else {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("finding not found: {}", req.rule_id),
            "available": backdoor.findings.iter().map(|f| f.rule_id.to_string()).collect::<Vec<_>>()
        }))));
    };
    Ok(Json(serde_json::json!({
        "path": req.path,
        "explanation": backdoor.explain(rule)
    })))
}

async fn sarif_path(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<ScanPathRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !req.path.exists() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("path not found: {}", req.path.display())
        }))));
    }
    let scanner = state.scanner().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e})),
    ))?;
    let scanner = configure_scanner(scanner, req.profile.as_deref());
    let report = scanner.scan_file(&req.path);
    let analysis = if req.suppress_rules.is_empty() {
        report.backdoor_analysis
    } else {
        report.backdoor_analysis.map(|analysis| {
            let suppressed: Vec<_> = analysis.findings.iter()
                .filter(|finding| req.suppress_rules.iter().any(|rule| {
                    rule.eq_ignore_ascii_case(&finding.rule_id.to_string())
                }))
                .map(|finding| finding.rule_id)
                .collect();
            analysis.without_rules(&suppressed)
        })
    };
    let sarif = analysis
        .map(|analysis| analysis.to_sarif(&req.path.to_string_lossy()))
        .unwrap_or_else(|| serde_json::json!({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "FreakRE backdoor-analyzer"}}, "results": []}]
        }));
    Ok(Json(sarif))
}

async fn scan_path(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<ScanPathRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !req.path.exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("path not found: {}", req.path.display())})),
        ));
    }
    let scanner = state.scanner().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    let scanner = configure_scanner(scanner, req.profile.as_deref());
    let mut report = scanner.scan_file(&req.path);
    if !req.suppress_rules.is_empty() {
        report.findings.retain(|finding| !req.suppress_rules.iter().any(|rule| {
            rule.eq_ignore_ascii_case(&finding.rule_id)
        }));
        if let Some(analysis) = report.backdoor_analysis.take() {
            let suppressed: Vec<_> = analysis.findings.iter()
                .filter(|finding| req.suppress_rules.iter().any(|rule| {
                    rule.eq_ignore_ascii_case(&finding.rule_id.to_string())
                }))
                .map(|finding| finding.rule_id)
                .collect();
            report.backdoor_analysis = Some(analysis.without_rules(&suppressed));
        }
    }
    // optional filtering for AI convenience
    if let Some(min_sev) = req.min_severity {
        let min = parse_severity(&min_sev);
        report.findings.retain(|f| f.severity >= min);
    }
    if req.findings_only.unwrap_or(false) && report.findings.is_empty() {
        // still return report but AI can check empty findings
    }
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

// ---------- Scan: base64 ----------

#[derive(Deserialize)]
struct ScanBase64Request {
    filename: Option<String>,
    data_base64: String,
    min_severity: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    suppress_rules: Vec<String>,
}

async fn scan_base64(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<ScanBase64Request>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.data_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid base64: {}", e)})),
            )
        })?;
    // write to temp file so scanner can use scan_file (needs Path)
    let filename = req.filename.unwrap_or_else(|| "upload.bin".to_string());
    let mut tmp = tempfile::Builder::new()
        .prefix("freakre-")
        .suffix(&format!("-{}", filename))
        .tempfile()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
    use std::io::Write;
    tmp.write_all(&data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let path = tmp.path().to_path_buf();
    let scanner = state.scanner().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    let scanner = configure_scanner(scanner, req.profile.as_deref());
    let mut report = scanner.scan_file(&path);
    // patch path to original filename for AI clarity
    report.path = PathBuf::from(&filename);
    if let Some(min_sev) = req.min_severity {
        let min = parse_severity(&min_sev);
        report.findings.retain(|f| f.severity >= min);
    }
    if !req.suppress_rules.is_empty() {
        report.findings.retain(|finding| !req.suppress_rules.iter().any(|rule| {
            rule.eq_ignore_ascii_case(&finding.rule_id)
        }));
    }
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

// ---------- Scan: multipart ----------

async fn scan_multipart(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut file_data: Option<(String, Vec<u8>)> = None;
    let mut min_severity: Option<String> = None;
    let mut profile: Option<String> = None;
    let mut suppress_rules: Vec<String> = Vec::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("multipart error: {}", e)})),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let filename = field.file_name().unwrap_or("upload.bin").to_string();
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;
            file_data = Some((filename, bytes.to_vec()));
        } else if name == "min_severity" {
            let v = field.text().await.unwrap_or_default();
            min_severity = Some(v);
        } else if name == "profile" {
            profile = Some(field.text().await.unwrap_or_default());
        } else if name == "suppress_rules" {
            suppress_rules.extend(field.text().await.unwrap_or_default()
                .split(',').map(str::trim).filter(|rule| !rule.is_empty()).map(str::to_string));
        }
    }

    let Some((filename, data)) = file_data else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing 'file' field"})),
        ));
    };

    let mut tmp = tempfile::Builder::new()
        .prefix("freakre-")
        .suffix(&format!("-{}", filename))
        .tempfile()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
    use std::io::Write;
    tmp.write_all(&data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let path = tmp.path().to_path_buf();
    let scanner = state.scanner().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    let scanner = configure_scanner(scanner, profile.as_deref());
    let mut report = scanner.scan_file(&path);
    report.path = PathBuf::from(&filename);
    if let Some(min_sev) = min_severity {
        let min = parse_severity(&min_sev);
        report.findings.retain(|f| f.severity >= min);
    }
    if !suppress_rules.is_empty() {
        report.findings.retain(|finding| !suppress_rules.iter().any(|rule| {
            rule.eq_ignore_ascii_case(&finding.rule_id)
        }));
    }
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

// ---------- Strings / Entropy / Xrefs (multipart file) ----------

async fn strings_multipart(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let data = extract_file_bytes(&mut multipart).await?;
    let config = str_extract::ExtractConfig::windows_pe(4);
    let strings = str_extract::extract_strings(&data.0, &config);
    Ok(Json(serde_json::json!({
        "filename": data.1,
        "count": strings.len(),
        "strings": strings.iter().take(500).map(|s| serde_json::json!({
            "value": s.value,
            "offset": s.offset,
            "encoding": format!("{:?}", s.encoding),
        })).collect::<Vec<_>>(),
        "truncated": strings.len() > 500
    })))
}

async fn entropy_multipart(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let data = extract_file_bytes(&mut multipart).await?;
    let overall = entropy_rs::calculate_entropy(&data.0);
    // sliding window for packed regions (AI-friendly) — batched O(n)
    let windows = entropy_rs::sliding_window_entropy_batched(&data.0, 256, 256);
    let high_windows: Vec<_> = windows
        .iter()
        .filter(|(_, r)| r.entropy > 7.0)
        .take(20)
        .map(|(off, r)| serde_json::json!({"offset": off, "entropy": r.entropy, "classification": r.classify()}))
        .collect();
    Ok(Json(serde_json::json!({
        "filename": data.1,
        "overall_entropy": overall.entropy,
        "classification": overall.classify().to_string(),
        "high_entropy_windows": high_windows,
        "size": data.0.len()
    })))
}

async fn xrefs_multipart(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let data = extract_file_bytes(&mut multipart).await?;
    let config = str_extract::ExtractConfig::windows_pe(4);
    let strings = str_extract::extract_strings(&data.0, &config);
    let string_xrefs = xrefs::build_string_xrefs(&data.0, &strings);
    // keep a copy for JSON before moving into db
    let xrefs_for_json = string_xrefs.clone();
    let mut db = xrefs::XrefDatabase::new();
    db.add_all(string_xrefs);
    let summary = db.summary();
    Ok(Json(serde_json::json!({
        "filename": data.1,
        "total_xrefs": summary.total_xrefs,
        "unique_targets": summary.unique_targets,
        "string_xrefs": summary.string_xrefs,
        "import_xrefs": summary.import_xrefs,
        "xrefs": xrefs_for_json.iter().take(200).map(|x| serde_json::json!({
            "source_offset": format!("0x{:X}", x.source_offset),
            "source_section": x.source_section,
            "target_label": x.target.label,
            "target_kind": format!("{}", x.target.kind),
            "target_offset": x.target.target_offset.map(|o| format!("0x{:X}", o)),
        })).collect::<Vec<_>>()
    })))
}

// decompile — real when built with the `decompiler` feature (default),
// stub with a hint otherwise.
#[cfg(feature = "decompiler")]
async fn decompile_multipart(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut file_data: Option<(String, Vec<u8>)> = None;
    let mut address: Option<String> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;
            file_data = Some((fname, bytes.to_vec()));
        } else if name == "address" {
            address = Some(field.text().await.unwrap_or_default());
        }
    }
    let Some((filename, data)) = file_data else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing 'file'"})),
        ));
    };
    let addr = match address.as_deref() {
        None | Some("") => None,
        Some(s) => match u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16) {
            Ok(a) => Some(a),
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid 'address', expected hex like 0x401000"})),
                ))
            }
        },
    };
    // CPU-bound lift + decompile off the async runtime.
    let result =
        tokio::task::spawn_blocking(move || freakre_scanner::decompile_api::decompile_pe_function(&data, addr))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("task join: {e}")})),
                )
            })?;
    match result {
        Ok(f) => Ok(Json(serde_json::json!({
            "filename": filename,
            "status": "ok",
            "address": format!("0x{:X}", f.address),
            "function": f.name,
            "size": f.size,
            "c_code": f.c_code,
        }))),
        Err(e) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "filename": filename,
                "status": "failed",
                "error": e,
            })),
        )),
    }
}

#[cfg(not(feature = "decompiler"))]
async fn decompile_multipart(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut file_data: Option<(String, Vec<u8>)> = None;
    let mut address: Option<String> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;
            file_data = Some((fname, bytes.to_vec()));
        } else if name == "address" {
            address = Some(field.text().await.unwrap_or_default());
        }
    }
    let Some((filename, _data)) = file_data else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing 'file'"})),
        ));
    };
    // For now, explain that full decompile needs --features decompiler
    Ok(Json(serde_json::json!({
        "filename": filename,
        "requested_address": address.unwrap_or_else(|| "0x401000".into()),
        "status": "not_enabled",
        "message": "Decompiler is feature-gated. Rebuild with --features decompiler or use scanner's FileReport.decompiler finding. For AI: call POST /api/scan and check findings with module=='decompiler'.",
        "hint": "cargo build -p freakre-scanner --features decompiler && ./target/debug/freakre -f json sample.exe | jq '.findings[] | select(.module==\"decompiler\")'"
    })))
}

async fn extract_file_bytes(
    multipart: &mut Multipart,
) -> Result<(Vec<u8>, String), (StatusCode, Json<serde_json::Value>)> {
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })? {
        if field.name().unwrap_or("") == "file" {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;
            return Ok((bytes.to_vec(), fname));
        }
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "missing 'file' field"})),
    ))
}

fn parse_severity(s: &str) -> freakre_scanner::Severity {
    match s.to_lowercase().as_str() {
        "low" => freakre_scanner::Severity::Low,
        "medium" => freakre_scanner::Severity::Medium,
        "high" => freakre_scanner::Severity::High,
        "critical" => freakre_scanner::Severity::Critical,
        _ => freakre_scanner::Severity::Info,
    }
}

// ---------- Main ----------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Best-effort harvested FLIRT overlay (Once-cached; Scanner::new would
    // also trigger it — this logs the outcome at startup).
    match func_sigs::auto_load_overlay() {
        Some(n) => info!("FLIRT overlay: {n} harvested signatures"),
        None => info!("FLIRT overlay: not found (curated DB only)"),
    }

    let state = Arc::new(AppState::new(cli.rules.clone()));

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/api/capabilities", get(capabilities))
        .route("/api/scan", post(scan_multipart))
        .route("/api/scan/base64", post(scan_base64))
        .route("/api/strings", post(strings_multipart))
        .route("/api/entropy", post(entropy_multipart))
        .route("/api/xrefs", post(xrefs_multipart))
        .route("/api/decompile", post(decompile_multipart))
        // JSON scan by path (alternative)
        .route("/api/scan/path", post(scan_path))
        .route("/api/explain", post(explain_path))
        .route("/api/sarif", post(sarif_path))
        .route("/api/jobs/scan", post(start_scan_job))
        .route("/api/jobs/:id", get(get_job))
        .route("/api/diff", post(binary_diff))
        .route("/api/report/html", post(html_report))
        .fallback(not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(cli.max_mb * 1024 * 1024))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port)
        .parse()
        .expect("invalid host/port");
    let listener = TcpListener::bind(addr).await.expect("bind failed");

    info!("FreakRE server listening on http://{}", addr);
    info!("  GET  /health");
    info!("  GET  /api/capabilities");
    info!("  POST /api/scan              (multipart file=...)");
    info!("  POST /api/scan/base64       (json {{data_base64}})");
    info!("  POST /api/scan/path         (json {{path}})");
    info!("  POST /api/strings|entropy|xrefs|decompile");
    info!("CLI equivalent: cargo run -p freakre-scanner -- -f json <file>");

    axum::serve(listener, app).await.expect("server failed");
}

// Small helper to avoid unused import warning
#[derive(Serialize)]
struct _Unused {}
