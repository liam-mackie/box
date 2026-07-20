use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use futures::{stream, StreamExt};
use http::header::{
    HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, TRANSFER_ENCODING,
};
use http::uri::PathAndQuery;
use http_body_util::BodyExt;
use hudsucker::hyper::body::{Body as HttpBody, Bytes};
use hudsucker::hyper::{Method, Request, Response, StatusCode, Uri};
use hudsucker::hyper_util::client::legacy::Error as LegacyError;
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};

use crate::config::{build_authority, fingerprint, load_snapshot, parse_ca, Paths, Snapshot};
use crate::decision::{request_action, should_intercept_connect, RequestAction};
use crate::inject::{self, Rendered};
use crate::allowlist::normalize_host;
use crate::logfmt::{access_line, NO_FLAGS, NO_SNI};
use crate::pinned::is_pinned;

pub struct Logger {
    file: Mutex<Option<std::fs::File>>,
}

impl Logger {
    pub fn open(path: &Path) -> Logger {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Logger {
                file: Mutex::new(Some(file)),
            },
            Err(err) => {
                eprintln!("box-proxy: cannot open access log {}: {err}", path.display());
                Logger {
                    file: Mutex::new(None),
                }
            }
        }
    }

    pub fn log(&self, line: &str) {
        use std::io::Write;
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "{line}");
                let _ = file.flush();
            }
        }
    }
}

pub struct SharedState {
    pub config: ArcSwap<Snapshot>,
    pub logger: Logger,
}

#[derive(Clone)]
struct Pending {
    time: SystemTime,
    client_ip: String,
    method: String,
    url: String,
}

#[derive(Clone)]
pub struct BoxHandler {
    state: Arc<SharedState>,
    pending: Option<Pending>,
}

impl BoxHandler {
    pub fn new(state: Arc<SharedState>) -> BoxHandler {
        BoxHandler {
            state,
            pending: None,
        }
    }
}

fn request_host(req: &Request<Body>) -> Option<String> {
    if let Some(host) = req.uri().host() {
        return Some(normalize_host(host));
    }
    if let Some(value) = req.headers().get(HOST) {
        if let Ok(text) = value.to_str() {
            let host = text.split(':').next().unwrap_or(text);
            if !host.is_empty() {
                return Some(normalize_host(host));
            }
        }
    }
    None
}

fn default_port(req: &Request<Body>) -> u16 {
    if req.uri().scheme_str() == Some("http") {
        80
    } else {
        443
    }
}

fn full_url(req: &Request<Body>, host: &str) -> String {
    let scheme = req.uri().scheme_str().unwrap_or("https");
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    format!("{scheme}://{host}{path_and_query}")
}

fn content_length(res: &Response<Body>) -> u64 {
    res.headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn deny_response(host: &str) -> Response<Body> {
    let body = format!("box: egress to \"{host}\" is blocked (not on the allowlist).\n");
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from("forbidden")))
}

const MAX_BUFFERED_BODY: usize = 10 * 1024 * 1024;

struct Placeholder {
    token: String,
    value: String,
}

fn partition_rendered(rendered: Vec<Rendered>) -> (Vec<Placeholder>, Vec<Rendered>) {
    let mut placeholders = Vec::new();
    let mut inserts = Vec::new();
    for item in rendered {
        match item {
            Rendered::Placeholder { token, value } => placeholders.push(Placeholder { token, value }),
            other => inserts.push(other),
        }
    }
    (placeholders, inserts)
}

fn replace_all_str(source: &str, placeholders: &[Placeholder]) -> Option<String> {
    let mut current: Option<String> = None;
    for placeholder in placeholders {
        let text = current.as_deref().unwrap_or(source);
        if let Some(replaced) = inject::replace_token_str(text, &placeholder.token, &placeholder.value) {
            current = Some(replaced);
        }
    }
    current
}

fn replace_all_bytes(source: Vec<u8>, placeholders: &[Placeholder]) -> Vec<u8> {
    let mut current = source;
    for placeholder in placeholders {
        if let Some(replaced) = inject::replace_token_bytes(&current, &placeholder.token, &placeholder.value) {
            current = replaced;
        }
    }
    current
}

fn apply_placeholder_headers(req: &mut Request<Body>, placeholders: &[Placeholder]) {
    for (name, value) in req.headers_mut().iter_mut() {
        if *name == HOST {
            continue;
        }
        let Ok(text) = value.to_str() else {
            continue;
        };
        if let Some(replaced) = replace_all_str(text, placeholders) {
            if let Ok(header) = HeaderValue::from_str(&replaced) {
                *value = header;
            }
        }
    }
}

fn apply_placeholder_uri(req: &mut Request<Body>, placeholders: &[Placeholder]) {
    let Some(path_and_query) = req.uri().path_and_query().map(|p| p.as_str().to_string()) else {
        return;
    };
    let Some(replaced) = replace_all_str(&path_and_query, placeholders) else {
        return;
    };
    let Ok(parsed) = replaced.parse::<PathAndQuery>() else {
        return;
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = Some(parsed);
    if let Ok(uri) = Uri::from_parts(parts) {
        *req.uri_mut() = uri;
    }
}

async fn apply_placeholder_body(
    req: Request<Body>,
    placeholders: &[Placeholder],
) -> Result<Request<Body>, Response<Body>> {
    let (parts, body) = req.into_parts();
    if body.is_end_stream() || body.size_hint().lower() > MAX_BUFFERED_BODY as u64 {
        return Ok(Request::from_parts(parts, body));
    }

    let mut body = body;
    let mut buffered: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                if buffered.len() + data.len() > MAX_BUFFERED_BODY {
                    let head = Bytes::from(std::mem::take(&mut buffered));
                    let prefix = stream::iter(vec![
                        Ok::<Bytes, hudsucker::Error>(head),
                        Ok(data),
                    ]);
                    let reconstructed = prefix.chain(body.into_data_stream());
                    return Ok(Request::from_parts(parts, Body::from_stream(reconstructed)));
                }
                buffered.extend_from_slice(&data);
            }
            Some(Err(_)) => return Err(bad_gateway()),
            None => break,
        }
    }

    let replaced = replace_all_bytes(buffered, placeholders);
    let mut parts = parts;
    parts.headers.remove(TRANSFER_ENCODING);
    if let Ok(length) = HeaderValue::from_str(&replaced.len().to_string()) {
        parts.headers.insert(CONTENT_LENGTH, length);
    }
    Ok(Request::from_parts(parts, Body::from(replaced)))
}

fn bad_gateway() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn apply_inserts(req: &mut Request<Body>, inserts: &[Rendered]) {
    for rendered in inserts {
        match rendered {
            Rendered::Header { field, value } => {
                if let (Ok(name), Ok(header)) = (
                    HeaderName::from_bytes(field.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    req.headers_mut().insert(name, header);
                }
            }
            Rendered::Cookie { field, value } => {
                let existing = req
                    .headers()
                    .get(COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let merged = inject::append_cookie(existing.as_deref(), field, value);
                if let Ok(header) = HeaderValue::from_str(&merged) {
                    req.headers_mut().insert(COOKIE, header);
                }
            }
            Rendered::Query { field, value } => apply_query(req, field, value),
            Rendered::Placeholder { .. } => {}
        }
    }
}

fn apply_query(req: &mut Request<Body>, field: &str, value: &str) {
    let mut parts = req.uri().clone().into_parts();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let new_query = inject::set_query_param(query.as_deref(), field, value);
    let candidate = if new_query.is_empty() {
        path
    } else {
        format!("{path}?{new_query}")
    };
    if let Ok(path_and_query) = candidate.parse::<PathAndQuery>() {
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = Uri::from_parts(parts) {
            *req.uri_mut() = uri;
        }
    }
}

impl HttpHandler for BoxHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let client_ip = ctx.client_addr.ip().to_string();
        let is_connect = req.method() == Method::CONNECT;
        let host = if is_connect {
            req.uri().host().map(normalize_host)
        } else {
            request_host(&req)
        };
        let snapshot = self.state.config.load();

        let Some(host) = host else {
            let port = default_port(&req);
            self.state.logger.log(&access_line(
                SystemTime::now(),
                &client_ip,
                NO_FLAGS,
                403,
                0,
                "CONNECT",
                &format!("unknown:{port}"),
                NO_SNI,
            ));
            return deny_response("(unknown host)").into();
        };

        let allowed = snapshot.allows(&client_ip, &host);
        if request_action(allowed) == RequestAction::Deny {
            let port = req.uri().port_u16().unwrap_or_else(|| default_port(&req));
            self.state.logger.log(&access_line(
                SystemTime::now(),
                &client_ip,
                NO_FLAGS,
                403,
                0,
                "CONNECT",
                &format!("{host}:{port}"),
                NO_SNI,
            ));
            return deny_response(&host).into();
        }

        if is_connect {
            return req.into();
        }

        let url = full_url(&req, &host);
        let method = req.method().to_string();
        let rendered = inject::applicable(&snapshot.secrets, &host, req.uri().path());
        drop(snapshot);

        let (placeholders, inserts) = partition_rendered(rendered);
        let mut req = req;
        if !placeholders.is_empty() {
            apply_placeholder_headers(&mut req, &placeholders);
            apply_placeholder_uri(&mut req, &placeholders);
            match apply_placeholder_body(req, &placeholders).await {
                Ok(updated) => req = updated,
                Err(response) => {
                    self.state.logger.log(&access_line(
                        SystemTime::now(),
                        &client_ip,
                        NO_FLAGS,
                        502,
                        0,
                        &method,
                        &url,
                        NO_SNI,
                    ));
                    return response.into();
                }
            }
        }
        apply_inserts(&mut req, &inserts);
        self.pending = Some(Pending {
            time: SystemTime::now(),
            client_ip,
            method,
            url,
        });
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if let Some(pending) = self.pending.take() {
            self.state.logger.log(&access_line(
                pending.time,
                &pending.client_ip,
                NO_FLAGS,
                res.status().as_u16(),
                content_length(&res),
                &pending.method,
                &pending.url,
                NO_SNI,
            ));
        }
        res
    }

    async fn handle_error(&mut self, _ctx: &HttpContext, err: LegacyError) -> Response<Body> {
        if let Some(pending) = self.pending.take() {
            self.state.logger.log(&access_line(
                pending.time,
                &pending.client_ip,
                NO_FLAGS,
                502,
                0,
                &pending.method,
                &pending.url,
                NO_SNI,
            ));
        }
        tracing::warn!(error = %err, "upstream request failed");
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    async fn should_intercept_connect(&mut self, ctx: &HttpContext, req: &Request<Body>) -> bool {
        let client_ip = ctx.client_addr.ip().to_string();
        let Some(host) = req.uri().host().map(normalize_host) else {
            return true;
        };
        let snapshot = self.state.config.load();
        let allowed = snapshot.allows(&client_ip, &host);
        let pinned = is_pinned(&host);
        let intercept = should_intercept_connect(allowed, pinned);
        if !intercept {
            let port = req.uri().port_u16().unwrap_or(443);
            self.state.logger.log(&access_line(
                SystemTime::now(),
                &client_ip,
                NO_FLAGS,
                200,
                0,
                "CONNECT",
                &format!("{host}:{port}"),
                NO_SNI,
            ));
        }
        intercept
    }
}

fn spawn_reloader(state: Arc<SharedState>, paths: Paths) {
    tokio::spawn(async move {
        let mut current = fingerprint(&paths);
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let next = fingerprint(&paths);
            if next != current {
                current = next;
                state.config.store(Arc::new(load_snapshot(&paths)));
                tracing::info!("reloaded egress policy");
            }
        }
    });
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).ok();
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match term.as_mut() {
            Some(sig) => {
                sig.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

pub async fn run(paths: Paths) -> Result<(), String> {
    let (pkey, cert) = parse_ca(&paths.ca_cert, &paths.ca_key)?;
    let ca = build_authority(pkey, cert);

    let addr: SocketAddr = paths
        .listen_addr
        .parse()
        .map_err(|e| format!("invalid listen address {:?}: {e}", paths.listen_addr))?;

    let state = Arc::new(SharedState {
        config: ArcSwap::from_pointee(load_snapshot(&paths)),
        logger: Logger::open(&paths.access_log),
    });

    spawn_reloader(Arc::clone(&state), paths.clone());

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(BoxHandler::new(state))
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .map_err(|e| format!("build proxy: {e}"))?;

    tracing::info!(%addr, "box-proxy listening");
    proxy.start().await.map_err(|e| format!("proxy: {e}"))
}
