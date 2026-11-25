use futures::StreamExt;
use salvo::http::Method;
use salvo::prelude::*;
use salvo::websocket::{Message, WebSocketUpgrade};
use std::sync::Arc;

#[cfg(feature = "k8s-bridge")]
use crate::compute::k8s_bridge::{export_k8s_yaml, import_k8s_yaml, ExportOptions};
use crate::compute::md_runtime::deploy_markdown;
use crate::db::Database;
use crate::iam::capabilities::{Capability, CapabilitySet};
use crate::js::cell::{CellManager, CellPolicy, CellWorkload};
use crate::observability::global_metrics;
use crate::ux::iam::{depot_auth_context, depot_request_id};

/// Enforce a specific fine-grained `Capability` derived from the canonical `AuthContext` in `Depot`.
fn require_capability(depot: &Depot, res: &mut Response, cap: Capability) -> bool {
    let auth = depot_auth_context(depot);
    let caps = CapabilitySet::from_auth_context(auth.as_ref());
    if caps.has(cap) {
        return true;
    }
    global_metrics().inc_iam_auth_denial();
    res.status_code(StatusCode::FORBIDDEN);
    res.render(Json(serde_json::json!({
        "code": 403,
        "details": format!("Missing required capability {:?}", cap)
    })));
    false
}

/// HTTP & WebSocket ingress handler for `/cells/<**path>` (`/cells/<app>/<cell_id>` and `POST /cells/deploy-md`).
/// Supports deploying/waking `pinned` or `elastic` (`celld`) cells, evaluating requests,
/// WebSocket message routing, declarative `.md` deployment, and explicit hibernation.
#[derive(Clone)]
pub struct CellGatewayHandler {
    pub db: Arc<Database>,
    pub cells: Arc<CellManager>,
}

/// Parse `/cells/<app>/<cell_id>[/...]` into `(app, cell_id)`.
pub fn parse_cell_path(path: &str) -> Option<(String, String)> {
    let stripped = path.strip_prefix("/cells/").unwrap_or(path).trim_matches('/');
    let mut parts = stripped.splitn(3, '/');
    let app = parts.next()?.trim();
    let cell_id = parts.next()?.trim();
    if app.is_empty() || cell_id.is_empty() {
        return None;
    }
    Some((app.to_string(), cell_id.to_string()))
}

fn policy_from_headers(req: &Request) -> CellPolicy {
    match req
        .headers()
        .get("x-nexus-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("pinned") => CellPolicy::Pinned,
        Some("mobile") => CellPolicy::elastic_mobile(),
        _ => CellPolicy::elastic_default(),
    }
}

#[async_trait]
impl Handler for CellGatewayHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        // POST /cells/deploy-md -> deploy declarative Markdown (.md) service nodes (requires CellSpawn)
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/deploy-md" {
            if !require_capability(depot, res, Capability::CellSpawn) {
                return;
            }
            let md = match req.payload().await {
                Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Failed to read markdown body: {}", e)));
                    return;
                }
            };
            match deploy_markdown(&self.cells, self.db.as_ref(), &md).await {
                Ok(nodes) => {
                    let deployed: Vec<serde_json::Value> = nodes
                        .into_iter()
                        .map(|n| serde_json::json!({ "app": n.app, "cell_id": n.cell_id, "name": n.name }))
                        .collect();
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "deployed": deployed })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Text::Plain(format!("Markdown deploy error: {}", e)));
                }
            }
            return;
        }

        // POST /cells/import-k8s -> import Kubernetes YAML into Nexus .md (requires CellSpawn)
        #[cfg(feature = "k8s-bridge")]
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/import-k8s" {
            if !require_capability(depot, res, Capability::CellSpawn) {
                return;
            }
            let yaml = match req.payload().await {
                Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Failed to read Kubernetes YAML body: {}", e)));
                    return;
                }
            };
            let should_deploy = req
                .uri()
                .query()
                .map(|q| q.split('&').any(|p| p == "deploy=true" || p == "deploy=1"))
                .unwrap_or(false);
            match import_k8s_yaml(&yaml) {
                Ok(report) => {
                    if should_deploy {
                        if let Err(e) = deploy_markdown(&self.cells, self.db.as_ref(), &report.markdown).await {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            res.render(Text::Plain(format!("Kubernetes deploy error: {}", e)));
                            return;
                        }
                    }
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({
                        "app": report.app,
                        "deployed": should_deploy,
                        "workloads": report.workloads,
                        "warnings": report.warnings,
                        "markdown": report.markdown
                    })));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Kubernetes import error: {}", e)));
                }
            }
            return;
        }

        // POST /cells/export-k8s -> export Nexus .md service document to standard Kubernetes YAML
        #[cfg(feature = "k8s-bridge")]
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/export-k8s" {
            let md = match req.payload().await {
                Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Failed to read markdown body: {}", e)));
                    return;
                }
            };
            let mut opts = ExportOptions::default();
            if let Some(q) = req.uri().query() {
                for pair in q.split('&') {
                    if let Some(img) = pair.strip_prefix("image=") {
                        if !img.is_empty() {
                            opts.runtime_image = img.to_string();
                        }
                    }
                }
            }
            match export_k8s_yaml(&md, opts) {
                Ok(yaml) => {
                    res.status_code(StatusCode::OK);
                    res.render(Text::Plain(yaml));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Kubernetes export error: {}", e)));
                }
            }
            return;
        }

        // POST /cells/_runtimes/pull -> pull Wasm runtime from OCI v2 registry (requires RuntimeInstall)
        #[cfg(all(feature = "wasm-runtime", feature = "oci-registry"))]
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/_runtimes/pull" {
            if !require_capability(depot, res, Capability::RuntimeInstall) {
                return;
            }
            let body: serde_json::Value = match req.parse_json().await {
                Ok(v) => v,
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!("Invalid pull JSON body: {}", e)));
                    return;
                }
            };
            let Some(reference) = body.get("reference").and_then(|v| v.as_str()) else {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain("Missing required 'reference' field (e.g. '@aerea/quickjs:1.0')"));
                return;
            };
            let alias = body.get("name").and_then(|v| v.as_str());
            match self.cells.runtimes().pull_oci(alias, reference).await {
                Ok(rec) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(rec));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_GATEWAY);
                    res.render(Text::Plain(format!("OCI pull error: {}", e)));
                }
            }
            return;
        }

        // GET /cells/_runtimes -> list registered WASI guest runtimes (quickjs, php-cgi, sqlite, pglite, ...)
        #[cfg(feature = "wasm-runtime")]
        if req.method() == &Method::GET && req.uri().path().trim_end_matches('/') == "/cells/_runtimes" {
            let runtimes = self.cells.runtimes().list_runtimes().await;
            res.status_code(StatusCode::OK);
            res.render(Json(serde_json::json!({ "runtimes": runtimes })));
            return;
        }

        // PUT /cells/_runtimes/<name> -> register & AOT-precompile a WASI guest runtime (requires RuntimeInstall)
        #[cfg(feature = "wasm-runtime")]
        if req.method() == &Method::PUT {
            let runtime_name = req
                .uri()
                .path()
                .strip_prefix("/cells/_runtimes/")
                .map(|s| s.trim_matches('/').to_string())
                .filter(|s| !s.is_empty());
            if let Some(name) = runtime_name {
                if !require_capability(depot, res, Capability::RuntimeInstall) {
                    return;
                }
                let bytes = match req.payload().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Failed to read runtime bytes: {}", e)));
                        return;
                    }
                };
                match self.cells.runtimes().register_runtime(&name, &bytes).await {
                    Ok(rec) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(rec));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Text::Plain(format!("Runtime registration error: {}", e)));
                    }
                }
                return;
            }
        }

        // DELETE /cells/_runtimes/<name> -> uninstall a WASI guest runtime (requires RuntimeInstall)
        #[cfg(feature = "wasm-runtime")]
        if req.method() == &Method::DELETE {
            let runtime_name = req
                .uri()
                .path()
                .strip_prefix("/cells/_runtimes/")
                .map(|s| s.trim_matches('/').to_string())
                .filter(|s| !s.is_empty());
            if let Some(name) = runtime_name {
                if !require_capability(depot, res, Capability::RuntimeInstall) {
                    return;
                }
                match self.cells.runtimes().uninstall_runtime(&name).await {
                    Ok(true) => {
                        res.status_code(StatusCode::NO_CONTENT);
                    }
                    Ok(false) => {
                        res.status_code(StatusCode::NOT_FOUND);
                        res.render(Text::Plain(format!("Runtime '{}' not found", name)));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Runtime uninstall error: {}", e)));
                    }
                }
                return;
            }
        }

        let Some((app, cell_id)) = parse_cell_path(req.uri().path()) else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Invalid cell path. Use: /cells/<app>/<cell_id>"));
            return;
        };

        // WebSocket upgrade for hibernatable / live cell messaging
        let is_ws = req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        if is_ws && req.method() == &Method::GET {
            let cells = self.cells.clone();
            let db_ws = self.db.clone();
            let app_ws = app.clone();
            let id_ws = cell_id.clone();
            let initial_auth = depot_auth_context(depot);
            let upgrade_res = WebSocketUpgrade::new()
                .upgrade(req, res, move |mut ws| async move {
                    let kernel = crate::iam::kernel::SecurityKernel::new(db_ws);
                    while let Some(Ok(msg)) = ws.next().await {
                        if let Ok(text) = msg.as_str() {
                            // Re-verify live authorization on EVERY frame (not just at upgrade time)
                            if let Some(ref auth) = initial_auth {
                                if let Some(ref actor) = auth.actor {
                                    let live = kernel.resolve_auth_context(actor, &app_ws, &id_ws).await;
                                    let caps = CapabilitySet::from_auth_context(Some(&live));
                                    if !caps.has(Capability::DbRead) {
                                        global_metrics().inc_iam_auth_denial();
                                        let _ = ws.send(Message::text("ERROR: 403 Forbidden (revoked)")).await;
                                        break;
                                    }
                                }
                            }
                            let reply = match cells.eval_in_cell(&app_ws, &id_ws, text).await {
                                Ok(out) => out,
                                Err(e) => format!("ERROR: {}", e),
                            };
                            if ws.send(Message::text(reply)).await.is_err() {
                                break;
                            }
                        }
                    }
                })
                .await;
            if let Err(e) = upgrade_res {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain(format!("WebSocket upgrade failed: {}", e)));
            }
            return;
        }

        let req_id = depot_request_id(depot);

        match req.method() {
            // PUT /cells/<app>/<cell_id>/db-config -> declaratively configure per-cell CellDbConfig (requires CellManage)
            &Method::PUT if req.uri().path().trim_end_matches('/').ends_with("/db-config") => {
                if !require_capability(depot, res, Capability::CellManage) {
                    return;
                }
                match req.parse_json::<crate::js::cell::CellDbConfig>().await {
                    Ok(cfg) => {
                        self.cells.set_db_config(&app, &cell_id, cfg.clone()).await;
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({
                            "app": app,
                            "cell_id": cell_id,
                            "db_config": cfg
                        })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Invalid CellDbConfig JSON: {}", e)));
                    }
                }
            }

            // PUT /cells/<app>/<cell_id> -> wake/deploy WASI, WASI-CGI, JS-on-Wasm, or TS/JS cell (requires CellSpawn)
            &Method::PUT => {
                if !require_capability(depot, res, Capability::CellSpawn) {
                    return;
                }
                let policy = policy_from_headers(req);
                let runtime_hdr = req
                    .headers()
                    .get("x-nexus-runtime")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_ascii_lowercase());
                let is_wasm_ct = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.contains("application/wasm"))
                    .unwrap_or(false);
                let raw_bytes = match req.payload().await {
                    Ok(bytes) => bytes.to_vec(),
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Failed to read cell payload: {}", e)));
                        return;
                    }
                };
                #[cfg(feature = "wasm-runtime")]
                if runtime_hdr.as_deref() == Some("js-wasm") || runtime_hdr.as_deref() == Some("quickjs") {
                    let script = String::from_utf8_lossy(&raw_bytes).to_string();
                    match self
                        .cells
                        .wake_js_wasm(&app, &cell_id, policy, script, "quickjs", 50_000_000)
                        .await
                    {
                        Ok(()) => {
                            res.status_code(StatusCode::OK);
                            res.render(Text::Plain(format!("Cell {}/{} awake (js-wasm)", app, cell_id)));
                        }
                        Err(e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            res.render(Text::Plain(format!("Cell js-wasm wake error: {}", e)));
                        }
                    }
                    return;
                }
                let workload = match runtime_hdr.as_deref() {
                    Some("wasi-cgi") | Some("cgi") | Some("php") => CellWorkload::WasiCgi {
                        module_bytes: raw_bytes,
                        doc_root: None,
                        fuel_limit: 50_000_000,
                    },
                    Some("wasi") | Some("wasm") => CellWorkload::WasiModule {
                        module_bytes: raw_bytes,
                        args: vec!["cell.wasm".to_string()],
                        env: Vec::new(),
                        preopen_dirs: Vec::new(),
                        fuel_limit: 50_000_000,
                    },
                    _ if is_wasm_ct => CellWorkload::WasiModule {
                        module_bytes: raw_bytes,
                        args: vec!["cell.wasm".to_string()],
                        env: Vec::new(),
                        preopen_dirs: Vec::new(),
                        fuel_limit: 50_000_000,
                    },
                    _ => CellWorkload::NativeJs {
                        script: String::from_utf8_lossy(&raw_bytes).to_string(),
                    },
                };
                match self.cells.wake_workload(&app, &cell_id, policy, workload).await {
                    Ok(()) => {
                        res.status_code(StatusCode::OK);
                        res.render(Text::Plain(format!("Cell {}/{} awake", app, cell_id)));
                    }
                    Err(e) if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>().is_some() => {
                        res.status_code(StatusCode::CONFLICT);
                        res.render(Text::Plain(format!("Cell lease owned remotely: {}", e)));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Text::Plain(format!("Cell wake error: {}", e)));
                    }
                }
            }

            // POST /cells/<app>/<cell_id> -> invoke WASI/CGI cell or evaluate expression/RPC inside JS cell
            &Method::POST => {
                let raw_bytes = match req.payload().await {
                    Ok(bytes) => bytes.to_vec(),
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Failed to read body: {}", e)));
                        return;
                    }
                };
                #[cfg(all(feature = "wasm-runtime", not(target_os = "ios")))]
                if self.cells.is_wasm_workload(&app, &cell_id).await {
                    let query = req.uri().query().unwrap_or("");
                    match self
                        .cells
                        .invoke_http_with_request_id(
                            &app,
                            &cell_id,
                            "POST",
                            req.uri().path(),
                            query,
                            &raw_bytes,
                            req_id,
                        )
                        .await
                    {
                        Ok(resp) => {
                            res.status_code(
                                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK),
                            );
                            for (k, v) in resp.headers {
                                if let (Ok(name), Ok(val)) = (
                                    salvo::http::header::HeaderName::from_bytes(k.as_bytes()),
                                    salvo::http::header::HeaderValue::from_str(&v),
                                ) {
                                    res.headers_mut().insert(name, val);
                                }
                            }
                            let _ = res.write_body(resp.body);
                        }
                        Err(e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            res.render(Text::Plain(format!("WASI cell error: {}", e)));
                        }
                    }
                    return;
                }
                let expr = String::from_utf8_lossy(&raw_bytes).to_string();
                match self.cells.eval_in_cell(&app, &cell_id, &expr).await {
                    Ok(out) => {
                        res.status_code(StatusCode::OK);
                        res.render(Text::Plain(out));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Text::Plain(format!("Cell eval error: {}", e)));
                    }
                }
            }

            // DELETE /cells/<app>/<cell_id> -> hibernate cell & release CAS lease (requires CellManage)
            &Method::DELETE => {
                if !require_capability(depot, res, Capability::CellManage) {
                    return;
                }
                match self.cells.hibernate(&app, &cell_id).await {
                    Ok(()) => {
                        res.status_code(StatusCode::NO_CONTENT);
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Text::Plain(format!("Cell hibernate error: {}", e)));
                    }
                }
            }

            // GET /cells/<app>/<cell_id> -> invoke WASI/CGI handler or WinterCG fetch(request)
            &Method::GET => {
                #[cfg(all(feature = "wasm-runtime", not(target_os = "ios")))]
                if self.cells.is_wasm_workload(&app, &cell_id).await {
                    let query = req.uri().query().unwrap_or("");
                    match self
                        .cells
                        .invoke_http_with_request_id(
                            &app,
                            &cell_id,
                            "GET",
                            req.uri().path(),
                            query,
                            b"",
                            req_id,
                        )
                        .await
                    {
                        Ok(resp) => {
                            res.status_code(
                                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK),
                            );
                            for (k, v) in resp.headers {
                                if let (Ok(name), Ok(val)) = (
                                    salvo::http::header::HeaderName::from_bytes(k.as_bytes()),
                                    salvo::http::header::HeaderValue::from_str(&v),
                                ) {
                                    res.headers_mut().insert(name, val);
                                }
                            }
                            let _ = res.write_body(resp.body);
                        }
                        Err(e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            res.render(Text::Plain(format!("WASI cell error: {}", e)));
                        }
                    }
                    return;
                }
                let req_url = format!("http://localhost{}", req.uri());
                let eval_expr = format!(
                    "typeof fetch === 'function' ? (() => {{ const r = fetch(new Request({:?}, {{ method: 'GET' }})); return r && typeof r === 'object' && '_body' in r ? r._body : String(r); }})() : 'ok'",
                    req_url
                );
                match self
                    .cells
                    .eval_in_cell(&app, &cell_id, &eval_expr)
                    .await
                {
                    Ok(out) => {
                        res.status_code(StatusCode::OK);
                        res.render(Text::Plain(out));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::NOT_FOUND);
                        res.render(Text::Plain(e.to_string()));
                    }
                }
            }

            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
                res.render(Text::Plain("Method not allowed"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cell_paths() {
        assert_eq!(
            parse_cell_path("/cells/demo_app/room_1"),
            Some(("demo_app".to_string(), "room_1".to_string()))
        );
        assert_eq!(
            parse_cell_path("/cells/demo_app/room_1/sub"),
            Some(("demo_app".to_string(), "room_1".to_string()))
        );
        assert_eq!(parse_cell_path("/cells/only_app"), None);
    }
}
