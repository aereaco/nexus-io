use futures::StreamExt;
use salvo::http::Method;
use salvo::prelude::*;
use salvo::websocket::{Message, WebSocketUpgrade};
use std::sync::Arc;

use crate::compute::k8s_bridge::{export_k8s_yaml, import_k8s_yaml, ExportOptions};
use crate::compute::md_runtime::deploy_markdown;
use crate::db::Database;
use crate::js::cell::{CellManager, CellPolicy};

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
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        // POST /cells/deploy-md -> deploy declarative Markdown (.md) service nodes directly
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/deploy-md" {
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

        // POST /cells/import-k8s -> import Kubernetes YAML into Nexus .md (and optionally deploy with ?deploy=true)
        if req.method() == &Method::POST && req.uri().path().trim_end_matches('/') == "/cells/import-k8s" {
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
            let app_ws = app.clone();
            let id_ws = cell_id.clone();
            let upgrade_res = WebSocketUpgrade::new()
                .upgrade(req, res, move |mut ws| async move {
                    while let Some(Ok(msg)) = ws.next().await {
                        if let Ok(text) = msg.as_str() {
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

        match req.method() {
            // PUT /cells/<app>/<cell_id> -> wake/deploy TS or JS cell script
            &Method::PUT => {
                let policy = policy_from_headers(req);
                let script = match req.payload().await {
                    Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Failed to read cell script: {}", e)));
                        return;
                    }
                };
                match self.cells.wake(&app, &cell_id, policy, script).await {
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

            // POST /cells/<app>/<cell_id> -> evaluate expression / RPC inside cell
            &Method::POST => {
                let expr = match req.payload().await {
                    Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Text::Plain(format!("Failed to read expression: {}", e)));
                        return;
                    }
                };
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

            // DELETE /cells/<app>/<cell_id> -> hibernate cell & release CAS lease
            &Method::DELETE => match self.cells.hibernate(&app, &cell_id).await {
                Ok(()) => {
                    res.status_code(StatusCode::NO_CONTENT);
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Text::Plain(format!("Cell hibernate error: {}", e)));
                }
            },

            // GET /cells/<app>/<cell_id> -> invoke WinterCG fetch(request) or return status
            &Method::GET => {
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
