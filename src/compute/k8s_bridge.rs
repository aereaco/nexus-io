use anyhow::{anyhow, Result};
use base64::Engine as _;
use nu_engine::CallExt;
use nu_protocol::engine::{Call, Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, SyntaxShape, Value};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use serde_norway::Value as YamlValue;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::compute::md_runtime::{deploy_markdown, parse_markdown_nodes};
use crate::db::Database;
use crate::js::cell::{CellManager, CellPolicy};
use crate::storage::BlobBridge;

/// Summary of an imported Kubernetes workload mapped to a Nexus-IO `SystemNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedWorkload {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub policy: String,
    pub image: Option<String>,
    pub wasm_refs: Vec<String>,
    pub ports: Vec<u16>,
    pub routes: Vec<RouteSpec>,
}

/// Declarative ingress/service route associated with a workload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteSpec {
    pub host: Option<String>,
    pub path: String,
    pub port: u16,
}

/// Output of importing a Kubernetes YAML manifest (single or multi-document) into Nexus-IO `.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub app: String,
    pub markdown: String,
    pub workloads: Vec<ImportedWorkload>,
    pub warnings: Vec<String>,
}

/// Options controlling Kubernetes YAML export from a Nexus-IO `.md` service file.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub runtime_image: String,
    pub default_port: u16,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            runtime_image: "ghcr.io/nexus-io/nexus:latest".to_string(),
            default_port: 8080,
        }
    }
}

fn yaml_str<'a>(v: &'a YamlValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn yaml_map_to_btreemap(v: Option<&YamlValue>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(YamlValue::Mapping(m)) = v {
        for (k, val) in m {
            if let Some(ks) = k.as_str() {
                let vs = match val {
                    YamlValue::String(s) => s.clone(),
                    YamlValue::Number(n) => n.to_string(),
                    YamlValue::Bool(b) => b.to_string(),
                    _ => serde_norway::to_string(val).unwrap_or_default().trim().to_string(),
                };
                out.insert(ks.to_string(), vs);
            }
        }
    }
    out
}

fn expand_documents(yaml: &str) -> Result<Vec<YamlValue>> {
    let mut docs = Vec::new();
    for doc in serde_norway::Deserializer::from_str(yaml) {
        let val = YamlValue::deserialize(doc)
            .map_err(|e| anyhow!("Failed to parse Kubernetes YAML document: {}", e))?;
        if val.is_null() {
            continue;
        }
        // Unwrap `kind: List` (common in `kubectl get -o yaml` and `helm template`)
        if yaml_str(&val, "kind") == Some("List") {
            if let Some(YamlValue::Sequence(items)) = val.get("items") {
                for item in items {
                    if !item.is_null() {
                        docs.push(item.clone());
                    }
                }
                continue;
            }
        }
        docs.push(val);
    }
    Ok(docs)
}

fn is_wasm_artifact(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.ends_with(".wasm")
        || lower.ends_with(".cwasm")
        || lower.starts_with("s3://")
        || lower.starts_with("iroh://")
        || lower.contains("wasm")
}

fn policy_label(policy: &CellPolicy) -> &'static str {
    match policy {
        CellPolicy::Pinned => "pinned",
        CellPolicy::Elastic { idle_timeout, .. } if idle_timeout.as_secs() <= 15 => "mobile",
        CellPolicy::Elastic { .. } => "elastic",
    }
}

/// Import a single- or multi-document Kubernetes YAML manifest into an executable Nexus-IO `.md` document.
pub fn import_k8s_yaml(yaml: &str) -> Result<ImportReport> {
    let docs = expand_documents(yaml)?;
    if docs.is_empty() {
        return Err(anyhow!("No Kubernetes resources found in YAML input"));
    }

    let mut namespace: Option<String> = None;
    let mut config_maps: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut secrets: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut services: Vec<(String, BTreeMap<String, String>, Vec<u16>)> = Vec::new();
    let mut ingresses: Vec<(String, RouteSpec)> = Vec::new();
    let mut pvcs: Vec<String> = Vec::new();
    let mut workload_docs: Vec<YamlValue> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Pass 1: Index supporting resources (ConfigMap, Secret, Service, Ingress, PVC) and collect workloads.
    for doc in docs {
        let kind = yaml_str(&doc, "kind").unwrap_or("Unknown").to_string();
        let meta = doc.get("metadata");
        let name = meta
            .and_then(|m| yaml_str(m, "name"))
            .unwrap_or("unnamed")
            .to_string();
        if namespace.is_none() {
            if let Some(ns) = meta.and_then(|m| yaml_str(m, "namespace")) {
                if !ns.is_empty() {
                    namespace = Some(ns.to_string());
                }
            }
        }

        match kind.as_str() {
            "Namespace" => {
                if namespace.is_none() && !name.is_empty() {
                    namespace = Some(name);
                }
            }
            "ConfigMap" => {
                let data = yaml_map_to_btreemap(doc.get("data"));
                config_maps.insert(name, data);
            }
            "Secret" => {
                let mut merged = yaml_map_to_btreemap(doc.get("stringData"));
                let raw_b64 = yaml_map_to_btreemap(doc.get("data"));
                for (k, v) in raw_b64 {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(v.trim())
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or(v);
                    merged.insert(k, decoded);
                }
                secrets.insert(name, merged);
            }
            "Service" => {
                let spec = doc.get("spec");
                let selector = yaml_map_to_btreemap(spec.and_then(|s| s.get("selector")));
                let mut ports = Vec::new();
                if let Some(YamlValue::Sequence(ps)) = spec.and_then(|s| s.get("ports")) {
                    for p in ps {
                        if let Some(port) = p
                            .get("port")
                            .or_else(|| p.get("targetPort"))
                            .and_then(|x| x.as_u64())
                        {
                            ports.push(port as u16);
                        }
                    }
                }
                services.push((name, selector, ports));
            }
            "Ingress" => {
                if let Some(YamlValue::Sequence(rules)) =
                    doc.get("spec").and_then(|s| s.get("rules"))
                {
                    for rule in rules {
                        let host = yaml_str(rule, "host").map(|s| s.to_string());
                        if let Some(YamlValue::Sequence(paths)) =
                            rule.get("http").and_then(|h| h.get("paths"))
                        {
                            for p in paths {
                                let path = yaml_str(p, "path").unwrap_or("/").to_string();
                                let backend = p.get("backend").and_then(|b| b.get("service"));
                                let svc_name = backend
                                    .and_then(|s| yaml_str(s, "name"))
                                    .unwrap_or("")
                                    .to_string();
                                let port = backend
                                    .and_then(|s| s.get("port"))
                                    .and_then(|pt| pt.get("number"))
                                    .and_then(|n| n.as_u64())
                                    .unwrap_or(80) as u16;
                                if !svc_name.is_empty() {
                                    ingresses.push((
                                        svc_name,
                                        RouteSpec {
                                            host: host.clone(),
                                            path,
                                            port,
                                        },
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            "PersistentVolumeClaim" => {
                pvcs.push(name);
            }
            "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" => {
                workload_docs.push(doc);
            }
            "HorizontalPodAutoscaler" => {
                warnings.push(format!(
                    "HPA '{}' omitted: Nexus-IO elastic cells handle scale-to-zero and demand-driven wake natively.",
                    name
                ));
            }
            "ServiceAccount" | "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding" => {
                warnings.push(format!(
                    "{} '{}' omitted: map RBAC policies into Nexus-IO SecurityKernel IAM rules.",
                    kind, name
                ));
            }
            other => {
                warnings.push(format!(
                    "Unsupported Kubernetes resource {} '{}' skipped (review manually).",
                    other, name
                ));
            }
        }
    }

    let app = namespace.unwrap_or_else(|| "default".to_string());
    let mut md = String::new();
    md.push_str("---\n");
    md.push_str(&format!("app: {}\n", app));
    md.push_str("policy: elastic\n");
    md.push_str("---\n\n");
    md.push_str(&format!("# {} (Imported from Kubernetes)\n\n", app));

    let mut workloads = Vec::new();
    let mut referenced_configs: Vec<String> = Vec::new();

    // Pass 2: Translate each workload into a `## <name>` SystemNode section.
    for doc in workload_docs {
        let kind = yaml_str(&doc, "kind").unwrap_or("Deployment").to_string();
        let meta = doc.get("metadata");
        let name = meta
            .and_then(|m| yaml_str(m, "name"))
            .unwrap_or("service")
            .to_string();
        let annotations = yaml_map_to_btreemap(meta.and_then(|m| m.get("annotations")));

        // Policy inference: explicit annotation > kind default
        let policy = if let Some(p) = annotations.get("nexus.io/policy") {
            p.to_ascii_lowercase()
        } else if kind == "StatefulSet" || kind == "DaemonSet" {
            "pinned".to_string()
        } else {
            "elastic".to_string()
        };

        // Locate pod template (CronJob nests under spec.jobTemplate.spec.template)
        let template = if kind == "CronJob" {
            doc.get("spec")
                .and_then(|s| s.get("jobTemplate"))
                .and_then(|j| j.get("spec"))
                .and_then(|s| s.get("template"))
        } else {
            doc.get("spec").and_then(|s| s.get("template"))
        };

        let pod_labels = yaml_map_to_btreemap(
            template
                .and_then(|t| t.get("metadata"))
                .and_then(|m| m.get("labels")),
        );
        let pod_spec = template.and_then(|t| t.get("spec"));
        let primary_container = pod_spec
            .and_then(|s| s.get("containers"))
            .and_then(|c| c.as_sequence())
            .and_then(|seq| seq.first());

        let image = primary_container
            .and_then(|c| yaml_str(c, "image"))
            .map(|s| s.to_string());

        let mut env_map: BTreeMap<String, String> = BTreeMap::new();
        let mut ports: Vec<u16> = Vec::new();
        let mut resources_map: BTreeMap<String, String> = BTreeMap::new();
        let mut wasm_refs: Vec<String> = Vec::new();
        let mut storage_buckets: Vec<String> = Vec::new();

        if let Some(wasm_ann) = annotations.get("nexus.io/wasm") {
            for r in wasm_ann.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                wasm_refs.push(r.to_string());
            }
        }
        if let Some(img) = &image {
            if is_wasm_artifact(img) && !wasm_refs.contains(img) {
                wasm_refs.push(img.clone());
            }
        }

        if let Some(container) = primary_container {
            // Container ports
            if let Some(YamlValue::Sequence(cports)) = container.get("ports") {
                for p in cports {
                    if let Some(cp) = p.get("containerPort").and_then(|x| x.as_u64()) {
                        ports.push(cp as u16);
                    }
                }
            }

            // envFrom (ConfigMap / Secret references)
            if let Some(YamlValue::Sequence(env_from)) = container.get("envFrom") {
                for ef in env_from {
                    if let Some(cm_name) = ef.get("configMapRef").and_then(|r| yaml_str(r, "name")) {
                        referenced_configs.push(cm_name.to_string());
                        if let Some(cm) = config_maps.get(cm_name) {
                            for (k, v) in cm {
                                env_map.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    if let Some(sec_name) = ef.get("secretRef").and_then(|r| yaml_str(r, "name")) {
                        referenced_configs.push(sec_name.to_string());
                        if let Some(sec) = secrets.get(sec_name) {
                            for (k, v) in sec {
                                env_map.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
            }

            // Direct env entries
            if let Some(YamlValue::Sequence(envs)) = container.get("env") {
                for e in envs {
                    if let Some(k) = yaml_str(e, "name") {
                        if let Some(v) = yaml_str(e, "value") {
                            env_map.insert(k.to_string(), v.to_string());
                        } else if let Some(cm_ref) =
                            e.get("valueFrom").and_then(|vf| vf.get("configMapKeyRef"))
                        {
                            if let (Some(cm_name), Some(cm_key)) =
                                (yaml_str(cm_ref, "name"), yaml_str(cm_ref, "key"))
                            {
                                referenced_configs.push(cm_name.to_string());
                                if let Some(val) =
                                    config_maps.get(cm_name).and_then(|m| m.get(cm_key))
                                {
                                    env_map.insert(k.to_string(), val.clone());
                                }
                            }
                        } else if let Some(sec_ref) =
                            e.get("valueFrom").and_then(|vf| vf.get("secretKeyRef"))
                        {
                            if let (Some(sec_name), Some(sec_key)) =
                                (yaml_str(sec_ref, "name"), yaml_str(sec_ref, "key"))
                            {
                                referenced_configs.push(sec_name.to_string());
                                if let Some(val) =
                                    secrets.get(sec_name).and_then(|m| m.get(sec_key))
                                {
                                    env_map.insert(k.to_string(), val.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Resource limits & requests (including nvidia.com/gpu)
            if let Some(res) = container.get("resources") {
                for (k, v) in yaml_map_to_btreemap(res.get("requests")) {
                    resources_map.insert(k, v);
                }
                for (k, v) in yaml_map_to_btreemap(res.get("limits")) {
                    resources_map.insert(k, v);
                }
            }

            // Volume mounts -> BlobBridge bucket signals
            if let Some(YamlValue::Sequence(mounts)) = container.get("volumeMounts") {
                for m in mounts {
                    if let Some(vname) = yaml_str(m, "name") {
                        storage_buckets.push(vname.to_string());
                    }
                }
            }
        }

        // StatefulSet volumeClaimTemplates
        if let Some(YamlValue::Sequence(vcts)) = doc.get("spec").and_then(|s| s.get("volumeClaimTemplates")) {
            for vct in vcts {
                if let Some(vname) = vct.get("metadata").and_then(|m| yaml_str(m, "name")) {
                    if !storage_buckets.contains(&vname.to_string()) {
                        storage_buckets.push(vname.to_string());
                    }
                }
            }
        }

        // Match Services & Ingresses by selector or name
        let mut routes: Vec<RouteSpec> = Vec::new();
        for (svc_name, selector, svc_ports) in &services {
            let selector_matches = !selector.is_empty()
                && selector
                    .iter()
                    .all(|(k, v)| pod_labels.get(k) == Some(v));
            let name_matches = svc_name == &name;
            if selector_matches || name_matches {
                for p in svc_ports {
                    if !ports.contains(p) {
                        ports.push(*p);
                    }
                }
                let mut matched_ingress = false;
                for (ing_svc, route) in &ingresses {
                    if ing_svc == svc_name {
                        routes.push(route.clone());
                        matched_ingress = true;
                    }
                }
                if !matched_ingress {
                    if let Some(&first_port) = svc_ports.first() {
                        routes.push(RouteSpec {
                            host: None,
                            path: format!("/cells/{}/{}", app, name),
                            port: first_port,
                        });
                    }
                }
            }
        }

        // Emit Markdown section for this SystemNode
        md.push_str(&format!("## {}\n", name));
        md.push_str(&format!("<!-- policy: {} -->\n\n", policy));
        md.push_str(&format!(
            "- **Source Kind:** `{}`{}\n\n",
            kind,
            image
                .as_ref()
                .map(|i| format!(" · **Image:** `{}`", i))
                .unwrap_or_default()
        ));

        // Signal JSON block (persisted to cell KV on deploy & used by exporter for round-trip)
        let signal_obj = json!({
            "k8s_kind": kind,
            "image": image,
            "ports": ports,
            "env": env_map,
            "resources": resources_map,
            "routes": routes,
            "storage_buckets": storage_buckets,
        });
        md.push_str("```json\n");
        md.push_str(&serde_json::to_string_pretty(&signal_obj)?);
        md.push_str("\n```\n\n");

        // Emit Wasm Crystal references if present
        for wref in &wasm_refs {
            md.push_str(&format!("```wasm src=\"{}\"\n```\n\n", wref));
        }

        // Emit a deployable TypeScript cell scaffold so the imported `.md` runs immediately in CellManager
        let default_port = ports.first().copied().unwrap_or(8080);
        md.push_str("```ts\n");
        md.push_str(&format!(
            "// Imported from Kubernetes {} '{}'\n",
            kind, name
        ));
        md.push_str(&format!(
            "function health(): string {{ return \"ok:{}:{}\"; }}\n",
            name, default_port
        ));
        md.push_str("function fetch(): string { return health(); }\n");
        md.push_str("```\n\n");

        workloads.push(ImportedWorkload {
            kind,
            name,
            namespace: app.clone(),
            policy,
            image,
            wasm_refs,
            ports,
            routes,
        });
    }

    // Include standalone PVC / unreferenced ConfigMap notes if any
    for pvc in pvcs {
        warnings.push(format!(
            "PersistentVolumeClaim '{}' detected: map persistent blobs to BlobBridge or SurrealDB cell storage.",
            pvc
        ));
    }
    for cm_name in config_maps.keys() {
        if !referenced_configs.contains(cm_name) {
            warnings.push(format!(
                "Unreferenced ConfigMap '{}' was not bound to any workload.",
                cm_name
            ));
        }
    }

    if !warnings.is_empty() {
        md.push_str("> **Migration Notes**\n");
        for w in &warnings {
            md.push_str(&format!("> - {}\n", w));
        }
        md.push('\n');
    }

    Ok(ImportReport {
        app,
        markdown: md,
        workloads,
        warnings,
    })
}

/// Export a declarative Nexus-IO `.md` service document into standard multi-document Kubernetes YAML.
pub fn export_k8s_yaml(md: &str, opts: ExportOptions) -> Result<String> {
    let nodes = parse_markdown_nodes(md);
    if nodes.is_empty() {
        return Err(anyhow!("No SystemNodes found in Markdown document"));
    }

    let app = nodes[0].app.clone();
    let mut manifests: Vec<JsonValue> = Vec::new();

    if app != "default" {
        manifests.push(json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": app,
                "labels": {
                    "app.kubernetes.io/managed-by": "nexus-io"
                }
            }
        }));
    }

    for node in &nodes {
        // K8s DNS-1123 name uses '-' instead of '_'
        let k8s_name = node.cell_id.replace('_', "-");
        let pol = policy_label(&node.policy);
        let is_stateful = matches!(node.policy, CellPolicy::Pinned);

        // Parse primary JSON signal block if present (round-trips env, resources, routes, ports, image)
        let mut parsed_signal: Option<JsonValue> = None;
        for raw in node.signals.values() {
            if let Ok(v) = serde_json::from_str::<JsonValue>(raw) {
                parsed_signal = Some(v);
                break;
            }
        }

        let image = parsed_signal
            .as_ref()
            .and_then(|s| s.get("image"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| opts.runtime_image.clone());

        let mut env_list: Vec<JsonValue> = vec![
            json!({ "name": "NEXUS_APP", "value": node.app }),
            json!({ "name": "NEXUS_CELL_ID", "value": node.cell_id }),
            json!({ "name": "NEXUS_POLICY", "value": pol }),
        ];

        if !node.wasm_refs.is_empty() {
            env_list.push(json!({
                "name": "NEXUS_WASM_REFS",
                "value": node.wasm_refs.join(",")
            }));
        }

        if let Some(JsonValue::Object(env_obj)) = parsed_signal.as_ref().and_then(|s| s.get("env")) {
            for (k, v) in env_obj {
                let val_str = v
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string());
                env_list.push(json!({ "name": k, "value": val_str }));
            }
        }

        let mut limits_map = JsonMap::new();
        if let Some(JsonValue::Object(res_obj)) =
            parsed_signal.as_ref().and_then(|s| s.get("resources"))
        {
            for (k, v) in res_obj {
                if let Some(vs) = v.as_str() {
                    limits_map.insert(k.clone(), JsonValue::String(vs.to_string()));
                }
            }
        }

        let ports: Vec<u16> = parsed_signal
            .as_ref()
            .and_then(|s| s.get("ports"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u16))
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![opts.default_port]);

        let primary_port = ports[0];

        // 1. ConfigMap carrying embedded TS/SQL/SurrealQL/WAT blocks
        let cm_name = format!("{}-config", k8s_name);
        let mut cm_data = JsonMap::new();
        if !node.script_blocks.is_empty() {
            cm_data.insert(
                "cell.ts".to_string(),
                JsonValue::String(node.script_blocks.join("\n")),
            );
        }
        if !node.sql_blocks.is_empty() {
            cm_data.insert(
                "schema.sql".to_string(),
                JsonValue::String(node.sql_blocks.join("\n")),
            );
        }
        if !node.surql_blocks.is_empty() {
            cm_data.insert(
                "schema.surql".to_string(),
                JsonValue::String(node.surql_blocks.join("\n")),
            );
        }
        if !node.wat_blocks.is_empty() {
            cm_data.insert(
                "crystal.wat".to_string(),
                JsonValue::String(node.wat_blocks.join("\n")),
            );
        }

        if !cm_data.is_empty() {
            manifests.push(json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": cm_name,
                    "namespace": node.app
                },
                "data": cm_data
            }));
        }

        // 2. Workload (StatefulSet for pinned, Deployment for elastic/mobile)
        let mut annotations = JsonMap::new();
        annotations.insert("nexus.io/policy".to_string(), JsonValue::String(pol.to_string()));
        if !node.wasm_refs.is_empty() {
            annotations.insert(
                "nexus.io/wasm".to_string(),
                JsonValue::String(node.wasm_refs.join(",")),
            );
        }

        let mut container = json!({
            "name": k8s_name,
            "image": image,
            "ports": ports.iter().map(|p| json!({ "containerPort": p })).collect::<Vec<_>>(),
            "env": env_list,
        });
        if !limits_map.is_empty() {
            container["resources"] = json!({ "limits": limits_map });
        }
        if !cm_data.is_empty() {
            container["volumeMounts"] = json!([{
                "name": "nexus-config",
                "mountPath": "/etc/nexus"
            }]);
        }

        let mut pod_spec = json!({
            "containers": [container]
        });
        if !cm_data.is_empty() {
            pod_spec["volumes"] = json!([{
                "name": "nexus-config",
                "configMap": { "name": cm_name }
            }]);
        }

        let labels = json!({
            "app": k8s_name,
            "nexus.io/app": node.app,
            "nexus.io/policy": pol
        });

        let workload = if is_stateful {
            let mut spec = json!({
                "serviceName": k8s_name,
                "replicas": 1,
                "selector": { "matchLabels": { "app": k8s_name } },
                "template": {
                    "metadata": { "labels": labels },
                    "spec": pod_spec
                }
            });
            if !node.sql_blocks.is_empty() || !node.surql_blocks.is_empty() {
                spec["volumeClaimTemplates"] = json!([{
                    "metadata": { "name": "nexus-state" },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": { "requests": { "storage": "1Gi" } }
                    }
                }]);
            }
            json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {
                    "name": k8s_name,
                    "namespace": node.app,
                    "annotations": annotations
                },
                "spec": spec
            })
        } else {
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": k8s_name,
                    "namespace": node.app,
                    "annotations": annotations
                },
                "spec": {
                    "replicas": 1,
                    "selector": { "matchLabels": { "app": k8s_name } },
                    "template": {
                        "metadata": { "labels": labels },
                        "spec": pod_spec
                    }
                }
            })
        };
        manifests.push(workload);

        // 3. ClusterIP Service
        manifests.push(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": k8s_name,
                "namespace": node.app
            },
            "spec": {
                "selector": { "app": k8s_name },
                "ports": ports.iter().map(|p| json!({ "port": p, "targetPort": p })).collect::<Vec<_>>()
            }
        }));

        // 4. Ingress if routes with hosts/paths are present
        if let Some(routes_val) = parsed_signal.as_ref().and_then(|s| s.get("routes")) {
            if let Ok(routes) = serde_json::from_value::<Vec<RouteSpec>>(routes_val.clone()) {
                let host_routes: Vec<RouteSpec> =
                    routes.into_iter().filter(|r| r.host.is_some()).collect();
                if !host_routes.is_empty() {
                    let rules: Vec<JsonValue> = host_routes
                        .into_iter()
                        .map(|r| {
                            json!({
                                "host": r.host.unwrap_or_default(),
                                "http": {
                                    "paths": [{
                                        "path": r.path,
                                        "pathType": "Prefix",
                                        "backend": {
                                            "service": {
                                                "name": k8s_name,
                                                "port": { "number": if r.port > 0 { r.port } else { primary_port } }
                                            }
                                        }
                                    }]
                                }
                            })
                        })
                        .collect();
                    manifests.push(json!({
                        "apiVersion": "networking.k8s.io/v1",
                        "kind": "Ingress",
                        "metadata": {
                            "name": format!("{}-ingress", k8s_name),
                            "namespace": node.app
                        },
                        "spec": { "rules": rules }
                    }));
                }
            }
        }
    }

    let mut out = String::new();
    for (idx, m) in manifests.iter().enumerate() {
        if idx > 0 {
            out.push_str("---\n");
        }
        out.push_str(&serde_norway::to_string(m)?);
    }
    Ok(out)
}

/// Nushell/CLI command: `k8s import <path.yaml> [--out <path.md>] [--deploy]`
#[derive(Clone)]
pub struct K8sImportCommand {
    pub db: Arc<Database>,
    pub bridge: Arc<BlobBridge>,
}

impl Command for K8sImportCommand {
    fn name(&self) -> &str {
        "k8s import"
    }

    fn description(&self) -> &str {
        "Import Kubernetes YAML manifests into a Nexus-IO declarative Markdown (.md) service file"
    }

    fn signature(&self) -> Signature {
        Signature::build("k8s import")
            .required("path", SyntaxShape::String, "Path to Kubernetes YAML file")
            .named("out", SyntaxShape::String, "Write generated .md to this file", Some('o'))
            .switch("deploy", "Immediately deploy imported cells into Nexus-IO", Some('d'))
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let path: String = call.req(engine_state, stack, 0)?;
        let out_path: Option<String> = call.get_flag(engine_state, stack, "out")?;
        let should_deploy = call.has_flag(engine_state, stack, "deploy")?;

        let yaml_src = std::fs::read_to_string(&path).map_err(|e| {
            crate::shell_err(
                "K8s Import IO Error",
                format!("Failed to read '{}': {}", path, e),
                Some(span),
                None,
            )
        })?;

        let report = import_k8s_yaml(&yaml_src).map_err(|e| {
            crate::shell_err("K8s Import Error", e.to_string(), Some(span), None)
        })?;

        if let Some(ref dest) = out_path {
            std::fs::write(dest, &report.markdown).map_err(|e| {
                crate::shell_err(
                    "K8s Import IO Error",
                    format!("Failed to write '{}': {}", dest, e),
                    Some(span),
                    None,
                )
            })?;
        }

        if should_deploy {
            let db = self.db.clone();
            let bridge = self.bridge.clone();
            let md = report.markdown.clone();
            let nodes = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    let manager = CellManager::new(db.clone(), bridge);
                    deploy_markdown(&manager, db.as_ref(), &md).await
                })
            })
            .map_err(|e| {
                crate::shell_err("K8s Deploy Error", e.to_string(), Some(span), None)
            })?;

            let summary = format!(
                "✅ Imported & deployed {} cell(s) into app '{}' ({} warning(s))",
                nodes.len(),
                report.app,
                report.warnings.len()
            );
            return Ok(PipelineData::Value(Value::string(summary, span), None));
        }

        let output = if let Some(dest) = out_path {
            format!(
                "✅ Imported {} workload(s) to '{}' ({} warning(s))",
                report.workloads.len(),
                dest,
                report.warnings.len()
            )
        } else {
            report.markdown
        };
        Ok(PipelineData::Value(Value::string(output, span), None))
    }
}

/// Nushell/CLI command: `k8s export <path.md> [--out <path.yaml>] [--image <image>]`
#[derive(Clone)]
pub struct K8sExportCommand;

impl Command for K8sExportCommand {
    fn name(&self) -> &str {
        "k8s export"
    }

    fn description(&self) -> &str {
        "Export a Nexus-IO Markdown (.md) service file into standard Kubernetes YAML manifests"
    }

    fn signature(&self) -> Signature {
        Signature::build("k8s export")
            .required("path", SyntaxShape::String, "Path to Nexus-IO .md service file")
            .named("out", SyntaxShape::String, "Write generated YAML to this file", Some('o'))
            .named("image", SyntaxShape::String, "Override runtime container image", Some('i'))
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let path: String = call.req(engine_state, stack, 0)?;
        let out_path: Option<String> = call.get_flag(engine_state, stack, "out")?;
        let image: Option<String> = call.get_flag(engine_state, stack, "image")?;

        let md_src = std::fs::read_to_string(&path).map_err(|e| {
            crate::shell_err(
                "K8s Export IO Error",
                format!("Failed to read '{}': {}", path, e),
                Some(span),
                None,
            )
        })?;

        let mut opts = ExportOptions::default();
        if let Some(img) = image {
            opts.runtime_image = img;
        }

        let yaml = export_k8s_yaml(&md_src, opts).map_err(|e| {
            crate::shell_err("K8s Export Error", e.to_string(), Some(span), None)
        })?;

        if let Some(dest) = out_path {
            std::fs::write(&dest, &yaml).map_err(|e| {
                crate::shell_err(
                    "K8s Export IO Error",
                    format!("Failed to write '{}': {}", dest, e),
                    Some(span),
                    None,
                )
            })?;
            let msg = format!("✅ Exported Kubernetes manifests to '{}'", dest);
            return Ok(PipelineData::Value(Value::string(msg, span), None));
        }

        Ok(PipelineData::Value(Value::string(yaml, span), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::engine::local::Mem;
    use surrealdb::Surreal;

    const SAMPLE_K8S: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
  namespace: payments
data:
  LOG_LEVEL: info
---
apiVersion: v1
kind: Secret
metadata:
  name: api-secret
  namespace: payments
stringData:
  API_KEY: super-secret
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-api
  namespace: payments
  annotations:
    nexus.io/wasm: "s3://crystals/pricing.wasm"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: checkout-api
  template:
    metadata:
      labels:
        app: checkout-api
    spec:
      containers:
        - name: checkout-api
          image: ghcr.io/acme/checkout:1.0
          ports:
            - containerPort: 8080
          envFrom:
            - configMapRef:
                name: api-config
            - secretRef:
                name: api-secret
          resources:
            limits:
              nvidia.com/gpu: "1"
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ledger-store
  namespace: payments
spec:
  serviceName: ledger-store
  replicas: 1
  selector:
    matchLabels:
      app: ledger-store
  template:
    metadata:
      labels:
        app: ledger-store
    spec:
      containers:
        - name: ledger-store
          image: ghcr.io/acme/ledger:1.0
          ports:
            - containerPort: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: checkout-api
  namespace: payments
spec:
  selector:
    app: checkout-api
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: checkout-ingress
  namespace: payments
spec:
  rules:
    - host: pay.example.com
      http:
        paths:
          - path: /v1/checkout
            pathType: Prefix
            backend:
              service:
                name: checkout-api
                port:
                  number: 8080
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: checkout-hpa
  namespace: payments
spec:
  minReplicas: 1
  maxReplicas: 10
"#;

    #[test]
    fn k8s_import_deploy_and_export_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_stack_size(16 * 1024 * 1024)
                    .build()
                    .unwrap();
                rt.block_on(Box::pin(async {
                    // 1. Import K8s YAML -> Nexus .md
                    let report = import_k8s_yaml(SAMPLE_K8S).unwrap();
                    assert_eq!(report.app, "payments");
                    assert_eq!(report.workloads.len(), 2);
                    assert_eq!(report.workloads[0].name, "checkout-api");
                    assert_eq!(report.workloads[0].policy, "elastic");
                    assert_eq!(
                        report.workloads[0].wasm_refs,
                        vec!["s3://crystals/pricing.wasm"]
                    );
                    assert_eq!(report.workloads[0].routes.len(), 1);
                    assert_eq!(
                        report.workloads[0].routes[0].host.as_deref(),
                        Some("pay.example.com")
                    );
                    assert_eq!(report.workloads[1].name, "ledger-store");
                    assert_eq!(report.workloads[1].policy, "pinned");
                    assert!(report.warnings.iter().any(|w| w.contains("HPA")));

                    // 2. Deploy imported .md directly into CellManager & verify live execution
                    let client = Surreal::new::<Mem>(()).await.unwrap();
                    client.use_ns("nexus").use_db("system").await.unwrap();
                    let db = Arc::new(Database { client });
                    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
                    let manager = CellManager::new(db.clone(), blobs);

                    let nodes = deploy_markdown(&manager, db.as_ref(), &report.markdown)
                        .await
                        .unwrap();
                    assert_eq!(nodes.len(), 2);
                    assert!(matches!(nodes[0].policy, CellPolicy::Elastic { .. }));
                    assert!(matches!(nodes[1].policy, CellPolicy::Pinned));

                    let health = manager
                        .eval_in_cell("payments", "checkout_api", "health()")
                        .await
                        .unwrap();
                    assert_eq!(health, "ok:checkout-api:8080");

                    // 3. Export .md -> standard Kubernetes YAML
                    let exported_yaml =
                        export_k8s_yaml(&report.markdown, ExportOptions::default()).unwrap();
                    assert!(exported_yaml.contains("kind: Namespace"));
                    assert!(exported_yaml.contains("kind: Deployment"));
                    assert!(exported_yaml.contains("kind: StatefulSet"));
                    assert!(exported_yaml.contains("kind: Ingress"));
                    assert!(exported_yaml.contains("nvidia.com/gpu"));

                    // 4. Re-import exported YAML to prove lossless round-trip of core metadata
                    let round_trip = import_k8s_yaml(&exported_yaml).unwrap();
                    assert_eq!(round_trip.app, "payments");
                    assert_eq!(round_trip.workloads.len(), 2);
                    assert_eq!(round_trip.workloads[0].policy, "elastic");
                    assert_eq!(
                        round_trip.workloads[0].wasm_refs,
                        vec!["s3://crystals/pricing.wasm"]
                    );
                    assert_eq!(
                        round_trip.workloads[0].routes[0].host.as_deref(),
                        Some("pay.example.com")
                    );
                    assert_eq!(round_trip.workloads[1].policy, "pinned");
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
