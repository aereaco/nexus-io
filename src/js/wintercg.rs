use base64::Engine as _;
use quickrs_core::context::Context;
use quickrs_core::object::{ObjectData, PropFlags, Property};
use quickrs_core::value::{JsResult, PropKey, Value as JsValue};
use rand::RngCore;
use uuid::Uuid;

/// Install the WinterCG Minimum Common Web Platform API globals (`Headers`, `URL`,
/// `URLSearchParams`, `Request`, `Response`, `TextEncoder`, `TextDecoder`, `atob`, `btoa`,
/// `crypto`, `console`, `structuredClone`, `queueMicrotask`) plus a thin `Deno.openKv()` bridge
/// into a `quickrs-core` `Context`.
pub fn install_wintercg_globals(ctx: &mut Context) {
    let global = ctx.global();

    let register = |c: &mut Context, name: &str, arity: u32, func: quickrs_core::object::NativeFn| {
        let f = c.new_native_function(func, name, arity, 0);
        let key = PropKey::from_string(&c.intern(name));
        c.define_own(&global, key, Property::data(JsValue::Object(f), PropFlags::C_W_E));
    };

    register(ctx, "__wcg_random_uuid", 0, wcg_random_uuid_cb);
    register(ctx, "__wcg_random_bytes", 1, wcg_random_bytes_cb);
    register(ctx, "__wcg_btoa", 1, wcg_btoa_cb);
    register(ctx, "__wcg_atob", 1, wcg_atob_cb);
    register(ctx, "__wcg_utf8_encode", 1, wcg_utf8_encode_cb);
    register(ctx, "__wcg_utf8_decode", 1, wcg_utf8_decode_cb);
    register(ctx, "__wcg_digest_hex", 2, wcg_digest_hex_cb);
    register(ctx, "__wcg_console", 2, wcg_console_cb);

    let _ = ctx.eval(WINTERCG_SHIM_JS);
}

fn val_to_string(v: &JsValue) -> String {
    match v {
        JsValue::Undefined | JsValue::Uninitialized => String::new(),
        JsValue::Null => "null".to_string(),
        JsValue::Bool(b) => b.to_string(),
        JsValue::Int(i) => i.to_string(),
        JsValue::Float(f) => f.to_string(),
        JsValue::Str(s) => s.to_string(),
        other => format!("{:?}", other),
    }
}

fn wcg_random_uuid_cb(
    ctx: &mut Context,
    _this: &JsValue,
    _args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let id = Uuid::new_v4().to_string();
    Ok(JsValue::Str(ctx.intern(&id)))
}

fn wcg_random_bytes_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let len = match args.first() {
        Some(JsValue::Int(n)) if *n > 0 => (*n as usize).min(65536),
        Some(JsValue::Float(f)) if *f > 0.0 => (*f as usize).min(65536),
        _ => 0,
    };
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    let elems: Vec<JsValue> = buf.into_iter().map(|b| JsValue::Int(b as i32)).collect();
    let arr = ctx.new_array_from(elems);
    Ok(JsValue::Object(arr))
}

fn wcg_btoa_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let input = args.first().map(val_to_string).unwrap_or_default();
    let encoded = base64::engine::general_purpose::STANDARD.encode(input.as_bytes());
    Ok(JsValue::Str(ctx.intern(&encoded)))
}

fn wcg_atob_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let input = args.first().map(val_to_string).unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    Ok(JsValue::Str(ctx.intern(&decoded)))
}

fn wcg_utf8_encode_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let input = args.first().map(val_to_string).unwrap_or_default();
    let elems: Vec<JsValue> = input
        .as_bytes()
        .iter()
        .map(|&b| JsValue::Int(b as i32))
        .collect();
    let arr = ctx.new_array_from(elems);
    Ok(JsValue::Object(arr))
}

fn wcg_utf8_decode_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let mut bytes = Vec::new();
    if let Some(JsValue::Object(obj)) = args.first() {
        let borrowed = obj.borrow();
        if let ObjectData::Array(arr) = &borrowed.data {
            for elem in &arr.elements {
                match elem {
                    JsValue::Int(n) => bytes.push((*n & 0xFF) as u8),
                    JsValue::Float(f) => bytes.push((*f as i32 & 0xFF) as u8),
                    _ => {}
                }
            }
        }
    }
    let decoded = String::from_utf8_lossy(&bytes).to_string();
    Ok(JsValue::Str(ctx.intern(&decoded)))
}

fn wcg_digest_hex_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let _alg = args.first().map(val_to_string).unwrap_or_else(|| "BLAKE3".into());
    let data = args.get(1).map(val_to_string).unwrap_or_default();
    let hash = blake3::hash(data.as_bytes()).to_hex().to_string();
    Ok(JsValue::Str(ctx.intern(&hash)))
}

fn wcg_console_cb(
    _ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let level = args.first().map(val_to_string).unwrap_or_else(|| "log".into());
    let msg = args.get(1).map(val_to_string).unwrap_or_default();
    if level == "error" || level == "warn" {
        eprintln!("[cell:{}] {}", level, msg);
    } else {
        println!("[cell:{}] {}", level, msg);
    }
    Ok(JsValue::Undefined)
}

const WINTERCG_SHIM_JS: &str = r#"
(function () {
    globalThis.btoa = function btoa(str) { return __wcg_btoa(String(str)); };
    globalThis.atob = function atob(str) { return __wcg_atob(String(str)); };

    globalThis.console = {
        log(...args)   { __wcg_console("log",   args.map(String).join(" ")); },
        info(...args)  { __wcg_console("info",  args.map(String).join(" ")); },
        warn(...args)  { __wcg_console("warn",  args.map(String).join(" ")); },
        error(...args) { __wcg_console("error", args.map(String).join(" ")); },
        debug(...args) { __wcg_console("debug", args.map(String).join(" ")); },
    };

    globalThis.structuredClone = function structuredClone(val) {
        if (val === null || typeof val !== "object") return val;
        return JSON.parse(JSON.stringify(val));
    };

    globalThis.queueMicrotask = function queueMicrotask(fn) {
        Promise.resolve().then(fn);
    };

    globalThis.TextEncoder = class TextEncoder {
        constructor() { this.encoding = "utf-8"; }
        encode(input = "") {
            const arr = __wcg_utf8_encode(String(input));
            return typeof Uint8Array !== "undefined" ? new Uint8Array(arr) : arr;
        }
    };

    globalThis.TextDecoder = class TextDecoder {
        constructor(label = "utf-8") { this.encoding = label; }
        decode(input) {
            if (!input) return "";
            const arr = Array.from(input);
            return __wcg_utf8_decode(arr);
        }
    };

    globalThis.crypto = {
        randomUUID() { return __wcg_random_uuid(); },
        getRandomValues(typedArray) {
            const bytes = __wcg_random_bytes(typedArray.length);
            for (let i = 0; i < typedArray.length; i++) {
                typedArray[i] = bytes[i];
            }
            return typedArray;
        },
        subtle: {
            async digest(algorithm, data) {
                const alg = typeof algorithm === "string" ? algorithm : (algorithm?.name || "BLAKE3");
                const payload = typeof data === "string"
                    ? data
                    : __wcg_utf8_decode(Array.from(data));
                return __wcg_digest_hex(alg, payload);
            }
        }
    };

    globalThis.Headers = class Headers {
        constructor(init) {
            this._map = Object.create(null);
            if (init instanceof Headers) {
                for (const [k, v] of init.entries()) this.set(k, v);
            } else if (Array.isArray(init)) {
                for (const [k, v] of init) this.append(k, v);
            } else if (init && typeof init === "object") {
                for (const k of Object.keys(init)) this.set(k, init[k]);
            }
        }
        get(name) {
            const k = String(name).toLowerCase();
            return k in this._map ? this._map[k] : null;
        }
        set(name, value) {
            this._map[String(name).toLowerCase()] = String(value);
        }
        append(name, value) {
            const k = String(name).toLowerCase();
            this._map[k] = k in this._map ? `${this._map[k]}, ${value}` : String(value);
        }
        has(name) { return String(name).toLowerCase() in this._map; }
        delete(name) { delete this._map[String(name).toLowerCase()]; }
        entries() { return Object.entries(this._map); }
        keys() { return Object.keys(this._map); }
        values() { return Object.values(this._map); }
        forEach(cb) { for (const [k, v] of this.entries()) cb(v, k, this); }
    };

    globalThis.URLSearchParams = class URLSearchParams {
        constructor(init = "") {
            this._pairs = [];
            if (typeof init === "string") {
                const s = init.startsWith("?") ? init.slice(1) : init;
                if (s.length > 0) {
                    for (const part of s.split("&")) {
                        const idx = part.indexOf("=");
                        if (idx === -1) {
                            this._pairs.push([decodeURIComponent(part), ""]);
                        } else {
                            this._pairs.push([
                                decodeURIComponent(part.slice(0, idx)),
                                decodeURIComponent(part.slice(idx + 1)),
                            ]);
                        }
                    }
                }
            } else if (init && typeof init === "object") {
                for (const [k, v] of Object.entries(init)) {
                    this._pairs.push([String(k), String(v)]);
                }
            }
        }
        get(name) {
            const found = this._pairs.find(([k]) => k === name);
            return found ? found[1] : null;
        }
        getAll(name) { return this._pairs.filter(([k]) => k === name).map(([, v]) => v); }
        has(name) { return this._pairs.some(([k]) => k === name); }
        append(name, value) { this._pairs.push([String(name), String(value)]); }
        set(name, value) {
            this.delete(name);
            this._pairs.push([String(name), String(value)]);
        }
        delete(name) { this._pairs = this._pairs.filter(([k]) => k !== name); }
        entries() { return this._pairs.slice(); }
        toString() {
            return this._pairs
                .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
                .join("&");
        }
    };

    globalThis.URL = class URL {
        constructor(input, base) {
            let full = String(input);
            if (base && !full.includes("://")) {
                const b = new URL(base);
                full = `${b.origin}${full.startsWith("/") ? "" : "/"}${full}`;
            }
            const m = full.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)\/\/([^/:?#]+)(?::(\d+))?([^?#]*)(\?[^#]*)?(#.*)?$/);
            if (!m) throw new TypeError(`Invalid URL: ${full}`);
            this.protocol = m[1].toLowerCase();
            this.hostname = m[2];
            this.port = m[3] || "";
            this.host = this.port ? `${this.hostname}:${this.port}` : this.hostname;
            this.origin = `${this.protocol}//${this.host}`;
            this.pathname = m[4] || "/";
            this.search = m[5] || "";
            this.hash = m[6] || "";
            this.searchParams = new URLSearchParams(this.search);
            this.href = full;
        }
        toString() { return this.href; }
    };

    globalThis.Request = class Request {
        constructor(input, init = {}) {
            if (input instanceof Request) {
                this.url = input.url;
                this.method = (init.method || input.method || "GET").toUpperCase();
                this.headers = new Headers(init.headers || input.headers);
                this._body = init.body !== undefined ? String(init.body) : input._body;
            } else {
                this.url = String(input);
                this.method = (init.method || "GET").toUpperCase();
                this.headers = new Headers(init.headers);
                this._body = init.body !== undefined ? String(init.body) : "";
            }
        }
        async text() { return this._body; }
        async json() { return JSON.parse(this._body || "null"); }
        clone() { return new Request(this); }
    };

    globalThis.Response = class Response {
        constructor(body = "", init = {}) {
            this._body = body === null || body === undefined ? "" : String(body);
            this.status = init.status !== undefined ? Number(init.status) : 200;
            this.statusText = init.statusText !== undefined ? String(init.statusText) : (this.status === 200 ? "OK" : "");
            this.ok = this.status >= 200 && this.status < 300;
            this.headers = new Headers(init.headers);
        }
        async text() { return this._body; }
        async json() { return JSON.parse(this._body || "null"); }
        static json(data, init = {}) {
            const headers = new Headers(init.headers);
            if (!headers.has("content-type")) headers.set("content-type", "application/json");
            return new Response(JSON.stringify(data), { ...init, headers });
        }
        static redirect(url, status = 302) {
            return new Response("", { status, headers: { location: String(url) } });
        }
    };

    // Thin Deno Deploy compatibility bridge (`Deno.openKv()` backed by `ctx.storage`)
    if (typeof globalThis.Deno === "undefined") {
        globalThis.Deno = {
            openKv() {
                return {
                    get(key) {
                        const k = Array.isArray(key) ? key.join("/") : String(key);
                        const v = globalThis.ctx?.storage?.get(k) ?? null;
                        return { key, value: v };
                    },
                    set(key, val) {
                        const k = Array.isArray(key) ? key.join("/") : String(key);
                        globalThis.ctx?.storage?.put(k, val);
                        return { ok: true };
                    },
                    delete(key) {
                        const k = Array.isArray(key) ? key.join("/") : String(key);
                        globalThis.ctx?.storage?.delete(k);
                    }
                };
            }
        };
    }
})();
"#;

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use crate::js::cell::{CellManager, CellPolicy};
    use crate::storage::BlobBridge;
    use std::sync::Arc;

    #[test]
    fn wintercg_globals_work_inside_cell_manager() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = Arc::new(Database::open_mem());
                    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
                    let manager = CellManager::new(db, blobs);

                    let script = r#"
                        function testWinterCG() {
                            const url = new URL("https://nexus.io:8443/cells/app/1?mode=fast&tag=wcg");
                            const h = new Headers({ "X-Custom": "hello" });
                            const enc = new TextEncoder().encode("hi");
                            const dec = new TextDecoder().decode(enc);
                            const b64 = atob(btoa("nexus"));
                            const uuid = crypto.randomUUID();
                            const rnd = new Uint8Array(4);
                            crypto.getRandomValues(rnd);
                            const req = new Request(url.href, { method: "POST", headers: h, body: '{"ok":true}' });
                            const res = Response.json({ host: url.hostname, mode: url.searchParams.get("mode"), dec, b64, hasUuid: uuid.length === 36, header: req.headers.get("x-custom") });
                            const kv = Deno.openKv();
                            kv.set(["pref", "theme"], "dark");
                            const got = kv.get(["pref", "theme"]).value;
                            return `${res.status}|${res.headers.get("content-type")}|${got}|${res._body}`;
                        }
                    "#;

                    manager
                        .wake("wcg_app", "cell_1", CellPolicy::Pinned, script.to_string())
                        .await
                        .unwrap();

                    let out = manager
                        .eval_in_cell("wcg_app", "cell_1", "testWinterCG()")
                        .await
                        .unwrap();
                    assert!(out.starts_with("200|application/json|dark|"), "unexpected: {}", out);
                    assert!(out.contains("\"host\":\"nexus.io\""), "unexpected: {}", out);
                    assert!(out.contains("\"mode\":\"fast\""), "unexpected: {}", out);
                    assert!(out.contains("\"dec\":\"hi\""), "unexpected: {}", out);
                    assert!(out.contains("\"b64\":\"nexus\""), "unexpected: {}", out);
            assert!(out.contains("\"hasUuid\":true"), "unexpected: {}", out);
            assert!(out.contains("\"header\":\"hello\""), "unexpected: {}", out);
        });
    }
}
