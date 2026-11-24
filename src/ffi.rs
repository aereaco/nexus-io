//! C-ABI FFI surface for embedding Nexus-IO natively in Android (JNI/`.aar`) and iOS (`XCFramework`/Swift)
//! host applications with zero Electron or third-party browser overhead.

use once_cell::sync::OnceCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::db::Database;

static EMBEDDED_DB: OnceCell<Database> = OnceCell::new();

/// Returns the static Nexus-IO + `nexus-db` version string (caller must free with `nexus_io_free_string`).
#[no_mangle]
pub extern "C" fn nexus_io_version() -> *mut c_char {
    let v = format!(
        "nexus-io 0.1.0 ({} / {})",
        crate::runtime::CapabilityRegistry::active_profile(),
        crate::ux::native_gui::NativeWebViewEngine::current().as_str()
    );
    CString::new(v).unwrap().into_raw()
}

/// Initialize the embedded in-memory `nexus-db` runtime for mobile/native host apps.
/// Returns `0` on success.
#[no_mangle]
pub extern "C" fn nexus_io_init_mem() -> i32 {
    let _ = EMBEDDED_DB.get_or_init(Database::open_mem);
    0
}

/// Execute a SurrealQL query against `(ns, db)` and return a JSON string
/// (caller must free with `nexus_io_free_string`).
///
/// # Safety
/// `ns`, `db`, and `surql` must be valid null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn nexus_io_query_json(
    ns: *const c_char,
    db: *const c_char,
    surql: *const c_char,
) -> *mut c_char {
    if ns.is_null() || db.is_null() || surql.is_null() {
        return CString::new(r#"{"status":"ERR","result":"null pointer argument"}"#)
            .unwrap()
            .into_raw();
    }
    let ns_str = CStr::from_ptr(ns).to_string_lossy();
    let db_str = CStr::from_ptr(db).to_string_lossy();
    let sql_str = CStr::from_ptr(surql).to_string_lossy();
    let database = EMBEDDED_DB.get_or_init(Database::open_mem);

    let payload = match database.inner.query_scoped_multi(&ns_str, &db_str, &sql_str, vec![]) {
        Ok(outcomes) => {
            let arr: Vec<serde_json::Value> = outcomes
                .into_iter()
                .map(|o| {
                    serde_json::json!({
                        "time": format!("{}µs", o.time_us),
                        "status": o.status,
                        "result": o.result.iter().map(|v| v.to_json()).collect::<Vec<_>>()
                    })
                })
                .collect();
            serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
        }
        Err(e) => serde_json::json!([{ "status": "ERR", "result": e.to_string() }]).to_string(),
    };
    CString::new(payload).unwrap_or_default().into_raw()
}

/// Free a string previously returned by `nexus_io_version` or `nexus_io_query_json`.
///
/// # Safety
/// `ptr` must have been returned by a Nexus-IO FFI function and not freed previously.
#[no_mangle]
pub unsafe extern "C" fn nexus_io_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
