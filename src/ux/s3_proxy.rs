use salvo::prelude::*;
use salvo::http::{header, Method};
use bytes::Bytes;
use std::sync::Arc;

use crate::iam::capabilities::{Capability, CapabilitySet};
use crate::observability::global_metrics;
use crate::storage::BlobBridge;
use crate::ux::iam::depot_auth_context;

fn require_blob_capability(depot: &Depot, res: &mut Response, cap: Capability) -> bool {
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

/// S3 request handler struct
#[derive(Clone)]
pub struct S3ProxyHandler {
    pub garage: Arc<BlobBridge>,
}

#[async_trait]
impl Handler for S3ProxyHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        match req.method() {
            &Method::GET => {
                if !require_blob_capability(depot, res, Capability::BlobRead) {
                    return;
                }
                self.handle_get(req, res).await;
            }
            &Method::PUT => {
                if !require_blob_capability(depot, res, Capability::BlobWrite) {
                    return;
                }
                self.handle_put(req, res).await;
            }
            &Method::DELETE => {
                if !require_blob_capability(depot, res, Capability::BlobWrite) {
                    return;
                }
                self.handle_delete(req, res).await;
            }
            &Method::HEAD => {
                if !require_blob_capability(depot, res, Capability::BlobRead) {
                    return;
                }
                self.handle_head(req, res).await;
            }
            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
                res.render(Text::Plain("Method not allowed"));
            }
        }
    }
}

impl S3ProxyHandler {
    /// Handle GET request - retrieve object from Garage
    async fn handle_get(&self, req: &Request, res: &mut Response) {
        let (bucket, key) = match parse_s3_path(req) {
            Some(parts) => parts,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain("Invalid S3 path format. Use: /s3/bucket/key"));
                return;
            }
        };

        // Get object from Garage
        match self.garage.get_object(&bucket, &key).await {
            Ok(Some(data)) => {
                // Success - return object data
                res.status_code(StatusCode::OK);
                
                // Set S3-specific headers
                res.headers_mut().insert("x-amz-request-id", header::HeaderValue::from_static("nexus-io-gateway"));
                res.headers_mut().insert(header::CONTENT_LENGTH, header::HeaderValue::from(data.len()));
                if let Ok(Some(meta)) = self.garage.head_object(&bucket, &key).await {
                    res.add_header("ETag", format!("\"{}\"", meta.etag), true).ok();
                }
                
                if let Some(content_type) = guess_content_type(&key) {
                    if let Ok(value) = header::HeaderValue::from_str(content_type) {
                        res.headers_mut().insert(header::CONTENT_TYPE, value);
                    }
                }
                
                res.body(data.to_vec());
            }
            Ok(None) => {
                // Object not found
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Text::Plain(format!("Object not found: {}/{}", bucket, key)));
            }
            Err(e) => {
                // Error retrieving object
                eprintln!("❌ S3 GET error: {}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(format!("Error retrieving object: {}", e)));
            }
        }
    }

    /// Handle PUT request - store object in Garage
    async fn handle_put(&self, req: &mut Request, res: &mut Response) {
        let (bucket, key) = match parse_s3_path(req) {
            Some(parts) => parts,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain("Invalid S3 path format. Use: /s3/bucket/key"));
                return;
            }
        };

        // Read request body
        let body = match req.payload().await {
            Ok(data) => Bytes::copy_from_slice(data),
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain(format!("Failed to read payload: {}", e)));
                return;
            }
        };

        // Put object with optional S3 CAS preconditions (If-Match / If-None-Match)
        let if_match = req
            .headers()
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let if_none_match = req
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            == Some("*");

        match self
            .garage
            .put_object_cas(&bucket, &key, body, if_match.as_deref(), if_none_match)
            .await
        {
            Ok(etag) => {
                // Success
                res.status_code(StatusCode::OK);
                res.add_header("x-amz-request-id", "nexus-io-gateway", true).ok();
                res.add_header("ETag", format!("\"{}\"", etag), true).ok();
                res.render(Text::Plain("Object stored successfully"));
            }
            Err(e) if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>().is_some() => {
                res.status_code(StatusCode::PRECONDITION_FAILED);
                res.render(Text::Plain(e.to_string()));
            }
            Err(e) => {
                // Error storing object
                eprintln!("❌ S3 PUT error: {}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(format!("Error storing object: {}", e)));
            }
        }
    }

    /// Handle DELETE request - remove object from Garage
    async fn handle_delete(&self, req: &Request, res: &mut Response) {
        let (bucket, key) = match parse_s3_path(req) {
            Some(parts) => parts,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain("Invalid S3 path format. Use: /s3/bucket/key"));
                return;
            }
        };

        // Delete object from Garage
        match self.garage.delete_object(&bucket, &key).await {
            Ok(_) => {
                res.status_code(StatusCode::NO_CONTENT);
                res.add_header("x-amz-request-id", "nexus-io-gateway", true).ok();
            }
            Err(e) => {
                eprintln!("❌ S3 DELETE error: {}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(format!("Error deleting object: {}", e)));
            }
        }
    }

    /// Handle HEAD request - get object metadata without body
    async fn handle_head(&self, req: &Request, res: &mut Response) {
        let (bucket, key) = match parse_s3_path(req) {
            Some(parts) => parts,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            }
        };

        // Check if object exists without reading bytes
        match self.garage.head_object(&bucket, &key).await {
            Ok(Some(meta)) => {
                // Object exists - return metadata
                res.status_code(StatusCode::OK);
                res.add_header(header::CONTENT_LENGTH, meta.size.to_string(), true).ok();
                res.add_header("ETag", format!("\"{}\"", meta.etag), true).ok();
                
                if let Some(content_type) = guess_content_type(&key) {
                    res.add_header(header::CONTENT_TYPE, content_type, true).ok();
                }
                
                res.add_header("x-amz-request-id", "nexus-io-gateway", true).ok();
                // No body for HEAD
            }
            Ok(None) => {
                res.status_code(StatusCode::NOT_FOUND);
            }
            Err(e) => {
                eprintln!("❌ S3 HEAD error: {}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Parse S3 path from request
/// Expected format: /s3/bucket/key or /s3/bucket/path/to/key
fn parse_s3_path(req: &Request) -> Option<(String, String)> {
    let path = req.uri().path();
    
    // Remove /s3/ prefix
    let path = path.strip_prefix("/s3/")?;
    
    // Split into bucket and key
    let mut parts = path.splitn(2, '/');
    let bucket = parts.next()?.to_string();
    let key = parts.next().unwrap_or("").to_string();
    
    if bucket.is_empty()
        || bucket.contains("..")
        || bucket.contains('\\')
        || bucket.contains('\0')
        || key.contains('\0')
        || key.contains('\\')
        || key.split('/').any(|seg| seg == "..")
    {
        return None;
    }
    
    Some((bucket, key))
}

/// Guess content type from file extension
fn guess_content_type(key: &str) -> Option<&'static str> {
    let extension = key.rsplit('.').next()?;
    
    match extension.to_lowercase().as_str() {
        // Text
        "txt" => Some("text/plain"),
        "html" | "htm" => Some("text/html"),
        "css" => Some("text/css"),
        "js" => Some("application/javascript"),
        "json" => Some("application/json"),
        "xml" => Some("application/xml"),
        
        // Images
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "svg" => Some("image/svg+xml"),
        "webp" => Some("image/webp"),
        
        // Video
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        
        // Audio
        "mp3" => Some("audio/mpeg"),
        "ogg" => Some("audio/ogg"),
        "wav" => Some("audio/wav"),
        
        // Documents
        "pdf" => Some("application/pdf"),
        "zip" => Some("application/zip"),
        
        _ => Some("application/octet-stream"),
    }
}

/// Simple MD5 hash for ETag (simplified version)
fn md5_hash(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
