// Storage commands for Garage and WireGuard management
use nu_protocol::engine::{Command, EngineState, Stack, Call};
use nu_protocol::{Category, PipelineData, ShellError, Signature, Value};
use nu_engine::CallExt;
use std::sync::Arc;
use crate::db::Database;
use crate::storage::{BlobBridge, WireGuardManager};

// ===== INITIALIZATION COMMANDS =====

/// storage init - Initialize Garage cluster and generate WireGuard keys
#[derive(Clone)]
pub struct StorageInitCommand {
    pub db: Arc<Database>,
    // Init command still creates the manager, as it initializes the system
}

impl Command for StorageInitCommand {
    fn name(&self) -> &str { "storage init" }
    fn description(&self) -> &str { "Initialize Garage cluster and generate WireGuard keys" }
    fn signature(&self) -> Signature {


        Signature::build("storage init")
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let db = self.db.clone();
        
        // Use tokio::task::block_in_place to avoid nested runtime panic
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let wg = WireGuardManager::new(db).await
                    .map_err(|e| crate::shell_err(
                        "Failed to initialize WireGuardManager",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                // Check if keypair already exists
                let existing = wg.get_local_keypair().await
                    .map_err(|e| crate::shell_err(
                        "Failed to check existing keypair",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                if let Some((_, pubkey)) = existing {
                    return Ok(format!("✅ Storage already initialized\nPublic Key: {}", pubkey));
                }
                
                // Generate new keypair
                let (_privkey, pubkey) = wg.generate_keypair().await
                    .map_err(|e| crate::shell_err(
                        "Failed to generate WireGuard keypair",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                Ok(format!("✅ Storage initialized successfully\nPublic Key: {}\n\nShare this public key with peers to join the mesh.", pubkey))
            })
        });
        
        match result {
            Ok(msg) => Ok(PipelineData::Value(Value::string(msg, span), None)),
            Err(e) => Err(e),
        }
    }
}

/// storage status - Show cluster health
#[derive(Clone)]
pub struct StorageStatusCommand;

impl Command for StorageStatusCommand {
    fn name(&self) -> &str { "storage status" }
    fn description(&self) -> &str { "Show Garage cluster status and peer count" }
    fn signature(&self) -> Signature {
        Signature::build("storage status")
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        
        // TODO: Query Garage cluster health
        // TODO: Query WireGuard peer count
        // TODO: Return structured data
        
        Ok(PipelineData::Value(
            Value::string("Storage status not yet implemented", span),
            None,
        ))
    }
}

// ===== BUCKET COMMANDS =====

/// storage bucket create - Create a Garage bucket
#[derive(Clone)]
pub struct StorageBucketCreateCommand {
    pub bridge: Arc<BlobBridge>,
}

impl Command for StorageBucketCreateCommand {
    fn name(&self) -> &str { "storage bucket create" }
    fn description(&self) -> &str { "Create a new Garage bucket" }
    fn signature(&self) -> Signature {
        Signature::build("storage bucket create")
            .required("name", nu_protocol::SyntaxShape::String, "Bucket name")
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
        let name: String = call.req(engine_state, stack, 0)?;
        let bridge = self.bridge.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                bridge.create_bucket(&name).await
                    .map_err(|e| crate::shell_err(
                        "Failed to create bucket",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                Ok(format!("✅ Bucket '{}' created successfully", name))
            })
        });
        
        match result {
            Ok(msg) => Ok(PipelineData::Value(Value::string(msg, span), None)),
            Err(e) => Err(e),
        }
    }
}

/// storage bucket list - List all buckets
#[derive(Clone)]
pub struct StorageBucketListCommand {
    pub bridge: Arc<BlobBridge>,
}

impl Command for StorageBucketListCommand {
    fn name(&self) -> &str { "storage bucket list" }
    fn description(&self) -> &str { "List all Garage buckets" }
    fn signature(&self) -> Signature {
        Signature::build("storage bucket list")
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let bridge = self.bridge.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let buckets = bridge.list_buckets().await
                    .map_err(|e| crate::shell_err(
                        "Failed to list buckets",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                // Convert to Nushell table
                let records: Vec<Value> = buckets.into_iter().map(|name| {
                    Value::record(
                        vec![
                            ("name".to_string(), Value::string(name, span)),
                        ].into_iter().collect(),
                        span
                    )
                }).collect();
                
                Ok(Value::list(records, span))
            })
        });
        
        match result {
            Ok(table) => Ok(PipelineData::Value(table, None)),
            Err(e) => Err(e),
        }
    }
}

// ===== OBJECT COMMANDS =====

/// storage put - Store an object in a bucket
#[derive(Clone)]
pub struct StoragePutCommand {
    pub bridge: Arc<BlobBridge>,
}

impl Command for StoragePutCommand {
    fn name(&self) -> &str { "storage put" }
    fn description(&self) -> &str { "Store an object in a bucket" }
    fn signature(&self) -> Signature {
        Signature::build("storage put")
            .required("bucket", nu_protocol::SyntaxShape::String, "Bucket name")
            .required("key", nu_protocol::SyntaxShape::String, "Object key")
            .required("value", nu_protocol::SyntaxShape::String, "Object value")
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
        let bucket: String = call.req(engine_state, stack, 0)?;
        let key: String = call.req(engine_state, stack, 1)?;
        let value: String = call.req(engine_state, stack, 2)?;
        let bridge = self.bridge.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                bridge.put_object(&bucket, &key, bytes::Bytes::from(value.into_bytes())).await
                    .map_err(|e| crate::shell_err(
                        "Failed to store object",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                Ok(format!("✅ Object stored: {}/{}", bucket, key))
            })
        });
        
        match result {
            Ok(msg) => Ok(PipelineData::Value(Value::string(msg, span), None)),
            Err(e) => Err(e),
        }
    }
}

/// storage get - Retrieve an object from a bucket
#[derive(Clone)]
pub struct StorageGetCommand {
    pub bridge: Arc<BlobBridge>,
}

impl Command for StorageGetCommand {
    fn name(&self) -> &str { "storage get" }
    fn description(&self) -> &str { "Retrieve an object from a bucket" }
    fn signature(&self) -> Signature {
        Signature::build("storage get")
            .required("bucket", nu_protocol::SyntaxShape::String, "Bucket name")
            .required("key", nu_protocol::SyntaxShape::String, "Object key")
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
        let bucket: String = call.req(engine_state, stack, 0)?;
        let key: String = call.req(engine_state, stack, 1)?;
        let bridge = self.bridge.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let value = bridge.get_object(&bucket, &key).await
                    .map_err(|e| crate::shell_err(
                        "Failed to retrieve object",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                match value {
                    Some(bytes) => {
                        let content = String::from_utf8_lossy(&bytes).to_string();
                        Ok(content)
                    },
                    None => Err(crate::shell_err(
                        "Object not found",
                        format!("No object found at {}/{}", bucket, key),
                        Some(span),
                        Some("Check that the bucket and key are correct".into()),
                    ))
                }
            })
        });
        
        match result {
            Ok(content) => Ok(PipelineData::Value(Value::string(content, span), None)),
            Err(e) => Err(e),
        }
    }
}

// ===== PEER COMMANDS =====

/// storage peer add - Add a WireGuard peer
#[derive(Clone)]
pub struct StoragePeerAddCommand {
    pub db: Arc<Database>,
}

impl Command for StoragePeerAddCommand {
    fn name(&self) -> &str { "storage peer add" }
    fn description(&self) -> &str { "Add a WireGuard peer and Garage node" }
    fn signature(&self) -> Signature {
        Signature::build("storage peer add")
            .required("pubkey", nu_protocol::SyntaxShape::String, "Peer public key")
            .required("endpoint", nu_protocol::SyntaxShape::String, "Peer endpoint (IP:port)")
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
        let pubkey: String = call.req(engine_state, stack, 0)?;
        let endpoint: String = call.req(engine_state, stack, 1)?;
        let db = self.db.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let wg = WireGuardManager::new(db).await
                    .map_err(|e| crate::shell_err(
                        "Failed to initialize WireGuardManager",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                wg.add_peer(&pubkey, &endpoint).await
                    .map_err(|e| crate::shell_err(
                        "Failed to add peer",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                Ok(format!("✅ Peer added successfully\nPublic Key: {}\nEndpoint: {}", pubkey, endpoint))
            })
        });
        
        match result {
            Ok(msg) => Ok(PipelineData::Value(Value::string(msg, span), None)),
            Err(e) => Err(e),
        }
    }
}

/// storage peer list - List all peers
#[derive(Clone)]
pub struct StoragePeerListCommand {
    pub db: Arc<Database>,
}

impl Command for StoragePeerListCommand {
    fn name(&self) -> &str { "storage peer list" }
    fn description(&self) -> &str { "List all WireGuard peers" }
    fn signature(&self) -> Signature {
        Signature::build("storage peer list")
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let db = self.db.clone();
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let wg = WireGuardManager::new(db).await
                    .map_err(|e| crate::shell_err(
                        "Failed to initialize WireGuardManager",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                let peers = wg.list_peers().await
                    .map_err(|e| crate::shell_err(
                        "Failed to list peers",
                        e.to_string(),
                        Some(span),
                        None,
                    ))?;
                
                // Convert to Nushell table
                let records: Vec<Value> = peers.into_iter().map(|(pubkey, endpoint, status)| {
                    Value::record(
                        vec![
                            ("pubkey".to_string(), Value::string(pubkey, span)),
                            ("endpoint".to_string(), Value::string(endpoint.unwrap_or_else(|| "N/A".to_string()), span)),
                            ("status".to_string(), Value::string(status, span)),
                        ].into_iter().collect(),
                        span
                    )
                }).collect();
                
                Ok(Value::list(records, span))
            })
        });
        
        match result {
            Ok(table) => Ok(PipelineData::Value(table, None)),
            Err(e) => Err(e),
        }
    }
}
