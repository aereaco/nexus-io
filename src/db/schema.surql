-- 1. CAPABILITIES
-- Defined granualar permissions
DEFINE TABLE capability SCHEMAFULL;
DEFINE FIELD resource ON capability TYPE string; -- e.g. "host", "net"
DEFINE FIELD action   ON capability TYPE string; -- e.g. "read", "write"

-- 2. ROLES
-- Group capabilities together
DEFINE TABLE role SCHEMAFULL;
DEFINE FIELD name ON role TYPE string;
DEFINE FIELD caps ON role TYPE array<record<capability>>;

-- 3. USERS
-- The identity
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD username ON user TYPE string ASSERT $value != NONE;
DEFINE FIELD password   ON user TYPE string; -- Hash in production!
DEFINE FIELD groups     ON user TYPE array<string>; -- Real host groups
DEFINE FIELD active_role ON user TYPE record<role> DEFAULT role:guest;


-- 4. SYSTEM STORAGE
-- Physical disk projection
DEFINE TABLE `sys::storage` SCHEMAFULL;
DEFINE FIELD name           ON `sys::storage` TYPE string;
DEFINE FIELD mount_point    ON `sys::storage` TYPE string;
DEFINE FIELD total_space    ON `sys::storage` TYPE int;
DEFINE FIELD available_space ON `sys::storage` TYPE int;
DEFINE FIELD removable      ON `sys::storage` TYPE bool;

-- 5. SYSTEM FILES
-- Virtual File System projection
DEFINE TABLE `sys::file` SCHEMAFULL;
DEFINE FIELD path       ON `sys::file` TYPE string;
DEFINE FIELD is_dir     ON `sys::file` TYPE bool;
DEFINE FIELD size       ON `sys::file` TYPE int;
DEFINE FIELD modified   ON `sys::file` TYPE datetime;

-- 6. SOVEREIGN BUCKETS
-- Managed disk namespaces
DEFINE TABLE `sys::bucket` SCHEMAFULL;
DEFINE FIELD name       ON `sys::bucket` TYPE string;
DEFINE FIELD host_path  ON `sys::bucket` TYPE string;
DEFINE FIELD quota      ON `sys::bucket` TYPE int; -- bytes


-- SYSTEM ROLES -------------------------------------
-- These define the capability model for the runtime.

CREATE role:admin SET 
    name = 'Administrator',
    caps = []; -- Capabilities will be added dynamically by the Kernel

-- Storage cluster metadata (Garage DHT)
DEFINE TABLE storage_cluster SCHEMAFULL;
DEFINE FIELD node_id ON storage_cluster TYPE string;
DEFINE FIELD cluster_layout ON storage_cluster TYPE object;
DEFINE FIELD initialized_at ON storage_cluster TYPE datetime;
DEFINE FIELD rpc_endpoint ON storage_cluster TYPE string;
DEFINE FIELD status ON storage_cluster TYPE string DEFAULT 'initializing';

-- WireGuard peer tracking
DEFINE TABLE peer_registry SCHEMAFULL;
DEFINE FIELD pubkey ON peer_registry TYPE string;
DEFINE FIELD privkey ON peer_registry TYPE string;  -- X25519 private key (base64)
DEFINE FIELD endpoint ON peer_registry TYPE option<string>;
DEFINE FIELD last_handshake ON peer_registry TYPE option<datetime>;
DEFINE FIELD status ON peer_registry TYPE string DEFAULT 'pending';
DEFINE FIELD added_at ON peer_registry TYPE datetime;
DEFINE FIELD is_local ON peer_registry TYPE bool DEFAULT false;  -- True for this node's keypair
DEFINE FIELD resources ON peer_registry TYPE option<object>; -- Compute capacity telemetry

-- Object storage buckets
DEFINE TABLE bucket SCHEMAFULL;
DEFINE FIELD name ON bucket TYPE string;
DEFINE FIELD created_at ON bucket TYPE datetime;
DEFINE FIELD object_count ON bucket TYPE int DEFAULT 0;

-- Object storage data
DEFINE TABLE objdata SCHEMAFULL;
DEFINE FIELD bucket ON objdata TYPE string;
DEFINE FIELD key ON objdata TYPE string;
DEFINE FIELD value ON objdata TYPE array;  -- Byte array
DEFINE FIELD created_at ON objdata TYPE datetime;
DEFINE FIELD size ON objdata TYPE int;

CREATE role:guest SET
    name = 'Guest',
    caps = [];

-- IDENTITY MAPPING BLOCK ----------------------------
-- System users from 'sys users' will be projected here.
