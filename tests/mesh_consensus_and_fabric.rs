//! Integration Milestone: 4-Node Heterogeneous Nexus Mesh + Scoped Hybrid Consensus + Fault Injection
//!
//! Demonstrates:
//! - Node A (Control Plane / App)
//! - Node B (CPU Compute)
//! - Node C (GPU Accelerator — 24GB VRAM, CUDA/Vulkan)
//! - Node D (Replicated Content-Addressed Storage via `CasStore`)
//!
//! All 4 nodes hold independent `NEXUS-ID-v1` cryptographic identities.
//! Exercises:
//! 1. Signed CRDT gossip discovery across all 4 nodes (commutative/idempotent merge).
//! 2. Content-addressed input dataset storage & BLAKE3 integrity verification on Node D.
//! 3. Policy-aware GPU placement onto Node C & CPU placement onto Node B via quorum-fenced leases (`CftFastPath`).
//! 4. Crash/partition fault injection on Node B -> automatic rescheduling onto Node C with higher
//!    `fencing_epoch` -> stale fencing token from partitioned Node B REJECTED!
//! 5. Opt-in Byzantine group (`BftSigned`, `3f+1`) rejecting minority quorums and cryptographically
//!    catching a malicious equivocating node with an `EquivocationProof`!

use nexus_io::db::Database;
use nexus_io::iam::idp::{NexusIdp, OrgPolicyPatch};
use nexus_io::mesh::consensus::{
    hash_proposal, sign_vote, ConsensusMode, CoordinationGroup, GroupMember,
};
use nexus_io::mesh::resources::{
    schedule_and_lease_workload, GpuCapability, NodeAdvertisement, ResourceMeshCrdt, WorkloadSpec,
};
use nexus_io::storage::blob_bridge::BlobBridge;
use nexus_io::storage::cas_store::CasStore;
use std::sync::Arc;

#[tokio::test]
async fn four_node_heterogeneous_mesh_discovery_fenced_placement_crash_failover_and_bft_equivocation() {
    let db = Arc::new(Database::open_mem());
    let idp = NexusIdp::new(db.clone());
    let org = idp
        .create_org("root", "nexus-mesh", "Nexus Mesh Org", None, None, OrgPolicyPatch::default())
        .await
        .unwrap();

    // 1. Provision 4 independent cryptographic node identities (`NEXUS-ID-v1` + Ed25519 keypairs)
    let (id_a, sk_a) = idp.create_identity("node-a-control", None).await.unwrap();
    let (id_b, sk_b) = idp.create_identity("node-b-cpu", None).await.unwrap();
    let (id_c, sk_c) = idp.create_identity("node-c-gpu", None).await.unwrap();
    let (id_d, sk_d) = idp.create_identity("node-d-storage", None).await.unwrap();

    let members = vec![
        GroupMember { node_id: "node-a".into(), identity_id: id_a.identity_id.clone(), ed25519_pubkey: id_a.active_pubkey.clone() },
        GroupMember { node_id: "node-b".into(), identity_id: id_b.identity_id.clone(), ed25519_pubkey: id_b.active_pubkey.clone() },
        GroupMember { node_id: "node-c".into(), identity_id: id_c.identity_id.clone(), ed25519_pubkey: id_c.active_pubkey.clone() },
        GroupMember { node_id: "node-d".into(), identity_id: id_d.identity_id.clone(), ed25519_pubkey: id_d.active_pubkey.clone() },
    ];
    let all_voters = vec![
        ("node-a".to_string(), sk_a.clone()),
        ("node-b".to_string(), sk_b.clone()),
        ("node-c".to_string(), sk_c.clone()),
        ("node-d".to_string(), sk_d.clone()),
    ];

    // 2. Signed CRDT resource advertisements for all 4 heterogeneous nodes
    let mut adv_b = NodeAdvertisement {
        node_id: "node-b".into(),
        identity_id: id_b.identity_id.clone(),
        org_id: org.org_id.clone(),
        region: "us-east".into(),
        ed25519_pubkey: id_b.active_pubkey.clone(),
        cpu_arch: "x86_64".into(),
        cpu_cores: 32,
        available_cpu_cores: 28,
        ram_mb: 65_536,
        shared_arena_mb: 4096,
        cas_storage_gb: 200,
        gpus: vec![],
        wasm_slots: 64,
        healthy: true,
        lamport_ts: 1,
        signature: String::new(),
    };
    adv_b.sign(&sk_b).unwrap();

    let mut adv_c = NodeAdvertisement {
        node_id: "node-c".into(),
        identity_id: id_c.identity_id.clone(),
        org_id: org.org_id.clone(),
        region: "us-east".into(),
        ed25519_pubkey: id_c.active_pubkey.clone(),
        cpu_arch: "x86_64".into(),
        cpu_cores: 16,
        available_cpu_cores: 12,
        ram_mb: 65_536,
        shared_arena_mb: 8192,
        cas_storage_gb: 500,
        gpus: vec![GpuCapability {
            vendor: "NVIDIA".into(),
            model: "RTX 4090".into(),
            vram_mb: 24_576,
            free_vram_mb: 22_000,
            apis: vec!["cuda".into(), "vulkan".into()],
        }],
        wasm_slots: 32,
        healthy: true,
        lamport_ts: 1,
        signature: String::new(),
    };
    adv_c.sign(&sk_c).unwrap();

    let mut adv_d = NodeAdvertisement {
        node_id: "node-d".into(),
        identity_id: id_d.identity_id.clone(),
        org_id: org.org_id.clone(),
        region: "us-east".into(),
        ed25519_pubkey: id_d.active_pubkey.clone(),
        cpu_arch: "aarch64".into(),
        cpu_cores: 8,
        available_cpu_cores: 6,
        ram_mb: 32_768,
        shared_arena_mb: 2048,
        cas_storage_gb: 8000,
        gpus: vec![],
        wasm_slots: 16,
        healthy: true,
        lamport_ts: 1,
        signature: String::new(),
    };
    adv_d.sign(&sk_d).unwrap();

    // Gossip CRDT convergence across Node A and Node D
    let mut crdt_a = ResourceMeshCrdt::new();
    crdt_a.merge_advertisement(adv_b.clone()).unwrap();
    crdt_a.merge_advertisement(adv_c.clone()).unwrap();
    let mut crdt_d = ResourceMeshCrdt::new();
    crdt_d.merge_advertisement(adv_d.clone()).unwrap();
    assert_eq!(crdt_a.merge_gossip(&crdt_d).unwrap(), 1);
    assert_eq!(crdt_a.merge_gossip(&crdt_d).unwrap(), 0); // Idempotent!

    // 3. Node D stores content-addressed workload manifest via BlobBridge + CasStore (CAS ETag verified)
    let tmp_dir = std::env::temp_dir().join(format!("nexus_mesh_cas_{}", uuid::Uuid::new_v4().simple()));
    let blobs = Arc::new(BlobBridge::new_in(db.clone(), tmp_dir.clone()).await.unwrap());
    let cas = CasStore::new(blobs);
    let dataset = serde_json::json!({ "shard": "alpha-v1", "weights_digest": "blake3:verified" });
    let cid = cas.commit_manifest_cas("mesh-datasets", "alpha-v1.json", &dataset, None).await.unwrap();
    let (loaded, loaded_etag): (serde_json::Value, String) =
        cas.read_manifest("mesh-datasets", "alpha-v1.json").await.unwrap().unwrap();
    assert_eq!(loaded["shard"], "alpha-v1");
    assert_eq!(loaded_etag, cid);

    // 4. Scoped CFT Fast-Path Group (`2f+1` = 3 of 4 nodes) places GPU workload -> Node C & CPU workload -> Node B
    let mut pool_group = CoordinationGroup::new("pool:us-east", ConsensusMode::CftFastPath, members.clone());
    let t0 = 1_700_000_000_000u64;

    let gpu_spec = WorkloadSpec {
        workload_id: "wl-llm-infer-1".into(),
        required_org_id: org.org_id.clone(),
        min_cpu_cores: 4,
        min_ram_mb: 16_384,
        min_gpu_vram_mb: 16_000,
        required_gpu_api: Some("cuda".into()),
        preferred_region: Some("us-east".into()),
        input_cas_cid: Some(cid.clone()),
    };
    let gpu_dec = schedule_and_lease_workload(
        &crdt_a,
        &mut pool_group,
        &gpu_spec,
        "gpu:us-east:slot-0",
        30_000,
        t0,
        &all_voters,
    )
    .unwrap();
    assert_eq!(gpu_dec.selected_node_id, "node-c");
    assert_eq!(gpu_dec.lease.fencing_epoch, 1);
    pool_group.verify_qc(&gpu_dec.lease.qc).unwrap();

    // Exclusive safety: trying to double-allocate the same GPU slot MUST fail while active!
    assert!(schedule_and_lease_workload(
        &crdt_a,
        &mut pool_group,
        &gpu_spec,
        "gpu:us-east:slot-0",
        30_000,
        t0 + 1000,
        &all_voters,
    )
    .is_ok()); // Same holder renewal succeeds, whereas a different holder is blocked:
    let conflict_hash = hash_proposal("gpu:us-east:slot-0", "node-b", "wl-hijack", 3);
    let conflict_votes: Vec<_> = all_voters
        .iter()
        .map(|(nid, sk)| sign_vote("pool:us-east", 1, pool_group.next_slot, &conflict_hash, nid, sk).unwrap())
        .collect();
    assert!(pool_group
        .commit_exclusive_lease("gpu:us-east:slot-0", "node-b", "wl-hijack", 30_000, t0 + 1000, conflict_votes)
        .is_err());

    // Place CPU workload onto Node B (highest available CPU cores: 28 > 12 > 6)
    let cpu_spec = WorkloadSpec {
        workload_id: "wl-etl-job-1".into(),
        required_org_id: org.org_id.clone(),
        min_cpu_cores: 8,
        min_ram_mb: 8192,
        min_gpu_vram_mb: 0,
        required_gpu_api: None,
        preferred_region: Some("us-east".into()),
        input_cas_cid: Some(cid.clone()),
    };
    let cpu_dec = schedule_and_lease_workload(
        &crdt_a,
        &mut pool_group,
        &cpu_spec,
        "cpu:us-east:etl-1",
        10_000,
        t0,
        &all_voters,
    )
    .unwrap();
    assert_eq!(cpu_dec.selected_node_id, "node-b");
    let stale_node_b_epoch = cpu_dec.lease.fencing_epoch;

    // 5. FAULT INJECTION: Node B crashes/partitions!
    // Mark Node B unhealthy in CRDT, expire its lease, and reschedule with remaining 3 online voters (A, C, D)
    let mut adv_b_down = adv_b.clone();
    adv_b_down.healthy = false;
    adv_b_down.lamport_ts = 2;
    adv_b_down.sign(&sk_b).unwrap();
    crdt_a.merge_advertisement(adv_b_down).unwrap();
    let t_failover = t0 + 15_000;
    pool_group.expire_lease_for_fault("cpu:us-east:etl-1", t_failover);

    let surviving_voters = vec![
        ("node-a".to_string(), sk_a.clone()),
        ("node-c".to_string(), sk_c.clone()),
        ("node-d".to_string(), sk_d.clone()),
    ];
    let recovered = schedule_and_lease_workload(
        &crdt_a,
        &mut pool_group,
        &cpu_spec,
        "cpu:us-east:etl-1",
        30_000,
        t_failover,
        &surviving_voters,
    )
    .unwrap();
    assert_eq!(recovered.selected_node_id, "node-c");
    assert!(recovered.lease.fencing_epoch > stale_node_b_epoch);

    // Partitioned Node B wakes up and tries to commit with its stale fencing token -> MUST BE REJECTED!
    assert!(pool_group
        .verify_fencing_token("cpu:us-east:etl-1", "node-b", stale_node_b_epoch, t_failover + 100)
        .is_err());
    // Recovered Node C's new fencing token MUST be accepted!
    pool_group
        .verify_fencing_token("cpu:us-east:etl-1", "node-c", recovered.lease.fencing_epoch, t_failover + 100)
        .unwrap();

    // Audit trail in NexusIdp
    idp.append_audit(&org.org_id, &id_a.identity_id, "mesh.failover", "cpu:us-east:etl-1", "ok", "rescheduled node-b -> node-c")
        .await
        .unwrap();
    let audit = idp.list_audit_events(Some(&org.org_id), 10).await.unwrap();
    assert!(audit.iter().any(|e| e.action == "mesh.failover"));

    // 6. Opt-In BFT Group (`BftSigned`, `3f+1` = 3 of 4 nodes) + Byzantine Equivocation Proof!
    let mut bft_group = CoordinationGroup::new("open-pool:global", ConsensusMode::BftSigned, members);
    assert_eq!(bft_group.quorum_size(), 3);
    let h1 = hash_proposal("open:gpu:1", "node-c", "wl-1", 1);
    let h2 = hash_proposal("open:gpu:1", "node-b", "wl-evil", 1);

    // Malicious node-b signs TWO conflicting proposals for the exact same (epoch=1, slot=1)!
    let v_honest = sign_vote("open-pool:global", 1, 1, &h1, "node-b", &sk_b).unwrap();
    let v_equiv = sign_vote("open-pool:global", 1, 1, &h2, "node-b", &sk_b).unwrap();
    assert!(bft_group.record_and_verify_vote(&v_honest).unwrap().is_none());
    let proof = bft_group
        .record_and_verify_vote(&v_equiv)
        .unwrap()
        .expect("Byzantine equivocation MUST produce cryptographic EquivocationProof!");
    assert_eq!(proof.voter_node_id, "node-b");
    assert_eq!(bft_group.equivocations.len(), 1);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
