//! P0.1 / P0.2 Hardening & 4-Node Heterogeneous Mesh Regression Suite
//!
//! Verifies:
//! 1. Canonical length-prefixed signing covers ALL fields (tampering `gpu.apis` or `wasm_slots` fails).
//! 2. Membership binding rejects untrusted/wrong-org self-signed advertisements.
//! 3. Deterministic CRDT convergence under equal `lamport_ts` (commutative & idempotent) + tombstones.
//! 4. `ReservationLedger` prevents double-booking advertised capacity + verified CAS locality check.
//! 5. Durable `VoterNode` vote-locks reject conflicting proposals on the same `(group, epoch, slot)`.
//! 6. Durable `CoordinationGroup::open_durable` recovers committed leases & monotonic fencing epochs.
//! 7. `FencedResourceGuard` rejects stale fencing tokens directly at the resource boundary.

use nexus_io::db::Database;
use nexus_io::iam::idp::{NexusIdp, OrgPolicyPatch};
use nexus_io::mesh::consensus::{
    hash_proposal, sign_vote_raw, ConsensusMode, CoordinationGroup, FencedResourceGuard,
    GroupMember, VoteRequest, VoterNode,
};
use nexus_io::mesh::resources::{
    schedule_and_lease_workload, GpuCapability, NodeAdvertisement, ReservationLedger,
    ResourceMeshCrdt, WorkloadSpec,
};
use nexus_io::storage::blob_bridge::BlobBridge;
use nexus_io::storage::cas_store::CasStore;
use std::sync::Arc;

#[tokio::test]
async fn p0_resource_trust_crdt_convergence_durable_consensus_and_boundary_fencing() {
    let db_coord = Arc::new(Database::open_mem());
    let idp = NexusIdp::new(db_coord.clone());
    let org = idp
        .create_org("root", "nexus-mesh", "Nexus Mesh Org", None, None, OrgPolicyPatch::default())
        .await
        .unwrap();

    // 4 independent cryptographic node identities + 4 independent VoterNode databases
    let (id_a, sk_a) = idp.create_identity("node-a-control", None).await.unwrap();
    let (id_b, sk_b) = idp.create_identity("node-b-cpu", None).await.unwrap();
    let (id_c, sk_c) = idp.create_identity("node-c-gpu", None).await.unwrap();
    let (id_d, sk_d) = idp.create_identity("node-d-storage", None).await.unwrap();

    let members = vec![
        GroupMember { node_id: "node-a".into(), identity_id: id_a.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_a.active_pubkey.clone() },
        GroupMember { node_id: "node-b".into(), identity_id: id_b.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_b.active_pubkey.clone() },
        GroupMember { node_id: "node-c".into(), identity_id: id_c.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_c.active_pubkey.clone() },
        GroupMember { node_id: "node-d".into(), identity_id: id_d.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_d.active_pubkey.clone() },
    ];

    let voter_a = VoterNode::new("node-a", sk_a.clone(), Arc::new(Database::open_mem()));
    let voter_b = VoterNode::new("node-b", sk_b.clone(), Arc::new(Database::open_mem()));
    let voter_c = VoterNode::new("node-c", sk_c.clone(), Arc::new(Database::open_mem()));
    let voter_d = VoterNode::new("node-d", sk_d.clone(), Arc::new(Database::open_mem()));
    let all_voters = vec![voter_a.clone(), voter_b.clone(), voter_c.clone(), voter_d.clone()];

    let mut group = CoordinationGroup::open_durable(
        db_coord.clone(),
        "pool:us-east",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();

    // Real CAS manifest on Node D
    let tmp_dir = std::env::temp_dir().join(format!("nexus_mesh_p0_{}", uuid::Uuid::new_v4().simple()));
    let blobs = Arc::new(BlobBridge::new_in(db_coord.clone(), tmp_dir.clone()).await.unwrap());
    let cas = CasStore::new(blobs);
    let dataset = serde_json::json!({ "shard": "alpha-v1", "weights_digest": "blake3:verified" });
    let cid = cas.commit_manifest_cas("mesh-datasets", "alpha-v1.json", &dataset, None).await.unwrap();

    let t0 = 1_700_000_000_000u64;
    let exp = t0 + 300_000;

    // 1. P0.1A: Tampering `gpu.apis` or `wasm_slots` MUST invalidate the signature!
    let mut adv_c = NodeAdvertisement {
        node_id: "node-c".into(),
        identity_id: id_c.identity_id.clone(),
        org_id: org.org_id.clone(),
        group_id: "pool:us-east".into(),
        region: "us-east".into(),
        ed25519_pubkey: id_c.active_pubkey.clone(),
        cpu_arch: "x86_64".into(),
        cpu_cores: 16,
        available_cpu_cores: 12,
        ram_mb: 65_536,
        available_ram_mb: 48_000,
        shared_arena_mb: 8192,
        cas_storage_gb: 500,
        verified_local_cas_cids: vec![cid.clone()],
        advertised_cas_cids: vec![],
        gpus: vec![GpuCapability {
            vendor: "NVIDIA".into(),
            model: "RTX 4090".into(),
            vram_mb: 24_576,
            free_vram_mb: 22_000,
            apis: vec!["cuda".into(), "vulkan".into()],
        }],
        wasm_slots: 4,
        healthy: true,
        tombstone: false,
        expires_at_ms: exp,
        lamport_ts: 1,
        signature: String::new(),
    };
    adv_c.sign(&sk_c).unwrap();

    let mut tampered_gpu = adv_c.clone();
    tampered_gpu.gpus[0].apis.push("rocm".into());
    let mut crdt_a = ResourceMeshCrdt::new();
    assert!(crdt_a.merge_advertisement(tampered_gpu, &group).is_err());

    let mut tampered_wasm = adv_c.clone();
    tampered_wasm.wasm_slots = 999;
    assert!(crdt_a.merge_advertisement(tampered_wasm, &group).is_err());

    // 2. P0.1B: Untrusted rogue node claiming membership in `org` MUST be rejected!
    let (rogue_id, rogue_sk) = idp.create_identity("rogue", None).await.unwrap();
    let mut rogue_adv = adv_c.clone();
    rogue_adv.node_id = "rogue-node".into();
    rogue_adv.identity_id = rogue_id.identity_id;
    rogue_adv.ed25519_pubkey = rogue_id.active_pubkey;
    rogue_adv.sign(&rogue_sk).unwrap();
    assert!(crdt_a.merge_advertisement(rogue_adv, &group).is_err());

    // 3. P0.1C: Equal-lamport_ts deterministic CRDT convergence (merge order invariant!)
    let mut adv_b1 = NodeAdvertisement {
        node_id: "node-b".into(),
        identity_id: id_b.identity_id.clone(),
        org_id: org.org_id.clone(),
        group_id: "pool:us-east".into(),
        region: "us-east".into(),
        ed25519_pubkey: id_b.active_pubkey.clone(),
        cpu_arch: "x86_64".into(),
        cpu_cores: 32,
        available_cpu_cores: 20,
        ram_mb: 65_536,
        available_ram_mb: 32_000,
        shared_arena_mb: 4096,
        cas_storage_gb: 200,
        verified_local_cas_cids: vec![],
        advertised_cas_cids: vec![cid.clone()],
        gpus: vec![],
        wasm_slots: 8,
        healthy: true,
        tombstone: false,
        expires_at_ms: exp,
        lamport_ts: 5,
        signature: String::new(),
    };
    adv_b1.sign(&sk_b).unwrap();
    let mut adv_b2 = adv_b1.clone();
    adv_b2.available_cpu_cores = 24;
    adv_b2.sign(&sk_b).unwrap();

    let mut peer1 = ResourceMeshCrdt::new();
    peer1.merge_advertisement(adv_b1.clone(), &group).unwrap();
    peer1.merge_advertisement(adv_b2.clone(), &group).unwrap();

    let mut peer2 = ResourceMeshCrdt::new();
    peer2.merge_advertisement(adv_b2.clone(), &group).unwrap();
    peer2.merge_advertisement(adv_b1.clone(), &group).unwrap();

    assert_eq!(
        peer1.nodes["node-b"].available_cpu_cores,
        peer2.nodes["node-b"].available_cpu_cores,
        "CRDT MUST converge identically regardless of equal-timestamp arrival order!"
    );

    // Populate live CRDT with valid advertisements for node-b and node-c
    crdt_a.merge_advertisement(adv_b2.clone(), &group).unwrap();
    crdt_a.merge_advertisement(adv_c.clone(), &group).unwrap();

    // 4. P0.1D: Verified CAS locality + ReservationLedger capacity accounting
    let mut reservations = ReservationLedger::new();
    let gpu_spec = WorkloadSpec {
        workload_id: "wl-gpu-1".into(),
        required_org_id: org.org_id.clone(),
        min_cpu_cores: 4,
        min_ram_mb: 16_000,
        min_gpu_vram_mb: 16_000,
        required_gpu_api: Some("cuda".into()),
        required_wasm_slots: 3,
        preferred_region: Some("us-east".into()),
        input_cas_cid: Some(cid.clone()),
        require_verified_cas_locality: true,
    };
    let dec1 = schedule_and_lease_workload(
        &crdt_a,
        &mut reservations,
        &mut group,
        &gpu_spec,
        "gpu:us-east:slot-0",
        30_000,
        t0,
        &all_voters,
    )
    .await
    .unwrap();
    assert_eq!(dec1.selected_node_id, "node-c");
    assert!(dec1.verified_cas_local);

    // Second workload needing 3 more wasm_slots on node-c (only 4 total, 3 reserved -> 1 free!) MUST FAIL!
    let gpu_spec_2 = WorkloadSpec {
        workload_id: "wl-gpu-2".into(),
        ..gpu_spec.clone()
    };
    assert!(
        schedule_and_lease_workload(
            &crdt_a,
            &mut reservations,
            &mut group,
            &gpu_spec_2,
            "gpu:us-east:slot-1",
            30_000,
            t0,
            &all_voters,
        )
        .await
        .is_err(),
        "ReservationLedger MUST prevent over-booking advertised wasm_slots/VRAM!"
    );

    // 5. P0.2: Durable VoterNode refuses conflicting vote for same (group, epoch, slot)
    let conflict_req = VoteRequest {
        group_id: "pool:us-east".into(),
        epoch: 1,
        slot: 1, // Already voted on slot 1 for wl-gpu-1!
        proposal_hash: hash_proposal("gpu:us-east:slot-0", "node-b", "wl-hijack", 1),
    };
    assert!(voter_a.cast_vote(&conflict_req).await.is_err());

    // 6. P0.2: Durable CoordinationGroup restart recovery preserves fencing_epoch & next_slot!
    let recovered_group = CoordinationGroup::open_durable(
        db_coord.clone(),
        "pool:us-east",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    assert_eq!(recovered_group.max_fencing_epoch["gpu:us-east:slot-0"], 1);
    assert_eq!(recovered_group.next_slot, 2);

    // 7. P0.2: Resource-boundary FencedResourceGuard rejects stale epoch directly at resource!
    let guard = FencedResourceGuard::new(Arc::new(Database::open_mem()));
    guard.accept_fenced_operation("gpu:us-east:slot-0", "node-c", 2).await.unwrap();
    assert!(guard.accept_fenced_operation("gpu:us-east:slot-0", "node-b", 1).await.is_err());

    // 8. Opt-in BFT equivocation detection still works cleanly
    let mut bft_group = CoordinationGroup::new("open:global", ConsensusMode::BftSigned, members);
    let h1 = hash_proposal("open:gpu:1", "node-c", "wl-1", 1);
    let h2 = hash_proposal("open:gpu:1", "node-b", "wl-evil", 1);
    let v1 = sign_vote_raw("open:global", 1, 1, &h1, "node-b", &sk_b).unwrap();
    let v2 = sign_vote_raw("open:global", 1, 1, &h2, "node-b", &sk_b).unwrap();
    assert!(bft_group.record_and_verify_vote(&v1).unwrap().is_none());
    assert!(bft_group.record_and_verify_vote(&v2).unwrap().is_some());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
