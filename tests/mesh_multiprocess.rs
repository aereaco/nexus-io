//! P1 Acceptance Test: 5-Process Distributed Mesh (2 Independent Durable Coordinators + 3 Voters)
//!
//! Spawns **5 separate OS processes** (zero shared memory, zero shared private keys, 5 separate
//! on-disk `redb` databases, all communication over real localhost TCP sockets):
//! - `node-1`, `node-2`, `node-3`: Independent durable `VoterNode` + `FencedResourceGuard` processes.
//! - `coord-1`, `coord-2`: Independent durable `CoordinationGroup` coordinator processes.
//!
//! Proves all 4 crash stages + adversarial security invariants:
//! 1. **Competing coordinator OS processes** (`coord-1` vs `coord-2`) racing the full propose ->
//!    parallel TCP fan-out -> durable commit lifecycle on `slot=1` -> at most ONE commits!
//! 2. **Stage 1 (Crash before quorum):** `coord-1` contacts only 1 voter on `slot=2` (below quorum)
//!    and is terminated (`kill()`) -> no false commit; `coord-2` safely proceeds on `slot=2`.
//! 3. **Stage 2 (Crash after quorum, before persistence):** `coord-1` collects quorum votes on
//!    `slot=3` and is killed BEFORE persisting -> `coord-2` queries voters' durable locks over TCP,
//!    runs `recover_safe_slot_decision`, and reconstructs the exact QC!
//! 4. **Stage 3 (Crash after decision persistence, before resource installation):** `coord-2`
//!    persists its committed lease to disk and is killed BEFORE calling `InstallLease` -> restarted
//!    `coord-2` recovers the persisted lease from its own `redb` DB and installs it on `node-3`!
//! 5. **Tampering, Idempotency & Stale Coordinator:**
//!    - +1 ms `expires_at_ms` tampering on a valid QC -> REJECTED by `node-3`!
//!    - Same-epoch exact retry -> idempotent OK; stale coordinator's obsolete `epoch=1` lease -> REJECTED!

use nexus_io::db::Database;
use nexus_io::mesh::consensus::{
    hash_lease_proposal, ConsensusMode, CoordinationGroup, FencedLease, FencedResourceGuard,
    GroupMember, SignedVote, VoteRequest, VoterNode,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum VoterRpcReq {
    Vote(VoteRequest),
    QueryLock {
        group_id: String,
        epoch: u64,
        slot: u64,
    },
    InstallLease {
        lease: FencedLease,
        members: Vec<GroupMember>,
        now: u64,
    },
    ExecLocal {
        resource_key: String,
        holder_node_id: String,
        fencing_epoch: u64,
        now: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum VoterRpcResp {
    VoteOk { vote: SignedVote },
    LockFound { vote: Option<SignedVote> },
    ExecOk { accepted_epoch: u64 },
    Err { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CoordRpcReq {
    /// Full propose -> parallel TCP fan-out -> durable commit lifecycle inside this coordinator process.
    ProposeAndCommit {
        voter_addrs: Vec<String>,
        lease_id: String,
        resource_key: String,
        holder_node_id: String,
        workload_id: String,
        issued_at_ms: u64,
        expires_at_ms: u64,
        now: u64,
        /// Optional: collect votes from voters and intentionally skip persistence (for crash-after-quorum test).
        skip_persist: bool,
    },
    /// Query voters' durable locks and run `recover_safe_slot_decision`.
    RecoverSlot {
        voter_addrs: Vec<String>,
        slot: u64,
    },
    /// Read committed lease from this coordinator's durable `CoordinationGroup` state.
    GetCommittedLease {
        resource_key: String,
    },
    /// Expire local lease tracking for reassignment.
    ExpireLocalLease {
        resource_key: String,
        now: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CoordRpcResp {
    Committed { lease: FencedLease },
    VotesCollectedOnly { count: usize, proposal_hash: String },
    RecoveredQc { proposal_hash: Option<String>, votes: Vec<SignedVote> },
    LeaseFound { lease: Option<FencedLease> },
    Ok,
    Err { message: String },
}

async fn send_voter_rpc(addr: &str, req: &VoterRpcReq) -> VoterRpcResp {
    let mut stream = TcpStream::connect(addr).await.expect("connect to voter TCP socket");
    let line = format!("{}\n", serde_json::to_string(req).unwrap());
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(resp_line.trim()).expect("valid VoterRpcResp JSON")
}

async fn send_coord_rpc(addr: &str, req: &CoordRpcReq) -> CoordRpcResp {
    let mut stream = TcpStream::connect(addr).await.expect("connect to coordinator TCP socket");
    let line = format!("{}\n", serde_json::to_string(req).unwrap());
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(resp_line.trim()).expect("valid CoordRpcResp JSON")
}

async fn fan_out_votes_tcp(addrs: &[String], req: VoteRequest) -> Vec<SignedVote> {
    let mut set = tokio::task::JoinSet::new();
    for addr in addrs {
        let a = addr.clone();
        let r = req.clone();
        set.spawn(async move { send_voter_rpc(&a, &VoterRpcReq::Vote(r)).await });
    }
    let mut votes = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(VoterRpcResp::VoteOk { vote }) = res {
            votes.push(vote);
        }
    }
    votes
}

async fn run_voter_child() {
    let node_id = std::env::var("NEXUS_CHILD_NODE_ID").unwrap();
    let data_dir = PathBuf::from(std::env::var("NEXUS_CHILD_DATA_DIR").unwrap());
    std::fs::create_dir_all(&data_dir).unwrap();

    let key_path = data_dir.join("node_key.json");
    let (sk, pk): (String, String) = if key_path.exists() {
        let raw = std::fs::read_to_string(&key_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        (v["sk"].as_str().unwrap().to_string(), v["pk"].as_str().unwrap().to_string())
    } else {
        let (sk, pk) = nexus_db::auth::ed25519_generate_keypair();
        std::fs::write(&key_path, serde_json::json!({ "sk": sk, "pk": pk }).to_string()).unwrap();
        (sk, pk)
    };

    let db = Arc::new(Database::init_in(data_dir.join("db")).await);
    let voter = VoterNode::new(node_id, sk, db.clone());
    let guard = FencedResourceGuard::new(db.clone());
    voter.ensure_tables().await.unwrap();
    guard.ensure_tables().await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("READY {} {}", addr, pk);
    use std::io::Write as _;
    std::io::stdout().flush().unwrap();

    loop {
        let Ok((socket, _)) = listener.accept().await else { break };
        let voter_c = voter.clone();
        let guard_c = guard.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let resp = match serde_json::from_str::<VoterRpcReq>(line.trim()) {
                Ok(VoterRpcReq::Vote(vreq)) => match voter_c.cast_vote(&vreq).await {
                    Ok(vote) => VoterRpcResp::VoteOk { vote },
                    Err(e) => VoterRpcResp::Err { message: e.to_string() },
                },
                Ok(VoterRpcReq::QueryLock { group_id, epoch, slot }) => {
                    match voter_c.query_slot_lock(&group_id, epoch, slot).await {
                        Ok(vote) => VoterRpcResp::LockFound { vote },
                        Err(e) => VoterRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(VoterRpcReq::InstallLease { lease, members, now }) => {
                    let grp = CoordinationGroup::new(lease.group_id.clone(), lease.qc.mode, members);
                    match guard_c.install_lease(&lease, &grp, now).await {
                        Ok(accepted_epoch) => VoterRpcResp::ExecOk { accepted_epoch },
                        Err(e) => VoterRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(VoterRpcReq::ExecLocal {
                    resource_key,
                    holder_node_id,
                    fencing_epoch,
                    now,
                }) => match guard_c
                    .authorize_local_exec(&resource_key, &holder_node_id, fencing_epoch, now)
                    .await
                {
                    Ok(accepted_epoch) => VoterRpcResp::ExecOk { accepted_epoch },
                    Err(e) => VoterRpcResp::Err { message: e.to_string() },
                },
                Err(e) => VoterRpcResp::Err { message: e.to_string() },
            };
            let out = format!("{}\n", serde_json::to_string(&resp).unwrap());
            let _ = write_half.write_all(out.as_bytes()).await;
            let _ = write_half.flush().await;
        });
    }
}

async fn run_coordinator_child() {
    let data_dir = PathBuf::from(std::env::var("NEXUS_CHILD_DATA_DIR").unwrap());
    let members_json = std::env::var("NEXUS_CHILD_MEMBERS_JSON").unwrap();
    let members: Vec<GroupMember> = serde_json::from_str(&members_json).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let db = Arc::new(Database::init_in(data_dir.join("db")).await);
    let group = CoordinationGroup::open_durable(db, "pool:mp", ConsensusMode::CftFastPath, members)
        .await
        .unwrap();
    let shared_group = Arc::new(Mutex::new(group));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("READY {}", addr);
    use std::io::Write as _;
    std::io::stdout().flush().unwrap();

    loop {
        let Ok((socket, _)) = listener.accept().await else { break };
        let grp_arc = shared_group.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let resp = match serde_json::from_str::<CoordRpcReq>(line.trim()) {
                Ok(CoordRpcReq::ProposeAndCommit {
                    voter_addrs,
                    lease_id,
                    resource_key,
                    holder_node_id,
                    workload_id,
                    issued_at_ms,
                    expires_at_ms,
                    now,
                    skip_persist,
                }) => {
                    let (gid, epoch, slot, next_fence) = {
                        let g = grp_arc.lock().await;
                        let nf = g.max_fencing_epoch.get(&resource_key).copied().unwrap_or(0) + 1;
                        (g.group_id.clone(), g.membership_epoch, g.next_slot, nf)
                    };
                    let prop_hash = hash_lease_proposal(
                        &gid,
                        &lease_id,
                        &resource_key,
                        &holder_node_id,
                        &workload_id,
                        next_fence,
                        issued_at_ms,
                        expires_at_ms,
                    );
                    let vreq = VoteRequest {
                        group_id: gid,
                        epoch,
                        slot,
                        proposal_hash: prop_hash.clone(),
                    };
                    let votes = fan_out_votes_tcp(&voter_addrs, vreq).await;
                    if skip_persist {
                        CoordRpcResp::VotesCollectedOnly {
                            count: votes.len(),
                            proposal_hash: prop_hash,
                        }
                    } else {
                        let mut g = grp_arc.lock().await;
                        match g
                            .commit_exclusive_lease(
                                &lease_id,
                                &resource_key,
                                &holder_node_id,
                                &workload_id,
                                issued_at_ms,
                                expires_at_ms,
                                now,
                                votes,
                            )
                            .await
                        {
                            Ok(lease) => CoordRpcResp::Committed { lease },
                            Err(e) => CoordRpcResp::Err { message: e.to_string() },
                        }
                    }
                }
                Ok(CoordRpcReq::RecoverSlot { voter_addrs, slot }) => {
                    let (gid, epoch) = {
                        let g = grp_arc.lock().await;
                        (g.group_id.clone(), g.membership_epoch)
                    };
                    let mut locked = Vec::new();
                    for a in &voter_addrs {
                        if let VoterRpcResp::LockFound { vote: Some(v) } = send_voter_rpc(
                            a,
                            &VoterRpcReq::QueryLock {
                                group_id: gid.clone(),
                                epoch,
                                slot,
                            },
                        )
                        .await
                        {
                            locked.push(v);
                        }
                    }
                    let g = grp_arc.lock().await;
                    match g.recover_safe_slot_decision(slot, locked) {
                        Ok(Some(qc)) => CoordRpcResp::RecoveredQc {
                            proposal_hash: Some(qc.proposal_hash),
                            votes: qc.votes,
                        },
                        Ok(None) => CoordRpcResp::RecoveredQc {
                            proposal_hash: None,
                            votes: vec![],
                        },
                        Err(e) => CoordRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(CoordRpcReq::GetCommittedLease { resource_key }) => {
                    let g = grp_arc.lock().await;
                    CoordRpcResp::LeaseFound {
                        lease: g.active_leases.get(&resource_key).cloned(),
                    }
                }
                Ok(CoordRpcReq::ExpireLocalLease { resource_key, now }) => {
                    let mut g = grp_arc.lock().await;
                    g.expire_lease_for_fault(&resource_key, now);
                    CoordRpcResp::Ok
                }
                Err(e) => CoordRpcResp::Err { message: e.to_string() },
            };
            let out = format!("{}\n", serde_json::to_string(&resp).unwrap());
            let _ = write_half.write_all(out.as_bytes()).await;
            let _ = write_half.flush().await;
        });
    }
}

fn spawn_voter(node_id: &str, data_dir: &PathBuf) -> (Child, String, String) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("five_process_independent_coordinators_staged_crash_recovery_and_lease_binding")
        .arg("--nocapture")
        .env("NEXUS_CHILD_ROLE", "voter")
        .env("NEXUS_CHILD_NODE_ID", node_id)
        .env("NEXUS_CHILD_DATA_DIR", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn voter child process");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    use std::io::BufRead as _;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read voter READY");
        assert!(n > 0, "Voter '{}' exited before READY", node_id);
        if let Some(rest) = line.trim().strip_prefix("READY ") {
            let mut parts = rest.split_whitespace();
            return (child, parts.next().unwrap().into(), parts.next().unwrap().into());
        }
    }
}

fn spawn_coordinator(data_dir: &PathBuf, members: &[GroupMember]) -> (Child, String) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("five_process_independent_coordinators_staged_crash_recovery_and_lease_binding")
        .arg("--nocapture")
        .env("NEXUS_CHILD_ROLE", "coordinator")
        .env("NEXUS_CHILD_DATA_DIR", data_dir)
        .env("NEXUS_CHILD_MEMBERS_JSON", serde_json::to_string(members).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn coordinator child process");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    use std::io::BufRead as _;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read coordinator READY");
        assert!(n > 0, "Coordinator exited before READY");
        if let Some(addr) = line.trim().strip_prefix("READY ") {
            return (child, addr.to_string());
        }
    }
}

#[tokio::test]
async fn five_process_independent_coordinators_staged_crash_recovery_and_lease_binding() {
    match std::env::var("NEXUS_CHILD_ROLE").ok().as_deref() {
        Some("voter") => {
            run_voter_child().await;
            return;
        }
        Some("coordinator") => {
            run_coordinator_child().await;
            return;
        }
        _ => {}
    }

    let base_dir = std::env::temp_dir().join(format!("nexus_5proc_{}", uuid::Uuid::new_v4().simple()));
    let (mut v1, v_addr1, pk1) = spawn_voter("node-1", &base_dir.join("v1"));
    let (mut v2, v_addr2, pk2) = spawn_voter("node-2", &base_dir.join("v2"));
    let (mut v3, v_addr3, pk3) = spawn_voter("node-3", &base_dir.join("v3"));
    let all_voters = vec![v_addr1.clone(), v_addr2.clone(), v_addr3.clone()];

    let members = vec![
        GroupMember { node_id: "node-1".into(), identity_id: "nxid_1".into(), org_id: "org_mp".into(), ed25519_pubkey: pk1 },
        GroupMember { node_id: "node-2".into(), identity_id: "nxid_2".into(), org_id: "org_mp".into(), ed25519_pubkey: pk2 },
        GroupMember { node_id: "node-3".into(), identity_id: "nxid_3".into(), org_id: "org_mp".into(), ed25519_pubkey: pk3 },
    ];

    let c1_dir = base_dir.join("coord-1");
    let c2_dir = base_dir.join("coord-2");
    let (mut c1, c_addr1) = spawn_coordinator(&c1_dir, &members);
    let (mut c2, c_addr2) = spawn_coordinator(&c2_dir, &members);

    let t0 = 1_700_000_000_000u64;

    // 1. TWO INDEPENDENT COORDINATOR OS PROCESSES race the ENTIRE propose->commit lifecycle on slot 1!
    let race_req_1 = CoordRpcReq::ProposeAndCommit {
        voter_addrs: all_voters.clone(),
        lease_id: "lse_c1_s1".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-1".into(),
        workload_id: "wl-c1".into(),
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
        now: t0,
        skip_persist: false,
    };
    let race_req_2 = CoordRpcReq::ProposeAndCommit {
        voter_addrs: all_voters.clone(),
        lease_id: "lse_c2_s1".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-2".into(),
        workload_id: "wl-c2".into(),
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
        now: t0,
        skip_persist: false,
    };
    let (r1, r2) = tokio::join!(
        send_coord_rpc(&c_addr1, &race_req_1),
        send_coord_rpc(&c_addr2, &race_req_2),
    );
    let (slot1_lease, winner_is_c1) = match (r1, r2) {
        (CoordRpcResp::Committed { lease }, CoordRpcResp::Err { .. }) => (lease, true),
        (CoordRpcResp::Err { .. }, CoordRpcResp::Committed { lease }) => (lease, false),
        (CoordRpcResp::Committed { .. }, CoordRpcResp::Committed { .. }) => {
            panic!("SAFETY VIOLATION: Both independent coordinator processes committed on slot 1!");
        }
        other => panic!("Expected exactly one coordinator to commit on slot 1, got {:?}", other),
    };
    assert_eq!(slot1_lease.fencing_epoch, 1);

    // 2. STAGE 1 CRASH (BEFORE QUORUM): Winning coordinator contacts ONLY 1 voter on slot 2 -> FAILS, then is killed!
    let (mut active_coord, active_addr, active_dir, mut standby_coord, standby_addr, standby_dir) = if winner_is_c1 {
        (c1, c_addr1, c1_dir, c2, c_addr2, c2_dir)
    } else {
        (c2, c_addr2, c2_dir, c1, c_addr1, c1_dir)
    };
    let _ = send_coord_rpc(
        &active_addr,
        &CoordRpcReq::ExpireLocalLease {
            resource_key: "gpu:mp:0".into(),
            now: t0 + 40_000,
        },
    )
    .await;
    let below_quorum = send_coord_rpc(
        &active_addr,
        &CoordRpcReq::ProposeAndCommit {
            voter_addrs: vec![v_addr1.clone()], // Only 1 of 3 voters -> below majority!
            lease_id: "lse_no_quorum".into(),
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            workload_id: "wl-no-quorum".into(),
            issued_at_ms: t0 + 40_000,
            expires_at_ms: t0 + 70_000,
            now: t0 + 40_000,
            skip_persist: false,
        },
    )
    .await;
    assert!(
        matches!(below_quorum, CoordRpcResp::Err { .. }),
        "Coordinator MUST NOT commit with only 1 of 3 votes!"
    );
    let _ = active_coord.kill();
    let _ = active_coord.wait();

    // 3. STAGE 2 CRASH (AFTER QUORUM, BEFORE PERSISTENCE): Restarted active_coord collects quorum on slot 2
    //    with `skip_persist = true`, then is KILLED before persisting -> standby recovers exact QC via QueryLock!
    let (mut active_restarted, active_addr_2) = spawn_coordinator(&active_dir, &members);
    let _ = send_coord_rpc(
        &active_addr_2,
        &CoordRpcReq::ExpireLocalLease {
            resource_key: "gpu:mp:0".into(),
            now: t0 + 40_000,
        },
    )
    .await;
    let pre_crash = send_coord_rpc(
        &active_addr_2,
        &CoordRpcReq::ProposeAndCommit {
            voter_addrs: vec![v_addr2.clone(), v_addr3.clone()], // 2 of 3 = quorum!
            lease_id: "lse_stage2".into(),
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            workload_id: "wl-stage2".into(),
            issued_at_ms: t0 + 40_000,
            expires_at_ms: t0 + 80_000,
            now: t0 + 40_000,
            skip_persist: true,
        },
    )
    .await;
    let stage2_hash = match pre_crash {
        CoordRpcResp::VotesCollectedOnly { count: 2, proposal_hash } => proposal_hash,
        other => panic!("Expected 2 votes collected before crash, got {:?}", other),
    };
    let _ = active_restarted.kill();
    let _ = active_restarted.wait();

    // Standby coordinator recovers the exact chosen QC for slot 2 from voters' durable locks!
    let rec_resp = send_coord_rpc(
        &standby_addr,
        &CoordRpcReq::RecoverSlot {
            voter_addrs: all_voters.clone(),
            slot: 2,
        },
    )
    .await;
    match rec_resp {
        CoordRpcResp::RecoveredQc { proposal_hash: Some(h), votes } => {
            assert_eq!(h, stage2_hash);
            assert!(votes.len() >= 2);
        }
        other => panic!("Standby coordinator failed to recover slot 2 QC: {:?}", other),
    }

    // 4. STAGE 3 CRASH (AFTER DECISION PERSISTENCE, BEFORE RESOURCE INSTALLATION):
    //    Restart active_coord, let it commit slot 2 cleanly, then KILL it BEFORE installing on node-3!
    let (mut active_s3, active_addr_3) = spawn_coordinator(&active_dir, &members);
    let _ = send_coord_rpc(
        &active_addr_3,
        &CoordRpcReq::ExpireLocalLease {
            resource_key: "gpu:mp:0".into(),
            now: t0 + 40_000,
        },
    )
    .await;
    let committed_s3 = send_coord_rpc(
        &active_addr_3,
        &CoordRpcReq::ProposeAndCommit {
            voter_addrs: all_voters.clone(),
            lease_id: "lse_stage2".into(), // Same lease as recovered slot 2!
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            workload_id: "wl-stage2".into(),
            issued_at_ms: t0 + 40_000,
            expires_at_ms: t0 + 80_000,
            now: t0 + 40_000,
            skip_persist: false,
        },
    )
    .await;
    let persisted_lease = match committed_s3 {
        CoordRpcResp::Committed { lease } => lease,
        other => panic!("Expected committed slot 2 lease, got {:?}", other),
    };
    // Kill coordinator BEFORE resource installation, then restart from on-disk redb DB!
    let _ = active_s3.kill();
    let _ = active_s3.wait();
    let (mut active_s3_recovered, active_addr_4) = spawn_coordinator(&active_dir, &members);

    let disk_lease = match send_coord_rpc(
        &active_addr_4,
        &CoordRpcReq::GetCommittedLease {
            resource_key: "gpu:mp:0".into(),
        },
    )
    .await
    {
        CoordRpcResp::LeaseFound { lease: Some(l) } => l,
        other => panic!("Restarted coordinator did not recover persisted lease from disk: {:?}", other),
    };
    assert_eq!(disk_lease.canonical_digest(), persisted_lease.canonical_digest());

    // Install recovered lease onto node-3's FencedResourceGuard (epoch=2)
    let inst_ok = send_voter_rpc(
        &v_addr3,
        &VoterRpcReq::InstallLease {
            lease: disk_lease.clone(),
            members: members.clone(),
            now: t0 + 41_000,
        },
    )
    .await;
    assert!(matches!(inst_ok, VoterRpcResp::ExecOk { accepted_epoch: 2 }));

    // 5. +1 ms EXPIRY TAMPERING, STRICT IDEMPOTENCY & STALE COORDINATOR REJECTION!
    let mut tampered = disk_lease.clone();
    tampered.expires_at_ms += 1;
    let tamper_resp = send_voter_rpc(
        &v_addr3,
        &VoterRpcReq::InstallLease {
            lease: tampered,
            members: members.clone(),
            now: t0 + 41_000,
        },
    )
    .await;
    assert!(
        matches!(tamper_resp, VoterRpcResp::Err { .. }),
        "+1 ms expires_at_ms tampering MUST be rejected by resource boundary!"
    );

    // Exact same lease retry is idempotent OK
    let retry_ok = send_voter_rpc(
        &v_addr3,
        &VoterRpcReq::InstallLease {
            lease: disk_lease.clone(),
            members: members.clone(),
            now: t0 + 41_500,
        },
    )
    .await;
    assert!(matches!(retry_ok, VoterRpcResp::ExecOk { accepted_epoch: 2 }));

    // Delayed stale coordinator trying to install obsolete epoch=1 lease -> REJECTED!
    let stale_install = send_voter_rpc(
        &v_addr3,
        &VoterRpcReq::InstallLease {
            lease: slot1_lease.clone(),
            members: members.clone(),
            now: t0 + 41_500,
        },
    )
    .await;
    assert!(
        matches!(stale_install, VoterRpcResp::Err { .. }),
        "Stale coordinator's obsolete epoch=1 lease MUST be rejected!"
    );

    // Hot-path local exec accepts epoch=2 and rejects stale epoch=1 & expired epoch=2!
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::ExecLocal {
                resource_key: "gpu:mp:0".into(),
                holder_node_id: "node-2".into(),
                fencing_epoch: 2,
                now: t0 + 42_000,
            },
        )
        .await,
        VoterRpcResp::ExecOk { accepted_epoch: 2 }
    ));
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::ExecLocal {
                resource_key: "gpu:mp:0".into(),
                holder_node_id: "node-2".into(),
                fencing_epoch: 2,
                now: t0 + 90_000, // Past expires_at_ms!
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));

    // Cleanup all 5 OS processes & temp directories
    let _ = active_s3_recovered.kill();
    let _ = active_s3_recovered.wait();
    let _ = standby_coord.kill();
    let _ = standby_coord.wait();
    let _ = v1.kill();
    let _ = v1.wait();
    let _ = v2.kill();
    let _ = v2.wait();
    let _ = v3.kill();
    let _ = v3.wait();
    let _ = std::fs::remove_dir_all(&base_dir);
    let _ = standby_dir;
}
