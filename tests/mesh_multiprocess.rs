//! P1 Acceptance Test: Real Separate-Process Multi-Node Distributed Safety Suite
//!
//! Proves across **3 independent OS processes** (zero shared memory, zero shared private keys,
//! separate on-disk `redb` databases, real localhost TCP sockets):
//! 1. **Two competing coordinators** race conflicting leases on the exact same `(group, epoch, slot)`
//!    concurrently over TCP -> at most ONE can reach quorum!
//! 2. **Coordinator crash recovery:** After Coordinator 1 collects quorum votes on slot 2 and
//!    "crashes" without persisting, Coordinator 2 queries voters' durable locks (`QueryLock`) over
//!    TCP and recovers the exact `QuorumCertificate`!
//! 3. **Real OS process `kill()` + restart** of `node-1`: recovers its durable vote-lock from disk
//!    and STILL rejects conflicting votes for slot 1!
//! 4. **Authenticated & Atomic Resource-Boundary Fencing:**
//!    - Forged high-epoch lease (invalid QC) sent directly to `node-3`'s `InstallLease` RPC -> REJECTED!
//!    - Concurrent out-of-order `InstallLease` calls (`epoch=2` and `epoch=1` racing over TCP) ->
//!      monotonic fence NEVER regresses; cheap O(1) `ExecLocal` accepts `epoch=2` and rejects stale `epoch=1`!

use nexus_io::db::Database;
use nexus_io::mesh::consensus::{
    hash_proposal, ConsensusMode, CoordinationGroup, FencedLease, FencedResourceGuard, GroupMember,
    QuorumCertificate, SignedVote, VoteRequest, VoterNode,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum NodeRpcReq {
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
enum NodeRpcResp {
    VoteOk { vote: SignedVote },
    LockFound { vote: Option<SignedVote> },
    ExecOk { accepted_epoch: u64 },
    Err { message: String },
}

async fn send_rpc(addr: &str, req: &NodeRpcReq) -> NodeRpcResp {
    let mut stream = TcpStream::connect(addr).await.expect("connect to child node TCP socket");
    let line = format!("{}\n", serde_json::to_string(req).unwrap());
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(resp_line.trim()).expect("valid JSON RPC response")
}

async fn fan_out_votes(addrs: &[String], req: VoteRequest) -> Vec<SignedVote> {
    let mut set = tokio::task::JoinSet::new();
    for addr in addrs {
        let a = addr.clone();
        let r = req.clone();
        set.spawn(async move { send_rpc(&a, &NodeRpcReq::Vote(r)).await });
    }
    let mut votes = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(NodeRpcResp::VoteOk { vote }) = res {
            votes.push(vote);
        }
    }
    votes
}

async fn run_child_node_server() {
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
    let voter = VoterNode::new(node_id.clone(), sk, db.clone());
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
            let resp = match serde_json::from_str::<NodeRpcReq>(line.trim()) {
                Ok(NodeRpcReq::Vote(vreq)) => match voter_c.cast_vote(&vreq).await {
                    Ok(vote) => NodeRpcResp::VoteOk { vote },
                    Err(e) => NodeRpcResp::Err { message: e.to_string() },
                },
                Ok(NodeRpcReq::QueryLock { group_id, epoch, slot }) => {
                    match voter_c.query_slot_lock(&group_id, epoch, slot).await {
                        Ok(vote) => NodeRpcResp::LockFound { vote },
                        Err(e) => NodeRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(NodeRpcReq::InstallLease { lease, members, now }) => {
                    let grp = CoordinationGroup::new(lease.group_id.clone(), lease.qc.mode, members);
                    match guard_c.install_lease(&lease, &grp, now).await {
                        Ok(accepted_epoch) => NodeRpcResp::ExecOk { accepted_epoch },
                        Err(e) => NodeRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(NodeRpcReq::ExecLocal {
                    resource_key,
                    holder_node_id,
                    fencing_epoch,
                    now,
                }) => match guard_c
                    .authorize_local_exec(&resource_key, &holder_node_id, fencing_epoch, now)
                    .await
                {
                    Ok(accepted_epoch) => NodeRpcResp::ExecOk { accepted_epoch },
                    Err(e) => NodeRpcResp::Err { message: e.to_string() },
                },
                Err(e) => NodeRpcResp::Err { message: e.to_string() },
            };
            let out = format!("{}\n", serde_json::to_string(&resp).unwrap());
            let _ = write_half.write_all(out.as_bytes()).await;
            let _ = write_half.flush().await;
        });
    }
}

fn spawn_child_node(node_id: &str, data_dir: &PathBuf) -> (Child, String, String) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("multiprocess_competing_coordinators_crash_recovery_and_authenticated_fencing")
        .arg("--nocapture")
        .env("NEXUS_CHILD_MODE", "1")
        .env("NEXUS_CHILD_NODE_ID", node_id)
        .env("NEXUS_CHILD_DATA_DIR", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child node process");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    use std::io::BufRead as _;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read child READY line");
        assert!(n > 0, "Child node '{}' exited before READY", node_id);
        if let Some(rest) = line.trim().strip_prefix("READY ") {
            let mut parts = rest.split_whitespace();
            let addr = parts.next().unwrap().to_string();
            let pk = parts.next().unwrap().to_string();
            return (child, addr, pk);
        }
    }
}

#[tokio::test]
async fn multiprocess_competing_coordinators_crash_recovery_and_authenticated_fencing() {
    if std::env::var("NEXUS_CHILD_MODE").ok().as_deref() == Some("1") {
        run_child_node_server().await;
        return;
    }

    let base_dir = std::env::temp_dir().join(format!("nexus_mp_mesh_{}", uuid::Uuid::new_v4().simple()));
    let d1 = base_dir.join("node-1");
    let d2 = base_dir.join("node-2");
    let d3 = base_dir.join("node-3");

    let (mut c1, addr1, pk1) = spawn_child_node("node-1", &d1);
    let (mut c2, addr2, pk2) = spawn_child_node("node-2", &d2);
    let (mut c3, addr3, pk3) = spawn_child_node("node-3", &d3);
    let addrs = vec![addr1.clone(), addr2.clone(), addr3.clone()];

    let members = vec![
        GroupMember { node_id: "node-1".into(), identity_id: "nxid_node1".into(), org_id: "org_mp".into(), ed25519_pubkey: pk1 },
        GroupMember { node_id: "node-2".into(), identity_id: "nxid_node2".into(), org_id: "org_mp".into(), ed25519_pubkey: pk2 },
        GroupMember { node_id: "node-3".into(), identity_id: "nxid_node3".into(), org_id: "org_mp".into(), ed25519_pubkey: pk3 },
    ];

    let mut coord_a = CoordinationGroup::open_durable(
        Arc::new(Database::open_mem()),
        "pool:mp",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let mut coord_b = CoordinationGroup::open_durable(
        Arc::new(Database::open_mem()),
        "pool:mp",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();

    // 1. TWO COMPETING COORDINATORS race conflicting leases on slot=1 concurrently over real TCP!
    let hash_a = hash_proposal("gpu:mp:0", "node-1", "wl-alpha", 1);
    let hash_b = hash_proposal("gpu:mp:0", "node-2", "wl-beta", 1);
    let req_a = VoteRequest { group_id: "pool:mp".into(), epoch: 1, slot: 1, proposal_hash: hash_a };
    let req_b = VoteRequest { group_id: "pool:mp".into(), epoch: 1, slot: 1, proposal_hash: hash_b };

    let (votes_a, votes_b) = tokio::join!(
        fan_out_votes(&addrs, req_a.clone()),
        fan_out_votes(&addrs, req_b.clone()),
    );
    let t0 = 1_700_000_000_000u64;
    let res_a = coord_a.commit_exclusive_lease("gpu:mp:0", "node-1", "wl-alpha", 10_000, t0, votes_a).await;
    let res_b = coord_b.commit_exclusive_lease("gpu:mp:0", "node-2", "wl-beta", 10_000, t0, votes_b).await;

    // SAFETY INVARIANT: At most ONE competing coordinator can commit on slot=1!
    assert!(
        !(res_a.is_ok() && res_b.is_ok()),
        "CRITICAL SAFETY VIOLATION: Both competing coordinators committed conflicting leases on slot 1!"
    );
    let (winner_lease, loser_req) = match (res_a, res_b) {
        (Ok(l), Err(_)) => (l, req_b),
        (Err(_), Ok(l)) => (l, req_a),
        _ => panic!("One of the two competing coordinators should reach majority quorum on 3 nodes"),
    };
    assert_eq!(winner_lease.fencing_epoch, 1);

    // 2. REAL OS PROCESS KILL + RESTART of node-1 -> restarted voter STILL rejects losing proposal on slot 1!
    let _ = c1.kill();
    let _ = c1.wait();
    let (mut c1_restarted, addr1_new, _) = spawn_child_node("node-1", &d1);
    let restarted_resp = send_rpc(&addr1_new, &NodeRpcReq::Vote(loser_req)).await;
    assert!(
        matches!(restarted_resp, NodeRpcResp::Err { .. }),
        "Restarted node-1 MUST reject conflicting vote on slot 1!"
    );

    // 3. COORDINATOR CRASH RECOVERY: Coordinator collects quorum votes on slot 2 and crashes before committing!
    let hash_slot2 = hash_proposal("gpu:mp:0", "node-2", "wl-recovered", 2);
    let req_slot2 = VoteRequest {
        group_id: "pool:mp".into(),
        epoch: 1,
        slot: 2,
        proposal_hash: hash_slot2.clone(),
    };
    let live_addrs = vec![addr1_new.clone(), addr2.clone(), addr3.clone()];
    let _abandoned_votes = fan_out_votes(&live_addrs, req_slot2).await;
    // Now a fresh recovery coordinator queries voters' durable locks over TCP and reconstructs the QC!
    let mut recovered_votes = Vec::new();
    for a in &live_addrs {
        if let NodeRpcResp::LockFound { vote: Some(v) } = send_rpc(
            a,
            &NodeRpcReq::QueryLock {
                group_id: "pool:mp".into(),
                epoch: 1,
                slot: 2,
            },
        )
        .await
        {
            recovered_votes.push(v);
        }
    }
    let recovery_coord = CoordinationGroup::new("pool:mp", ConsensusMode::CftFastPath, members.clone());
    let recovered_qc = recovery_coord
        .recover_qc_from_voter_locks(2, recovered_votes)
        .unwrap()
        .expect("Recovery coordinator MUST reconstruct valid QC from voters' durable locks!");
    assert_eq!(recovered_qc.proposal_hash, hash_slot2);

    let lease_epoch2 = FencedLease {
        lease_id: "lse_epoch2".into(),
        group_id: "pool:mp".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-2".into(),
        workload_id: "wl-recovered".into(),
        fencing_epoch: 2,
        issued_at_ms: t0 + 15_000,
        expires_at_ms: t0 + 60_000,
        qc: recovered_qc,
    };

    // 4. FORGED HIGH-EPOCH LEASE ATTACK against child node-3's resource boundary -> REJECTED!
    let forged = FencedLease {
        lease_id: "lse_forged".into(),
        group_id: "pool:mp".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-1".into(),
        workload_id: "wl-evil".into(),
        fencing_epoch: 999,
        issued_at_ms: t0,
        expires_at_ms: t0 + 60_000,
        qc: QuorumCertificate {
            group_id: "pool:mp".into(),
            epoch: 1,
            slot: 99,
            proposal_hash: hash_proposal("gpu:mp:0", "node-1", "wl-evil", 999),
            mode: ConsensusMode::CftFastPath,
            votes: vec![],
        },
    };
    let forged_resp = send_rpc(
        &addr3,
        &NodeRpcReq::InstallLease {
            lease: forged,
            members: members.clone(),
            now: t0 + 16_000,
        },
    )
    .await;
    assert!(
        matches!(forged_resp, NodeRpcResp::Err { .. }),
        "Resource boundary MUST reject forged high-epoch lease without valid QC!"
    );

    // 5. CONCURRENT OUT-OF-ORDER FENCING RACE: install epoch=2 and epoch=1 concurrently at node-3!
    let req_install_2 = NodeRpcReq::InstallLease {
        lease: lease_epoch2.clone(),
        members: members.clone(),
        now: t0 + 16_000,
    };
    let req_install_1 = NodeRpcReq::InstallLease {
        lease: winner_lease.clone(),
        members: members.clone(),
        now: t0 + 16_000,
    };
    let (r_ep2, _r_ep1) = tokio::join!(
        send_rpc(&addr3, &req_install_2),
        send_rpc(&addr3, &req_install_1),
    );
    assert!(matches!(r_ep2, NodeRpcResp::ExecOk { accepted_epoch: 2 }));

    // Cheap O(1) hot-path local execution check on node-3: accepts epoch=2, REJECTS stale epoch=1!
    let ok_hot = send_rpc(
        &addr3,
        &NodeRpcReq::ExecLocal {
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            fencing_epoch: 2,
            now: t0 + 17_000,
        },
    )
    .await;
    assert!(matches!(ok_hot, NodeRpcResp::ExecOk { accepted_epoch: 2 }));

    let stale_hot = send_rpc(
        &addr3,
        &NodeRpcReq::ExecLocal {
            resource_key: "gpu:mp:0".into(),
            holder_node_id: winner_lease.holder_node_id.clone(),
            fencing_epoch: 1,
            now: t0 + 17_000,
        },
    )
    .await;
    assert!(
        matches!(stale_hot, NodeRpcResp::Err { .. }),
        "Hot-path ExecLocal MUST reject stale epoch=1 after monotonic advance to epoch=2!"
    );

    let _ = c1_restarted.kill();
    let _ = c1_restarted.wait();
    let _ = c2.kill();
    let _ = c2.wait();
    let _ = c3.kill();
    let _ = c3.wait();
    let _ = std::fs::remove_dir_all(&base_dir);
}
