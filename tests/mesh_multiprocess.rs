//! P1 Acceptance Test: Real Separate-Process Multi-Node Mesh Validation
//!
//! Proves across **independent OS processes** (zero shared memory, zero shared private keys,
//! separate on-disk `redb` databases, real localhost TCP sockets):
//! 1. 3 child voter/resource processes each generate and keep their own Ed25519 private key and
//!    their own on-disk `nexus-db` database.
//! 2. Parent coordinator collects real TCP votes to commit an exclusive lease (`fencing_epoch=1`).
//! 3. Conflicting proposal on the same `(group_id, epoch, slot)` is REJECTED by every child's
//!    durable `VoterNode` lock — conflicting proposals CANNOT both commit.
//! 4. Child process `node-1` is **terminated (`kill()`) and restarted** against its on-disk DB:
//!    it recovers its durable vote-lock and STILL rejects conflicting votes for that slot!
//! 5. Lease reassignment mints `fencing_epoch=2`; resource boundary (`FencedResourceGuard`) on
//!    child `node-3` accepts `fencing_epoch=2` and REJECTS stale `fencing_epoch=1`!

use nexus_io::db::Database;
use nexus_io::mesh::consensus::{
    hash_proposal, ConsensusMode, CoordinationGroup, FencedResourceGuard, GroupMember, SignedVote,
    VoteRequest, VoterNode,
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
    ExecFenced {
        resource_key: String,
        holder_node_id: String,
        fencing_epoch: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum NodeRpcResp {
    VoteOk { vote: SignedVote },
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

/// Child-process entrypoint: runs an isolated voter + resource-boundary node over TCP.
async fn run_child_node_server() {
    let node_id = std::env::var("NEXUS_CHILD_NODE_ID").unwrap();
    let data_dir = PathBuf::from(std::env::var("NEXUS_CHILD_DATA_DIR").unwrap());
    std::fs::create_dir_all(&data_dir).unwrap();

    // Persist keypair inside child's private directory so restart keeps the exact same identity
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

    // Announce ONLY address and PUBLIC key to parent over stdout (private key never leaves process!)
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
                Ok(NodeRpcReq::ExecFenced {
                    resource_key,
                    holder_node_id,
                    fencing_epoch,
                }) => match guard_c
                    .accept_fenced_operation(&resource_key, &holder_node_id, fencing_epoch)
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
        .arg("multiprocess_three_node_mesh_vote_locks_kill_restart_and_boundary_fencing")
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
async fn multiprocess_three_node_mesh_vote_locks_kill_restart_and_boundary_fencing() {
    if std::env::var("NEXUS_CHILD_MODE").ok().as_deref() == Some("1") {
        run_child_node_server().await;
        return;
    }

    let base_dir = std::env::temp_dir().join(format!("nexus_mp_mesh_{}", uuid::Uuid::new_v4().simple()));
    let d1 = base_dir.join("node-1");
    let d2 = base_dir.join("node-2");
    let d3 = base_dir.join("node-3");

    // 1. Spawn 3 truly separate OS child processes (separate DBs, separate private keys, real TCP sockets)
    let (mut c1, addr1, pk1) = spawn_child_node("node-1", &d1);
    let (mut c2, addr2, pk2) = spawn_child_node("node-2", &d2);
    let (mut c3, addr3, pk3) = spawn_child_node("node-3", &d3);

    let members = vec![
        GroupMember { node_id: "node-1".into(), identity_id: "nxid_node1".into(), org_id: "org_mp".into(), ed25519_pubkey: pk1 },
        GroupMember { node_id: "node-2".into(), identity_id: "nxid_node2".into(), org_id: "org_mp".into(), ed25519_pubkey: pk2 },
        GroupMember { node_id: "node-3".into(), identity_id: "nxid_node3".into(), org_id: "org_mp".into(), ed25519_pubkey: pk3 },
    ];
    let mut group = CoordinationGroup::new("pool:mp", ConsensusMode::CftFastPath, members);

    // 2. Collect real TCP votes for Proposal A (slot=1, fencing_epoch=1 -> holder=node-1)
    let hash_a = hash_proposal("gpu:mp:0", "node-1", "wl-alpha", 1);
    let req_a = VoteRequest {
        group_id: "pool:mp".into(),
        epoch: 1,
        slot: 1,
        proposal_hash: hash_a,
    };
    let mut votes_a = Vec::new();
    for addr in [&addr1, &addr2, &addr3] {
        match send_rpc(addr, &NodeRpcReq::Vote(req_a.clone())).await {
            NodeRpcResp::VoteOk { vote } => votes_a.push(vote),
            other => panic!("Expected VoteOk, got {:?}", other),
        }
    }
    let t0 = 1_700_000_000_000u64;
    let lease_a = group
        .commit_exclusive_lease("gpu:mp:0", "node-1", "wl-alpha", 10_000, t0, votes_a)
        .await
        .unwrap();
    assert_eq!(lease_a.fencing_epoch, 1);

    // Execute work at node-3's resource boundary with fencing_epoch=1 -> ACCEPTED
    let exec1 = send_rpc(
        &addr3,
        &NodeRpcReq::ExecFenced {
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-1".into(),
            fencing_epoch: 1,
        },
    )
    .await;
    assert!(matches!(exec1, NodeRpcResp::ExecOk { accepted_epoch: 1 }));

    // 3. Conflicting Proposal B on exact same (group, epoch=1, slot=1) -> ALL 3 child processes MUST REJECT!
    let hash_b = hash_proposal("gpu:mp:0", "node-2", "wl-conflict", 1);
    let req_b = VoteRequest {
        group_id: "pool:mp".into(),
        epoch: 1,
        slot: 1,
        proposal_hash: hash_b,
    };
    for addr in [&addr1, &addr2, &addr3] {
        let resp = send_rpc(addr, &NodeRpcReq::Vote(req_b.clone())).await;
        assert!(
            matches!(resp, NodeRpcResp::Err { .. }),
            "Child node at {} MUST reject conflicting vote on slot 1!",
            addr
        );
    }

    // 4. REAL OS PROCESS TERMINATION + RESTART of node-1!
    let _ = c1.kill();
    let _ = c1.wait();
    let (mut c1_restarted, addr1_new, _pk1_same) = spawn_child_node("node-1", &d1);

    // Restarted node-1 MUST recover its durable vote-lock from disk and STILL reject conflicting Proposal B!
    let resp_after_restart = send_rpc(&addr1_new, &NodeRpcReq::Vote(req_b.clone())).await;
    assert!(
        matches!(resp_after_restart, NodeRpcResp::Err { .. }),
        "Restarted node-1 MUST still reject conflicting vote on slot 1!"
    );

    // 5. Reassign gpu:mp:0 to node-2 on slot=2 (fencing_epoch=2) after lease expiry
    let t_reassign = t0 + 20_000;
    group.expire_lease_for_fault("gpu:mp:0", t_reassign);
    let hash_reassign = hash_proposal("gpu:mp:0", "node-2", "wl-beta", 2);
    let req_reassign = VoteRequest {
        group_id: "pool:mp".into(),
        epoch: 1,
        slot: 2,
        proposal_hash: hash_reassign,
    };
    let mut votes_2 = Vec::new();
    for addr in [&addr2, &addr3] {
        if let NodeRpcResp::VoteOk { vote } = send_rpc(addr, &NodeRpcReq::Vote(req_reassign.clone())).await {
            votes_2.push(vote);
        }
    }
    let lease_b = group
        .commit_exclusive_lease("gpu:mp:0", "node-2", "wl-beta", 30_000, t_reassign, votes_2)
        .await
        .unwrap();
    assert_eq!(lease_b.fencing_epoch, 2);

    // Resource boundary on node-3 accepts new fencing_epoch=2 and REJECTS stale fencing_epoch=1 from node-1!
    let exec2 = send_rpc(
        &addr3,
        &NodeRpcReq::ExecFenced {
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            fencing_epoch: 2,
        },
    )
    .await;
    assert!(matches!(exec2, NodeRpcResp::ExecOk { accepted_epoch: 2 }));

    let stale_exec = send_rpc(
        &addr3,
        &NodeRpcReq::ExecFenced {
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-1".into(),
            fencing_epoch: 1,
        },
    )
    .await;
    assert!(
        matches!(stale_exec, NodeRpcResp::Err { .. }),
        "Resource boundary MUST reject stale fencing_epoch=1 after reassignment to epoch 2!"
    );

    // Cleanup child processes & temp directories
    let _ = c1_restarted.kill();
    let _ = c1_restarted.wait();
    let _ = c2.kill();
    let _ = c2.wait();
    let _ = c3.kill();
    let _ = c3.wait();
    let _ = std::fs::remove_dir_all(&base_dir);
}
