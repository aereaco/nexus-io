# Nexus-IO Beta: 4-Node Cluster Deployment Guide

This guide details how to deploy your "Personal Dark Cloud" on 4 test nodes using the Nexus-IO Beta binary (`nexus-io`).

## Prerequisites
- 4 Linux nodes (physical or VM)
- `nexus-io` binary (built via `cargo build --release`)
- Root privileges (for WireGuard interface creation) OR `CAP_NET_ADMIN`

## 1. Distribution
Copy the binary to all 4 nodes:
```bash
# On your dev machine
scp ./target/release/nexus-io node1:~/
scp ./target/release/nexus-io node2:~/
scp ./target/release/nexus-io node3:~/
scp ./target/release/nexus-io node4:~/
```

## 2. Initialization & Identity
Run on **ALL** nodes to generate unique identities and WireGuard keys:
```bash
# Initialize storage and network identity
sudo ./nexus-io "storage init"

# Get the node's public info (Save this!)
sudo ./nexus-io "storage peer list"
```
*Note the `pubkey` (WireGuard) and `endpoint` (IP:Port) for each node.*

## 3. Peering (Mesh Activation)
Pick **Node 1** as your "Bootstrap" node. You will introduce the others to it.

On **Node 1**:
```bash
# Check status
sudo ./nexus-io "storage status"
```

On **Node 2, 3, 4**:
Run the following to peer with Node 1:
```bash
# Replace with Node 1's actual Pubkey and Endpoint
sudo ./nexus-io "storage peer add <NODE_1_PUBKEY> <NODE_1_IP>:51820"
```

*The **Mesh Reactor** will automatically:*
1.  Configure the WireGuard tunnel.
2.  Connect Garage DHT to Node 1.
3.  Sync the cluster layout (Node 1 will see new peers).

## 4. Verification
On any node, check the status. You should see 4 Garage nodes:
```bash
sudo ./nexus-io "storage status"
```

Test data replication:
```bash
# On Node 1
sudo ./nexus-io "storage bucket create beta_test"
sudo ./nexus-io "storage put beta_test hello.txt 'Hello from Node 1'"

# On Node 4
sudo ./nexus-io "storage get beta_test hello.txt"
# Output should be: Hello from Node 1
```

## Troubleshooting
- **Logs**: Run with `RUST_LOG=debug` to see Mesh Reactor logs.
- **Firewall**: Ensure UDP port 51820 and TCP port 3901 are open.
