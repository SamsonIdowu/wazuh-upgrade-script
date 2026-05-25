# Wazuh Upgrade Automation

Scripts for upgrading Wazuh central components (indexer, manager, dashboard, filebeat) on single-node and multi-node cluster deployments.

---

## Scripts

| Script | Purpose |
|---|---|
| `wazuh_upgrade_cluster.py` | Upgrades a multi-node cluster over SSH. Follows a 4-phase rolling upgrade sequence: remote nodes first, then local. |
| `wazuh_upgrade_single.py` | Upgrades a single all-in-one node locally (no SSH required). |
| `wazuh_upgrade_common.py` | Shared helper library used by both scripts above. Not run directly. |

---

## Requirements

**Python 3.8 or later**

```bash
python3 --version
```

**Install dependencies**

```bash
pip3 install pyyaml paramiko
```

Or via the requirements file:

```bash
pip3 install -r requirements.txt
```

**Runtime requirements on every target node**

- Root or passwordless `sudo`
- `curl` (used to call the Wazuh Indexer REST API)
- `gpg` on Debian/Ubuntu nodes (used to import the Wazuh GPG key)
- SSH key-based access from the control machine to all remote nodes (cluster script only)

---

## Configuration

Edit `config.yml` before running either script.

```yaml
# SSH settings used by the cluster script to reach remote nodes
ssh:
  username: <SSH_USER>
  port: 22
  key: ~/.ssh/wazuh_upgrade       # path to your private key; generated if absent
  sudo: true
  # sudo_password: "yourpassword" # only needed if sudo requires a password

wazuh:
  indexer:
    username: admin
    password: <YOUR_INDEXER_PASSWORD>
    api_url: https://localhost:9200

nodes:
  indexers:
    - name: indexer-1
      host: 192.168.1.10
      local: true          # marks this node as the one running the script
    - name: indexer-2
      host: 192.168.1.11

  servers:
    - name: wazuh-server-1
      host: 192.168.1.10
    - name: wazuh-server-2
      host: 192.168.1.11

  dashboards:
    - name: wazuh-dashboard-1
      host: 192.168.1.10

source_version: "4.8.2"    # current installed version (used for config patching)
target_version: "4.14.5"   # version to upgrade to
```

**Key notes**

- Mark the node running the script with `local: true` under the `indexers` section.
- A host appearing in multiple sections (indexers + servers + dashboards) is deduplicated automatically; the name from its first appearance is used in logs.
- The `ssh.key` path is expanded with `~`. If the file does not exist, a new ed25519 keypair is generated there automatically.

---

## Usage — Cluster script

Run from the **local (control) node** as root or with sudo:

```bash
sudo python3 wazuh_upgrade_cluster.py --config config.yml [options]
```

### Options

```
--config PATH        Path to config.yml (default: config.yml)
--verbose            Show debug-level output in the terminal

Node scope (mutually exclusive — default: all nodes, remote first):
  --local            Upgrade only the local node
  --remote-only      Upgrade only remote nodes
                     (Phases 1 and 3 still run on local — they are cluster-level operations)

Component scope (combinable — default: all components):
  --wazuh-indexer    Upgrade wazuh-indexer  →  runs Phases 1, 2, 3; skips Phase 4
  --wazuh-manager    Upgrade wazuh-manager  →  runs Phase 4 only
  --wazuh-dashboard  Upgrade wazuh-dashboard → runs Phase 4 only
  --filebeat         Upgrade filebeat        → runs Phase 4 only
  --all              Upgrade all components (explicit alias for the default)
```

Component flags are **additive**: `--wazuh-manager --filebeat` upgrades both.

### Examples

```bash
# Full upgrade of all nodes (default behaviour)
sudo python3 wazuh_upgrade_cluster.py --config config.yml

# Full upgrade with verbose output
sudo python3 wazuh_upgrade_cluster.py --config config.yml --verbose

# Upgrade only the local node (all components)
sudo python3 wazuh_upgrade_cluster.py --config config.yml --local

# Upgrade only remote nodes (all components)
sudo python3 wazuh_upgrade_cluster.py --config config.yml --remote-only

# Re-run just manager and filebeat on the remote node after a partial failure
sudo python3 wazuh_upgrade_cluster.py --config config.yml --remote-only --wazuh-manager --filebeat

# Upgrade only the dashboard across all nodes
sudo python3 wazuh_upgrade_cluster.py --config config.yml --wazuh-dashboard

# Upgrade indexer only (runs Phases 1-3, skips Phase 4)
sudo python3 wazuh_upgrade_cluster.py --config config.yml --wazuh-indexer
```

---

## Usage — Single-node script

Run **on the target node** as root or with sudo:

```bash
sudo python3 wazuh_upgrade_single.py --config config.yml [options]
```

### Options

```
--config PATH            Path to config.yml (default: config.yml)
--log-file PATH          Log file path (default: wazuh_upgrade_single.log)
--source-version VER     Current installed version, e.g. 4.8.2 (overrides config)
--target-version VER     Target version for Filebeat template URL (default: 4.14.5)
--skip-config-patches    Skip ossec.conf version-gated changes
```

### Example

```bash
sudo python3 wazuh_upgrade_single.py --config config.yml --target-version 4.14.5
```

---

## Upgrade phases (cluster script)

The cluster script follows the official Wazuh rolling upgrade sequence:

| Phase | What runs | Where |
|---|---|---|
| **1 — Prepare cluster** | Disable shard allocation; flush transaction logs | Local node |
| **2 — Upgrade indexer** | Stop services → remove broken packages → install wazuh-indexer → start indexer | Remote nodes first, then local |
| **3 — Security init** | Re-enable shard allocation; wait for cluster health; run `indexer-security-init.sh` | Local node |
| **4 — Upgrade the rest** | Install wazuh-manager, filebeat, wazuh-dashboard; restore config backups; start services | Remote nodes first, then local |

**Why remote nodes are upgraded first**: this ensures the local node (which also runs the control logic and the cluster API calls in Phases 1 and 3) is always the last to go offline during the rolling upgrade, keeping the cluster API accessible throughout.

**Why Phase 3 is non-fatal**: if the health check or security-init fails (e.g. due to a pending kernel upgrade), Phase 4 still runs so all packages reach the new version. The script prints exact commands to complete Phase 3 manually.

---

## Logs

Both scripts write timestamped logs to the `logs/` directory created alongside the script:

| File | Contents |
|---|---|
| `logs/upgrade.log` | Full upgrade log (all levels) |
| `logs/upgrade.json` | Structured JSON event log for each node |

---

## Exit codes (cluster script)

| Code | Meaning |
|---|---|
| `0` | All phases completed successfully |
| `1` | Fatal error — upgrade stopped (check logs) |
| `2` | Package upgrades complete but Phase 3 (security-init) still needs to be repeated manually |

---

## Troubleshooting

### Cluster health is RED after upgrade

```bash
# Check cluster health
curl -k -u admin:'yourpassword' https://localhost:9200/_cluster/health | python3 -m json.tool

# Find unassigned shards
curl -k -u admin:'yourpassword' https://localhost:9200/_cluster/allocation/explain | python3 -m json.tool
```

If a shard shows `no_valid_shard_copy` (data permanently lost on all nodes), delete the index — Wazuh rebuilds statistics indices automatically:

```bash
curl -k -u admin:'yourpassword' -X DELETE https://localhost:9200/wazuh-statistics-YYYY.WWw
```

### Security init fails with "cluster state timeout"

After a major version upgrade (e.g. 4.8 → 4.14), run with the `--accept-red-cluster` flag to skip the YELLOW-wait:

```bash
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options '--accept-red-cluster'
```

### `Curl error (23)` on yum download (disk space)

The wazuh-indexer RPM is ~835 MB. If the remote node's `/var` partition is full:

```bash
# Clean caches
ssh user@remote 'sudo dnf clean all && sudo yum clean all'

# Vacuum old journal logs
ssh user@remote 'sudo journalctl --vacuum-size=100M'

# Check remaining space (need at least 2 GB free)
ssh user@remote 'df -h /var'
```

Then re-run the script.

### Pending kernel upgrade destabilises the cluster

If `needrestart` reports a pending kernel on any node, reboot that node after the upgrade completes and then re-run Phase 3:

```bash
ssh user@node 'sudo reboot'
# wait for reboot, then:
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

### Re-running after a partial failure

Use the component and node-scope flags to target only what failed:

```bash
# Phase 4 failed on the remote node — re-run Phase 4 on remote only
sudo python3 wazuh_upgrade_cluster.py --config config.yml --remote-only --wazuh-manager --filebeat

# Phase 3 failed — re-run the full indexer phase sequence
sudo python3 wazuh_upgrade_cluster.py --config config.yml --wazuh-indexer
```

---

## Security note

`config.yml` contains the Wazuh indexer password in plain text. Restrict permissions after editing:

```bash
chmod 600 config.yml
```
