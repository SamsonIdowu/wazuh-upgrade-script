#!/usr/bin/env python3
"""
Shared helpers for Wazuh upgrade automation.

This module is used by:
  - wazuh_upgrade_single.py
  - wazuh_upgrade_cluster.py

It automates the documented Wazuh central-component upgrade flow for
single-node and multi-node deployments.

Requirements:
  pip install pyyaml

Run as root or with passwordless sudo on every node.
"""

from __future__ import annotations

import dataclasses
import getpass
import json
import logging
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("wazuh_upgrade")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.INFO)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


# -----------------------------
# Data models
# -----------------------------

@dataclass
class SSHSettings:
    user: str = "root"
    port: int = 22
    key: Optional[str] = None
    sudo: bool = True


@dataclass
class Node:
    name: str
    host: str
    roles: List[str] = field(default_factory=list)
    local: bool = False
    master: bool = False
    cluster_manager: bool = False
    ssh_user: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_key: Optional[str] = None
    sudo: Optional[bool] = None

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def display(self) -> str:
        return f"{self.name} ({self.host})"

    def endpoint(self, ssh: SSHSettings) -> str:
        user = self.ssh_user or ssh.user
        return f"{user}@{self.host}"

    def port(self, ssh: SSHSettings) -> int:
        return self.ssh_port or ssh.port

    def key(self, ssh: SSHSettings) -> Optional[str]:
        return self.ssh_key or ssh.key

    def use_sudo(self, ssh: SSHSettings) -> bool:
        if self.sudo is None:
            return ssh.sudo
        return self.sudo


# -----------------------------
# YAML / config helpers
# -----------------------------

def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def expand_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.expanduser(path)


def get_ssh_settings(cfg: Dict[str, Any]) -> SSHSettings:
    ssh_cfg = cfg.get("ssh", {}) or {}
    return SSHSettings(
        user=ssh_cfg.get("user", "root"),
        port=int(ssh_cfg.get("port", 22)),
        key=expand_path(ssh_cfg.get("key")),
        sudo=bool(ssh_cfg.get("sudo", True)),
    )


def parse_nodes(section: Dict[str, Any], ssh: SSHSettings) -> List[Node]:
    nodes: List[Node] = []
    for item in (section.get("nodes", []) or []):
        nodes.append(
            Node(
                name=item["name"],
                host=item.get("host") or item.get("ip") or item["name"],
                roles=list(item.get("roles", []) or []),
                local=bool(item.get("local", False)),
                master=bool(item.get("master", False)),
                cluster_manager=bool(item.get("cluster_manager", False)),
                ssh_user=item.get("ssh_user"),
                ssh_port=item.get("ssh_port"),
                ssh_key=expand_path(item.get("ssh_key")),
                sudo=item.get("sudo"),
            )
        )
    return nodes


# -----------------------------
# Local host detection
# -----------------------------

def local_identifiers() -> set[str]:
    ids = {"localhost", "127.0.0.1", "::1"}
    try:
        ids.add(socket.gethostname())
    except Exception:
        pass
    try:
        ids.add(socket.getfqdn())
    except Exception:
        pass

    # Add all IPs assigned to the local host.
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ids.add(info[4][0])
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.getfqdn(), None):
            ids.add(info[4][0])
    except Exception:
        pass
    return {i for i in ids if i}


def is_local_node(node: Node) -> bool:
    if node.local:
        return True
    ids = local_identifiers()
    return node.host in ids or node.name in ids


# -----------------------------
# Command execution
# -----------------------------

def _cmd_str(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def run_command(
    cmd: Sequence[str],
    logger: logging.Logger,
    *,
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """
    Run a command in a new process group so that a timeout kills all children.

    Without os.setsid(), Python kills only the top-level process on timeout,
    leaving postinst scripts and service-start children running as orphans.
    Those orphans hold dpkg locks and cause subsequent dpkg --configure -a to
    hang indefinitely.
    """
    logger.info("RUN: %s", _cmd_str(cmd))
    process = subprocess.Popen(
        list(cmd),
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        text=text,
        preexec_fn=os.setsid,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ss: %s", timeout, _cmd_str(cmd))
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except Exception:
                pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        # Build a CompletedProcess-like result with returncode=1
        proc = subprocess.CompletedProcess(cmd, 1, stdout or "", stderr or "")
        if check:
            raise RuntimeError(f"Command timed out after {timeout}s: {_cmd_str(cmd)}")
        return proc

    proc = subprocess.CompletedProcess(
        cmd, process.returncode, stdout or "", stderr or ""
    )
    if proc.stdout:
        logger.info("STDOUT: %s", proc.stdout.strip())
    if proc.stderr:
        logger.info("STDERR: %s", proc.stderr.strip())
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {_cmd_str(cmd)}")
    return proc


def remote_prefix(node: Node, ssh: SSHSettings) -> List[str]:
    base = ["ssh", "-p", str(node.port(ssh))]
    if node.key(ssh):
        base += ["-i", node.key(ssh)]
    # Avoid interactive hangs on automation.
    base += ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new"]
    return base


def remote_run(node: Node, ssh: SSHSettings, remote_cmd: str, logger: logging.Logger, *, check: bool = True) -> subprocess.CompletedProcess:
    cmd = remote_prefix(node, ssh) + [node.endpoint(ssh), "bash", "-lc", remote_cmd]
    if node.use_sudo(ssh):
        cmd = remote_prefix(node, ssh) + [node.endpoint(ssh), "sudo", "-n", "bash", "-lc", remote_cmd]
    return run_command(cmd, logger, check=check)


def local_run(cmd: str, logger: logging.Logger, *, use_sudo: bool = True, check: bool = True) -> subprocess.CompletedProcess:
    if use_sudo:
        full = ["sudo", "-n", "bash", "-lc", cmd]
    else:
        full = ["bash", "-lc", cmd]
    return run_command(full, logger, check=check)


def node_run(node: Node, ssh: SSHSettings, cmd: str, logger: logging.Logger, *, check: bool = True) -> subprocess.CompletedProcess:
    if is_local_node(node):
        return local_run(cmd, logger, use_sudo=node.use_sudo(ssh), check=check)
    return remote_run(node, ssh, cmd, logger, check=check)


def node_output(node: Node, ssh: SSHSettings, cmd: str, logger: logging.Logger) -> str:
    proc = node_run(node, ssh, cmd, logger, check=True)
    return (proc.stdout or "").strip()


# -----------------------------
# Package manager and OS helpers
# -----------------------------

def detect_pkg_mgr(node: Node, ssh: SSHSettings, logger: logging.Logger) -> Tuple[str, str]:
    """
    Returns (family, binary):
      family: "apt" or "yum"
      binary: apt-get / yum / dnf
    """
    probe = r"""
if command -v apt-get >/dev/null 2>&1; then
  echo apt:apt-get
elif command -v yum >/dev/null 2>&1; then
  echo yum:yum
elif command -v dnf >/dev/null 2>&1; then
  echo yum:dnf
else
  echo unknown:unknown
fi
"""
    out = node_output(node, ssh, probe, logger)
    family, binary = out.split(":", 1)
    if family == "unknown":
        raise RuntimeError(f"Could not detect package manager on {node.display()}")
    return family, binary


def get_os_major_version(node: Node, ssh: SSHSettings, logger: logging.Logger) -> Optional[int]:
    probe = r"""
if [ -r /etc/os-release ]; then
  . /etc/os-release
  echo "${VERSION_ID%%.*}"
else
  echo ""
fi
"""
    out = node_output(node, ssh, probe, logger)
    try:
        return int(out)
    except Exception:
        return None


def package_installed(node: Node, ssh: SSHSettings, pkg: str, logger: logging.Logger) -> bool:
    # Works for both Debian and RPM families.
    cmd = f"""
if command -v dpkg >/dev/null 2>&1; then
  dpkg -s {shlex.quote(pkg)} >/dev/null 2>&1
else
  rpm -q {shlex.quote(pkg)} >/dev/null 2>&1
fi
"""
    proc = node_run(node, ssh, cmd, logger, check=False)
    return proc.returncode == 0


# -----------------------------
# Repository management
# -----------------------------

def ensure_wazuh_repo(node: Node, ssh: SSHSettings, logger: logging.Logger) -> Tuple[str, str]:
    family, binary = detect_pkg_mgr(node, ssh, logger)
    if family == "apt":
        cmd = r"""
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y gnupg apt-transport-https ca-certificates >/dev/null
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --batch --yes --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import >/dev/null
chmod 644 /usr/share/keyrings/wazuh.gpg
cat >/etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF
apt-get update
"""
        node_run(node, ssh, cmd, logger, check=True)
    else:
        major = get_os_major_version(node, ssh, logger)
        repo_extra = "priority=1"
        if major is not None and major <= 8:
            repo_extra = "protect=1"
        cmd = rf"""
set -e
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat >/etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
{repo_extra}
EOF
"""
        node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Wazuh repository is configured", node.display())
    return family, binary


def disable_wazuh_repo(node: Node, ssh: SSHSettings, family: str, logger: logging.Logger) -> None:
    if family == "apt":
        cmd = r"""
if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
  sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
  apt-get update
fi
"""
    else:
        cmd = r"""
if [ -f /etc/yum.repos.d/wazuh.repo ]; then
  sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/wazuh.repo
fi
"""
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Wazuh repository disabled", node.display())


# -----------------------------
# Service management
# -----------------------------

def service_cmd(name: str, action: str) -> str:
    return f"""
if command -v systemctl >/dev/null 2>&1; then
  systemctl {action} {name}
else
  service {name} {action}
fi
"""


def stop_service(node: Node, ssh: SSHSettings, service: str, logger: logging.Logger) -> None:
    node_run(node, ssh, service_cmd(service, "stop"), logger, check=True)
    logger.info("[%s] Stopped %s", node.display(), service)


def start_service(node: Node, ssh: SSHSettings, service: str, logger: logging.Logger) -> None:
    cmd = f"""
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable {service}
  systemctl start {service}
else
  case "{service}" in
    wazuh-indexer) chkconfig --add wazuh-indexer || true; service wazuh-indexer start ;;
    wazuh-manager) chkconfig --add wazuh-manager || true; service wazuh-manager start ;;
    wazuh-dashboard) chkconfig --add wazuh-dashboard || true; service wazuh-dashboard start ;;
    filebeat) chkconfig --add filebeat || true; service filebeat start ;;
    *) service {service} start ;;
  esac
fi
"""
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Started %s", node.display(), service)


def restart_service(node: Node, ssh: SSHSettings, service: str, logger: logging.Logger) -> None:
    cmd = service_cmd(service, "restart")
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Restarted %s", node.display(), service)


# -----------------------------
# Backup helpers
# -----------------------------

def backup_file(node: Node, ssh: SSHSettings, path: str, backup_dir: str, logger: logging.Logger) -> Optional[str]:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_name = path.strip("/").replace("/", "_")
    target = f"{backup_dir}/{safe_name}.{stamp}.bak"
    cmd = f"""
set -e
mkdir -p {shlex.quote(backup_dir)}
if [ -f {shlex.quote(path)} ]; then
  cp -a {shlex.quote(path)} {shlex.quote(target)}
  echo {shlex.quote(target)}
fi
"""
    out = node_output(node, ssh, cmd, logger)
    return out or None


# -----------------------------
# Version helpers
# -----------------------------

def parse_version(v: Optional[str]) -> Tuple[int, int, int]:
    if not v:
        return (0, 0, 0)
    parts = re.findall(r"\d+", v)
    nums = [int(x) for x in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])  # type: ignore[return-value]


def version_lte(a: Optional[str], b: str) -> bool:
    return parse_version(a) <= parse_version(b)


# -----------------------------
# XML config patching
# -----------------------------

def pretty_xml(element) -> str:
    from xml.dom import minidom
    import xml.etree.ElementTree as ET

    rough = ET.tostring(element, encoding="utf-8")
    parsed = minidom.parseString(rough)
    return parsed.toprettyxml(indent="  ")


def patch_ossec_conf(
    node: Node,
    ssh: SSHSettings,
    logger: logging.Logger,
    *,
    source_version: Optional[str],
    indexer_hosts: List[str],
    apply_cdb_lists: bool = True,
    apply_vuln_detection: bool = True,
) -> None:
    """
    Idempotently updates /var/ossec/etc/ossec.conf for version-gated changes.
    """
    import xml.etree.ElementTree as ET

    conf = "/var/ossec/etc/ossec.conf"
    backup_dir = "/var/backups/wazuh-upgrade"
    backup_file(node, ssh, conf, backup_dir, logger)

    tmp = f"/tmp/ossec.conf.wazuh-upgrade.{int(time.time())}"
    if is_local_node(node):
        read_cmd = f"cat {shlex.quote(conf)}"
        current = node_output(node, ssh, read_cmd, logger)
    else:
        current = node_output(node, ssh, f"cat {shlex.quote(conf)}", logger)

    root = ET.fromstring(current)

    changed = False

    if apply_cdb_lists and source_version is not None and version_lte(source_version, "4.12.999"):
        ruleset = root.find("ruleset")
        if ruleset is None:
            ruleset = ET.SubElement(root, "ruleset")
            changed = True

        required_lists = [
            "etc/lists/malicious-ioc/malware-hashes",
            "etc/lists/malicious-ioc/malicious-ip",
            "etc/lists/malicious-ioc/malicious-domains",
        ]
        existing = {el.text.strip() for el in ruleset.findall("list") if el.text}
        for item in required_lists:
            if item not in existing:
                ET.SubElement(ruleset, "list").text = item
                changed = True

    if apply_vuln_detection and source_version is not None and version_lte(source_version, "4.7.999"):
        # Remove old block if present.
        for old in list(root.findall("vulnerability-detector")):
            root.remove(old)
            changed = True

        # Create/replace new block.
        vd = root.find("vulnerability-detection")
        if vd is None:
            vd = ET.SubElement(root, "vulnerability-detection")
            changed = True
        def set_child(parent, tag, text):
            nonlocal changed
            el = parent.find(tag)
            if el is None:
                el = ET.SubElement(parent, tag)
                changed = True
            if (el.text or "").strip() != text:
                el.text = text
                changed = True

        set_child(vd, "enabled", "yes")
        set_child(vd, "index-status", "yes")
        set_child(vd, "feed-update-interval", "60m")

        indexer = root.find("indexer")
        if indexer is None:
            indexer = ET.SubElement(root, "indexer")
            changed = True
        set_child(indexer, "enabled", "yes")
        hosts = indexer.find("hosts")
        if hosts is None:
            hosts = ET.SubElement(indexer, "hosts")
            changed = True
        current_hosts = [h.text.strip() for h in hosts.findall("host") if h.text]
        if indexer_hosts and current_hosts != indexer_hosts:
            # Replace the hosts list completely for deterministic output.
            for child in list(hosts):
                hosts.remove(child)
            for host in indexer_hosts:
                ET.SubElement(hosts, "host").text = f"https://{host}:9200"
            changed = True

        ssl = indexer.find("ssl")
        if ssl is None:
            ssl = ET.SubElement(indexer, "ssl")
            changed = True
        ca = ssl.find("certificate_authorities")
        if ca is None:
            ca = ET.SubElement(ssl, "certificate_authorities")
            changed = True
        ca_file = ca.find("ca")
        if ca_file is None:
            ca_file = ET.SubElement(ca, "ca")
            changed = True
        if (ca_file.text or "").strip() != "/etc/filebeat/certs/root-ca.pem":
            ca_file.text = "/etc/filebeat/certs/root-ca.pem"
            changed = True

        cert = ssl.find("certificate")
        if cert is None:
            cert = ET.SubElement(ssl, "certificate")
            changed = True
        if (cert.text or "").strip() != "/etc/filebeat/certs/filebeat.pem":
            cert.text = "/etc/filebeat/certs/filebeat.pem"
            changed = True

        key = ssl.find("key")
        if key is None:
            key = ET.SubElement(ssl, "key")
            changed = True
        if (key.text or "").strip() != "/etc/filebeat/certs/filebeat-key.pem":
            key.text = "/etc/filebeat/certs/filebeat-key.pem"
            changed = True

    if changed:
        updated = pretty_xml(root)
        write_cmd = f"cat > {shlex.quote(tmp)} <<'EOF'\n{updated}\nEOF\ncp {shlex.quote(tmp)} {shlex.quote(conf)}\nrm -f {shlex.quote(tmp)}\n"
        node_run(node, ssh, write_cmd, logger, check=True)
        logger.info("[%s] Updated %s", node.display(), conf)
    else:
        logger.info("[%s] %s already had the required blocks", node.display(), conf)


# -----------------------------
# Wazuh-specific steps
# -----------------------------

def wait_for_indexer_health(node: Node, ssh: SSHSettings, username: str, password: str, logger: logging.Logger, timeout: int = 600) -> None:
    logger.info("[%s] Waiting for indexer cluster health (timeout=%ds)...", node.display(), timeout)
    logger.warning("IMPORTANT: If a kernel upgrade is pending, it WILL NOT be applied automatically.")
    logger.warning("You must reboot manually AFTER upgrade. Pending kernels prevent cluster stabilization.")
    
    start = time.time()
    last_status = "unknown"
    retry_count = 0
    
    while time.time() - start < timeout:
        elapsed = int(time.time() - start)
        cmd = (
            f"curl -sk -u {shlex.quote(username)}:{shlex.quote(password)} "
            f"https://{node.host}:9200/_cluster/health"
        )
        try:
            out = node_output(node, ssh, cmd, logger)
            if out:
                data = json.loads(out)
                last_status = data.get("status", "unknown")
                if last_status in ("yellow", "green"):
                    logger.info("[%s] Indexer health is %s after %ds", node.display(), last_status, elapsed)
                    return
                else:
                    logger.debug("[%s] Cluster status is %s, waiting...", node.display(), last_status)
        except Exception as exc:
            last_status = f"error: {exc}"
            logger.debug("[%s] Health check error: %s", node.display(), exc)
        
        retry_count += 1
        remaining = timeout - elapsed
        if remaining > 10:
            logger.info("[%s] Retry %d: not ready, waiting 10s (%ds remaining)...", node.display(), retry_count, remaining)
            time.sleep(10)
        else:
            break
    
    msg = f"Indexer health did not become yellow/green on {node.display()} (last={last_status}, waited={int(time.time() - start)}s). Pending kernel may be affecting stability - reboot and retry."
    raise RuntimeError(msg)


def ensure_green_cluster_health(
    node: Node,
    ssh: SSHSettings,
    username: str,
    password: str,
    logger: logging.Logger,
    *,
    is_single_node: bool = False,
    timeout: int = 600,
) -> bool:
    """
    Drive the indexer cluster to GREEN after an upgrade or security-init.

    Steps executed in order:
      1. Re-enable shard allocation (Phase 1 sets it to 'primaries'; must be
         restored to 'all' before replicas can be assigned).
      2. POST /_cluster/reroute?retry_failed=true  — unsticks shards whose
         allocation attempts failed during the rolling upgrade.  This is the
         most common cause of post-upgrade yellow/red status.
      3. Single-node only: set number_of_replicas=0 on all indices.  A single
         node can never host its own replica shards; they remain unassigned and
         keep the cluster permanently yellow unless replicas are set to zero.
      4. Poll for GREEN.  Repeats the reroute kick every 4 polls.
      5. On timeout: query /_cluster/allocation/explain to log the root cause.
         Auto-removes wazuh-statistics-* / wazuh-monitoring-* indices that have
         no_valid_shard_copy (data permanently lost on all nodes; Wazuh
         recreates these automatically).

    Returns True if GREEN is reached, False on timeout (non-fatal: the upgrade
    packages are already installed).
    """
    creds = shlex.quote(f"{username}:{password}")
    base = f"https://{node.host}:9200"

    def _curl(method: str, path: str, body: str = "") -> str:
        b = f" -H 'Content-Type: application/json' -d '{body}'" if body else ""
        cmd = f"curl -sk -X {method} -u {creds}{b} '{base}{path}'"
        proc = node_run(node, ssh, cmd, logger, check=False)
        return (proc.stdout or "").strip()

    # Step 1: restore full shard allocation
    logger.info("[%s] Re-enabling shard allocation to 'all'", node.display())
    _curl(
        "PUT", "/_cluster/settings",
        '{"persistent":{"cluster.routing.allocation.enable":"all"}}',
    )

    # Step 2: kick shards stuck in a failed-retry state from rolling upgrade
    logger.info("[%s] Triggering cluster reroute (retry_failed=true)", node.display())
    _curl("POST", "/_cluster/reroute?retry_failed=true")

    # Step 3: single-node — replicas can never be assigned, set them to 0
    if is_single_node:
        logger.info(
            "[%s] Single-node: setting number_of_replicas=0 on all indices",
            node.display(),
        )
        _curl("PUT", "/_all/_settings", '{"index":{"number_of_replicas":"0"}}')

    # Step 4: poll for GREEN
    deadline = time.time() + timeout
    interval = 10
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        out = _curl("GET", "/_cluster/health")
        try:
            data = json.loads(out)
            status = data.get("status", "unknown")
            unassigned = data.get("unassigned_shards", 0)
            initializing = data.get("initializing_shards", 0)
            if status == "green":
                logger.info("[%s] Cluster health: GREEN ✓", node.display())
                return True
            remaining = max(int(deadline - time.time()), 0)
            logger.info(
                "[%s] Health check #%d: %s (unassigned=%d initializing=%d) — %ds remaining",
                node.display(), attempt, status, unassigned, initializing, remaining,
            )
            if attempt % 4 == 0:
                _curl("POST", "/_cluster/reroute?retry_failed=true")
        except Exception as exc:
            logger.debug("[%s] Health parse error: %s", node.display(), exc)
        time.sleep(interval)

    # Step 5: timed out — diagnose and auto-clean safe-to-delete lost indices
    logger.warning("[%s] Cluster did not reach GREEN within %ds", node.display(), timeout)
    explain_out = _curl("GET", "/_cluster/allocation/explain")
    if explain_out:
        try:
            explain = json.loads(explain_out)
            idx = explain.get("index", "")
            reason = explain.get("allocate_explanation") or str(
                explain.get("unassigned_info", {}).get("reason", "")
            )
            logger.warning(
                "[%s] Stuck shard — index=%s reason=%s", node.display(), idx, reason
            )
            _SAFE_PREFIXES = ("wazuh-statistics-", "wazuh-monitoring-")
            if "no_valid_shard_copy" in explain_out and idx:
                if any(idx.startswith(p) for p in _SAFE_PREFIXES):
                    logger.warning(
                        "[%s] Auto-removing '%s' (all shard copies lost; "
                        "Wazuh recreates statistics/monitoring indices automatically)",
                        node.display(), idx,
                    )
                    _curl("DELETE", f"/{idx}")
                    time.sleep(3)
                    _curl("POST", "/_cluster/reroute?retry_failed=true")
                    time.sleep(5)
                    final_out = _curl("GET", "/_cluster/health")
                    if json.loads(final_out).get("status") == "green":
                        logger.info(
                            "[%s] Cluster health: GREEN ✓ (after removing lost index)",
                            node.display(),
                        )
                        return True
                else:
                    logger.warning(
                        "[%s] '%s' has permanently lost all shard copies. "
                        "Delete it manually if it is safe to do so:\n"
                        "  curl -k -u '%s:<PASSWORD>' -X DELETE '%s/%s'",
                        node.display(), idx, username, base, idx,
                    )
        except Exception:
            logger.warning(
                "[%s] Allocation explain raw:\n%s", node.display(), explain_out[:2000]
            )
    return False


def indexer_cluster_prepare(node: Node, ssh: SSHSettings, username: str, password: str, logger: logging.Logger) -> None:
    disable_allocation = f"""
curl -sk -X PUT "https://{node.host}:9200/_cluster/settings" -u {shlex.quote(username)}:{shlex.quote(password)} -H 'Content-Type: application/json' -d '
{{
  "persistent": {{
    "cluster.routing.allocation.enable": "primaries"
  }}
}}'
"""
    flush = f'curl -sk -X POST "https://{node.host}:9200/_flush" -u {shlex.quote(username)}:{shlex.quote(password)}'
    node_run(node, ssh, disable_allocation, logger, check=True)
    node_run(node, ssh, flush, logger, check=True)
    logger.info("[%s] Disabled shard allocation and flushed the cluster", node.display())


def indexer_cluster_reenable(node: Node, ssh: SSHSettings, username: str, password: str, logger: logging.Logger) -> None:
    enable_allocation = f"""
curl -sk -X PUT "https://{node.host}:9200/_cluster/settings" -u {shlex.quote(username)}:{shlex.quote(password)} -H 'Content-Type: application/json' -d '
{{
  "persistent": {{
    "cluster.routing.allocation.enable": "all"
  }}
}}'
"""
    node_run(node, ssh, enable_allocation, logger, check=True)
    logger.info("[%s] Re-enabled shard allocation", node.display())


def backup_indexer_security(node: Node, ssh: SSHSettings, logger: logging.Logger) -> None:
    """
    Backs up the indexer security configuration before any cluster operations.
    Must be called before indexer_cluster_prepare on the first indexer node.
    """
    cmd = (
        '/usr/share/wazuh-indexer/bin/indexer-security-init.sh '
        '--options "-backup /etc/wazuh-indexer/opensearch-security -icl -nhnv"'
    )
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Backed up indexer security configuration", node.display())


def verify_indexer_nodes(node: Node, ssh: SSHSettings, username: str, password: str, logger: logging.Logger) -> None:
    """
    Logs the current cluster node list. Call after re-enabling shard allocation
    to confirm all nodes have rejoined and the upgraded node is visible.
    """
    cmd = f"curl -sk -u {shlex.quote(username)}:{shlex.quote(password)} 'https://{node.host}:9200/_cat/nodes?v'"
    out = node_output(node, ssh, cmd, logger)
    logger.info("[%s] Indexer cluster nodes:\n%s", node.display(), out)


def setup_manager_keystore(node: Node, ssh: SSHSettings, username: str, password: str, logger: logging.Logger) -> None:
    """
    Stores indexer credentials in the Wazuh manager keystore.
    Required after patching ossec.conf so the manager can authenticate
    to the indexer for vulnerability detection and index queries.
    """
    cmd = (
        f"echo {shlex.quote(username)} | /var/ossec/bin/wazuh-keystore -f indexer -k username && "
        f"echo {shlex.quote(password)} | /var/ossec/bin/wazuh-keystore -f indexer -k password"
    )
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Manager keystore credentials updated", node.display())


def _apt_install_with_policy_rc(node: Node, ssh: SSHSettings, pkg: str, logger: logging.Logger) -> None:
    """
    Install/upgrade an apt package with policy-rc.d blocking service starts.

    Wazuh package postinst scripts call 'invoke-rc.d <service> start' during
    install.  Without policy-rc.d this blocks waiting for the service to reach
    active state — up to 20+ minutes on slow or indexer-bound systems.
    policy-rc.d returning 101 tells invoke-rc.d to skip the start.  The caller
    is responsible for starting the service explicitly after install.
    """
    cmd = (
        f"( printf '#!/bin/sh\\nexit 101\\n' | sudo tee /usr/sbin/policy-rc.d > /dev/null "
        f"&& sudo chmod +x /usr/sbin/policy-rc.d; "
        f"sudo DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true "
        f"NEEDRESTART_SUSPEND=1 UCF_FORCE_CONFFNEW=1 "
        f"apt-get install -y -o Dpkg::options::='--force-confnew' {pkg}; "
        f"EXIT=$?; sudo rm -f /usr/sbin/policy-rc.d; exit $EXIT )"
    )
    node_run(node, ssh, cmd, logger, check=True)


def upgrade_indexer(node: Node, ssh: SSHSettings, pkg_bin: str, logger: logging.Logger) -> None:
    stop_service(node, ssh, "wazuh-indexer", logger)
    jvm_backup = backup_file(node, ssh, "/etc/wazuh-indexer/jvm.options", "/var/backups/wazuh-upgrade", logger)
    if pkg_bin in {"yum", "dnf"}:
        node_run(node, ssh, f"{pkg_bin} -y upgrade wazuh-indexer", logger, check=True)
    else:
        _apt_install_with_policy_rc(node, ssh, "wazuh-indexer", logger)
    if jvm_backup:
        node_run(node, ssh, f"cp -a {shlex.quote(jvm_backup)} /etc/wazuh-indexer/jvm.options", logger, check=True)
        logger.info("[%s] Restored custom JVM options from backup", node.display())
    start_service(node, ssh, "wazuh-indexer", logger)
    logger.info("[%s] Indexer upgrade completed", node.display())


def upgrade_manager(node: Node, ssh: SSHSettings, pkg_bin: str, logger: logging.Logger) -> None:
    if pkg_bin in {"yum", "dnf"}:
        node_run(node, ssh, f"{pkg_bin} -y upgrade wazuh-manager", logger, check=True)
    else:
        _apt_install_with_policy_rc(node, ssh, "wazuh-manager", logger)
    start_service(node, ssh, "wazuh-manager", logger)
    logger.info("[%s] Manager upgrade completed", node.display())


def upgrade_filebeat(node: Node, ssh: SSHSettings, pkg_bin: str, target_version: str, logger: logging.Logger) -> None:
    if not re.match(r'^\d+\.\d+\.\d+$', target_version):
        raise ValueError(f"Invalid target_version: {target_version!r}")

    backup_file(node, ssh, "/etc/filebeat/filebeat.yml", "/var/backups/wazuh-upgrade", logger)
    cmd = f"""
set -e
mkdir -p /usr/share/filebeat/module
curl -fsSL https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.5.tar.gz | tar -xvz -C /usr/share/filebeat/module
curl -fsSL -o /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v{target_version}/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
"""
    node_run(node, ssh, cmd, logger, check=True)

    if pkg_bin in {"yum", "dnf"}:
        node_run(node, ssh, f"{pkg_bin} -y upgrade filebeat", logger, check=True)
    else:
        _apt_install_with_policy_rc(node, ssh, "filebeat", logger)

    # Restore the pre-upgrade filebeat.yml; the package upgrade may have replaced it.
    restore_cmd = r"""
latest="$(ls -1t /var/backups/wazuh-upgrade/etc_filebeat_filebeat.yml.*.bak 2>/dev/null | head -n1 || true)"
if [ -n "$latest" ]; then
  cp -a "$latest" /etc/filebeat/filebeat.yml
fi
"""
    node_run(node, ssh, restore_cmd, logger, check=True)

    start_service(node, ssh, "filebeat", logger)
    node_run(node, ssh, "filebeat setup --pipelines", logger, check=True)
    node_run(node, ssh, "filebeat setup --index-management -E output.logstash.enabled=false", logger, check=True)
    logger.info("[%s] Filebeat upgrade completed", node.display())


def upgrade_dashboard(node: Node, ssh: SSHSettings, pkg_bin: str, logger: logging.Logger) -> None:
    backup_file(node, ssh, "/etc/wazuh-dashboard/opensearch_dashboards.yml", "/var/backups/wazuh-upgrade", logger)
    if pkg_bin in {"yum", "dnf"}:
        node_run(node, ssh, f"{pkg_bin} -y upgrade wazuh-dashboard", logger, check=True)
    else:
        _apt_install_with_policy_rc(node, ssh, "wazuh-dashboard", logger)
    start_service(node, ssh, "wazuh-dashboard", logger)
    logger.info("[%s] Dashboard upgrade completed", node.display())


def upgrade_indexer_security(node: Node, ssh: SSHSettings, logger: logging.Logger) -> None:
    # Applies the previously backed-up security configuration to the upgraded indexer.
    cmd = r"""
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
"""
    node_run(node, ssh, cmd, logger, check=True)
    logger.info("[%s] Applied indexer security configuration", node.display())


def verify_versions(node: Node, ssh: SSHSettings, family: str, logger: logging.Logger) -> None:
    if family == "apt":
        cmd = "apt list --installed wazuh-indexer wazuh-manager wazuh-dashboard 2>/dev/null || true"
    else:
        cmd = "yum list installed wazuh-indexer wazuh-manager wazuh-dashboard 2>/dev/null || dnf list installed wazuh-indexer wazuh-manager wazuh-dashboard 2>/dev/null || true"
    node_run(node, ssh, cmd, logger, check=True)
