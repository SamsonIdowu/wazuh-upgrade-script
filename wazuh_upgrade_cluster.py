#!/usr/bin/env python3
"""
Wazuh Multi-Node Cluster Upgrade Script

Upgrade sequence (per official Wazuh documentation):
  Phase 1 — Prepare cluster: disable shard allocation, flush (on local indexer node)
  Phase 2 — Upgrade wazuh-indexer: REMOTE NODES FIRST, then local node.
             Security-init is NOT run here — all nodes must be on the same version first.
  Phase 3 — Health check + indexer-security-init ONCE (on local indexer node) + re-enable shards.
  Phase 4 — Upgrade wazuh-manager / filebeat / wazuh-dashboard: REMOTE NODES FIRST, then local.

See: https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html
"""

import argparse
import json
import logging
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import paramiko
import yaml

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

WAZUH_PKG_TO_COMPONENT = {
    "wazuh-indexer": "indexer",
    "wazuh-manager": "manager",
    "wazuh-dashboard": "dashboard",
    "filebeat": "filebeat",
}

ROLE_TO_COMPONENTS = {
    "indexers": ["indexer"],
    "servers": ["manager", "filebeat"],
    "dashboards": ["dashboard"],
}


# ── Console colour support ────────────────────────────────────────────────────

class _C:
    """ANSI escape codes — applied only when stdout is a real TTY."""
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
    BR_RED = "\033[91m"; BR_GREEN = "\033[92m"; BR_YELLOW = "\033[93m"
    BR_BLUE = "\033[94m"; BR_MAGENTA = "\033[95m"; BR_CYAN = "\033[96m"
    BR_WHITE = "\033[97m"

_TTY = sys.stdout.isatty()

def _cc(code, text):
    """Wrap text in an ANSI code+reset; return plain text when not a TTY."""
    return f"{code}{text}{_C.RESET}" if _TTY else text

_COMPONENT_COLOR = {
    "indexer":   _C.BR_BLUE,
    "manager":   _C.BR_MAGENTA,
    "dashboard": _C.BR_CYAN,
    "filebeat":  _C.BR_YELLOW,
}

_PHASE_COLOR = {
    1: _C.CYAN,
    2: _C.BR_BLUE,
    3: _C.BR_MAGENTA,
    4: _C.BR_YELLOW,
}


def _node_tag(name, is_local, component=None):
    """
    Return a compact log prefix that shows node name, LOCAL/REMOTE scope,
    and optionally the component being worked on.  Coloured on a TTY;
    plain bracket notation when piped or written to a log file.

    TTY example:   [indexer-1 | LOCAL | indexer]
    Plain example: [indexer-2 | REMOTE | manager]
    """
    scope = "LOCAL" if is_local else "REMOTE"
    if _TTY:
        scope_color = _C.BR_GREEN if is_local else _C.BR_CYAN
        parts = [
            _cc(_C.BOLD, name),
            _cc(scope_color + _C.BOLD, scope),
        ]
        if component:
            parts.append(_cc(_COMPONENT_COLOR.get(component, _C.BR_WHITE), component))
    else:
        parts = [name, scope]
        if component:
            parts.append(component)
    return "[" + " | ".join(parts) + "]"


def _phase_banner(logger, phase_num, title):
    """Print a coloured phase separator banner to the logger."""
    color = _PHASE_COLOR.get(phase_num, "")
    border = _cc(color + _C.BOLD, "=" * 80) if _TTY else "=" * 80
    heading = (
        _cc(color + _C.BOLD, f"PHASE {phase_num}: {title}") if _TTY
        else f"PHASE {phase_num}: {title}"
    )
    logger.info(f"\n{border}")
    logger.info(heading)
    logger.info(border)


def _ok(msg):
    """Return a success line with a green tick on TTY, plain tick otherwise."""
    return _cc(_C.BR_GREEN + _C.BOLD, f"✓ {msg}") if _TTY else f"✓ {msg}"


class _ColorFormatter(logging.Formatter):
    """
    Console formatter that colours the levelname token only.
    The message body is left untouched so inline colour codes from
    _node_tag / _ok render correctly inside INFO lines.
    """
    _LEVEL_COLOR = {
        logging.DEBUG:    _C.DIM,
        logging.WARNING:  _C.YELLOW + _C.BOLD,
        logging.ERROR:    _C.BR_RED + _C.BOLD,
        logging.CRITICAL: _C.BR_RED + _C.BOLD,
    }

    def format(self, record):
        if _TTY:
            color = self._LEVEL_COLOR.get(record.levelno, "")
            if color:
                orig = record.levelname
                record.levelname = f"{color}{record.levelname}{_C.RESET}"
                result = super().format(record)
                record.levelname = orig
                return result
        return super().format(record)


def setup_logger(verbose=False):
    logger = logging.getLogger("wazuh-upgrade")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        plain_fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(
            _ColorFormatter("%(asctime)s | %(levelname)s | %(message)s") if _TTY else plain_fmt
        )
        console.setLevel(logging.DEBUG if verbose else logging.INFO)
        logfile = logging.FileHandler(f"{LOG_DIR}/upgrade.log")
        logfile.setFormatter(plain_fmt)
        logfile.setLevel(logging.DEBUG)
        logger.addHandler(console)
        logger.addHandler(logfile)
    return logger


class JsonLogger:
    def __init__(self, path="logs/upgrade.json"):
        self.path = path

    def write(self, event, status, node=None, details=None):
        payload = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": event,
            "status": status,
            "node": node,
            "details": details,
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(payload) + "\n")


json_logger = JsonLogger()


def load_config(path="config.yml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def resolve_ssh_key(ssh_cfg, logger):
    """
    Resolve the SSH keypair to use for remote connections.

    The key name is always taken from ssh.key in config.yml — no fallbacks to
    default locations.  If the key file does not exist it is generated at the
    configured path.  If the file exists but is empty or corrupted it is
    replaced with a fresh keypair.

    Returns (private_key_path, public_key_path).
    Raises RuntimeError if ssh.key is not set in config.yml.
    """
    config_key = ssh_cfg.get("key")
    if not config_key:
        raise RuntimeError(
            "ssh.key is not set in config.yml.  "
            "Add the path to your SSH private key, e.g.:\n"
            "  ssh:\n"
            "    key: ~/.ssh/wazuh_upgrade"
        )

    private = Path(os.path.expanduser(config_key))
    public  = Path(str(private) + ".pub")

    if private.exists():
        # Validate the key is non-empty and parseable before trusting it.
        # An empty file causes paramiko to raise "no lines in OPENSSH private key file".
        result = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(private)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            logger.warning(
                f"SSH key {private} is empty or invalid "
                f"({result.stderr.decode().strip()}); regenerating keypair"
            )
            private.unlink(missing_ok=True)
            if public.exists():
                public.unlink()
        else:
            if not public.exists():
                logger.warning(
                    f"Private key {private} exists but {public.name} is missing; "
                    f"regenerating public key"
                )
                with open(str(public), "w") as pub_f:
                    subprocess.run(
                        ["ssh-keygen", "-y", "-f", str(private)],
                        check=True, stdout=pub_f,
                    )
            logger.info(f"Using SSH key from config: {private}")
            return str(private), str(public)

    # Key does not exist (or was just removed) — generate it at the configured path
    private.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"SSH key {private} not found; generating new ed25519 keypair")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(private), "-C", "wazuh-upgrade"],
        check=True,
    )
    logger.info(f"SSH keypair generated: {private}")
    return str(private), str(public)


def is_local_node(host):
    local_hosts = {"127.0.0.1", "localhost", socket.gethostname(), socket.getfqdn()}
    try:
        local_hosts.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return host in local_hosts


def classify_nodes(nodes, logger):
    """Tag every node with _local=True/False exactly once at startup."""
    local_found = False
    for node in nodes:
        is_local = is_local_node(node["host"]) or node.get("local", False)
        if is_local and not local_found:
            node["_local"] = True
            local_found = True
            logger.info(f"Local node identified: {node.get('name', node['host'])} ({node['host']})")
        else:
            node["_local"] = False
            if is_local:
                logger.warning(
                    f"Multiple local-looking nodes; treating {node['host']} as remote"
                )
    return nodes


def annotate_expected_components(nodes, config):
    """
    Set node['_expected_components'] from config role sections (indexers/servers/dashboards).
    Used as a supplement to dpkg-based detection so that a package force-removed in a
    previous run (dpkg state = deinstall) is still included in the upgrade.
    """
    expected_by_host: dict = {}
    for role, role_comps in ROLE_TO_COMPONENTS.items():
        for n in config["nodes"].get(role, []):
            host = n["host"]
            if host not in expected_by_host:
                expected_by_host[host] = []
            for comp in role_comps:
                if comp not in expected_by_host[host]:
                    expected_by_host[host].append(comp)
    for node in nodes:
        node["_expected_components"] = expected_by_host.get(node["host"], [])


class SSHClientWrapper:
    def __init__(self, host, username, key_path=None, port=22, timeout=30, sudo_password=None):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self.sudo_password = sudo_password
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            username=self.username,
            key_filename=self.key_path,
            port=self.port,
            timeout=self.timeout,
        )

    def run(self, cmd, timeout=600):
        if self.sudo_password and "sudo " in cmd:
            cmd = cmd.replace("sudo ", "sudo -S ", 1)
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            stdin.write(self.sudo_password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        else:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, stdout.read().decode(), stderr.read().decode()

    def close(self):
        if self.client:
            self.client.close()


def run_local(cmd, logger, timeout=600):
    """
    Run a shell command locally, killing the entire process group on timeout.

    Python's subprocess.run kills the top-level shell on TimeoutExpired but
    leaves child processes (postinst scripts, service-start subprocesses)
    running as orphans.  Those orphans hold dpkg state and cause the next
    dpkg --configure -a to hang indefinitely.

    Using Popen + os.setsid() puts the shell and all its children in a new
    process group.  On timeout we send SIGKILL to the whole group so nothing
    escapes.
    """
    logger.debug(f"LOCAL CMD: {cmd}")
    try:
        process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, preexec_fn=os.setsid,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            logger.error(f"LOCAL CMD timed out after {timeout}s: {cmd}")
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
            return 1, stdout or "", f"Command timed out after {timeout}s"
    except Exception as exc:
        logger.error(f"LOCAL CMD error: {exc}")
        return 1, "", str(exc)


def _make_runner(node, ssh_cfg, private_key, logger):
    if node.get("_local", False):
        return (lambda cmd, timeout=600: run_local(cmd, logger, timeout=timeout)), None
    ssh = SSHClientWrapper(
        host=node["host"],
        username=ssh_cfg["username"],
        key_path=private_key,
        port=ssh_cfg.get("port", 22),
        timeout=ssh_cfg.get("timeout", 30),
        sudo_password=ssh_cfg.get("sudo_password"),
    )
    ssh.connect()
    return ssh.run, ssh


def deploy_ssh_key(node, ssh_cfg, public_key_path, logger):
    """Deploy public key to a remote node's authorized_keys. Skips local nodes."""
    if node.get("_local", False):
        return
    host = node["host"]
    logger.info(f"Deploying SSH public key to remote node {host}")
    subprocess.run(
        ["ssh-copy-id", "-i", public_key_path, f'{ssh_cfg["username"]}@{host}'],
        check=True,
    )
    logger.info(f"SSH key deployed to {host}")


def detect_package_manager(run_cmd):
    rc, _, _ = run_cmd("which apt")
    if rc == 0:
        return "apt"
    rc, _, _ = run_cmd("which yum")
    if rc == 0:
        return "yum"
    raise RuntimeError("Unsupported package manager (apt and yum not found)")


def detect_components(run_cmd, pm, expected_components=None):
    """
    Detect installed Wazuh components using the package database (not service status).

    For apt, a component is included when dpkg's desired action is 'install' or 'hold',
    regardless of current state.  This covers fully-installed, half-configured, unpacked,
    and half-installed packages — all states where the admin intends the package installed.

    expected_components (from config roles) is unioned in so that a package which was
    force-removed in a previous run (dpkg desired=deinstall) is still upgraded.
    """
    detected = []
    for pkg, component in WAZUH_PKG_TO_COMPONENT.items():
        if pm == "apt":
            rc, _, _ = run_cmd(
                f"dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null "
                f"| grep -qE '^(install|hold) '"
            )
        else:
            rc, _, _ = run_cmd(f"rpm -q {pkg} >/dev/null 2>&1")
        if rc == 0:
            detected.append(component)

    if expected_components:
        for comp in expected_components:
            if comp not in detected:
                detected.append(comp)

    return detected


def _ensure_yum_disk_space(run_cmd, logger, name, host, min_free_gb=2.0):
    """
    Clean yum/dnf caches and verify adequate free space for downloads.

    The wazuh-indexer RPM alone is ~835 MB; we need at least min_free_gb free in
    the yum cache filesystem.  A full cache partition causes yum to fail mid-download
    with 'Curl error (23): Failed writing received data to disk' — which is
    confusing.  This function surfaces the problem before the download starts.
    """
    def _get_free_gb():
        for path in ["/var/cache/dnf", "/var/cache/yum", "/var"]:
            rc, out, _ = run_cmd(
                f"df -BG {path} --output=avail 2>/dev/null | tail -1"
            )
            if rc == 0:
                try:
                    return int(out.strip().rstrip("G"))
                except (ValueError, AttributeError):
                    continue
        return None

    free_before = _get_free_gb()
    if free_before is not None:
        logger.info(f"[{name}] Disk space before cache clean: {free_before}G available")

    logger.info(f"[{name}] Cleaning yum/dnf caches (wazuh-indexer RPM is ~835 MB)")
    run_cmd("sudo yum clean all")
    run_cmd("sudo dnf clean all 2>/dev/null || true")
    # Remove any partially-downloaded RPMs from a previous failed attempt
    run_cmd(
        "sudo find /var/cache/dnf /var/cache/yum -name '*.rpm' -delete 2>/dev/null || true"
    )

    free_after = _get_free_gb()
    if free_after is not None:
        logger.info(f"[{name}] Disk space after cache clean: {free_after}G available")
    else:
        # Best-effort: log df output so the user can see what's going on
        rc, out, _ = run_cmd("df -h /var 2>/dev/null || df -h /")
        if out:
            logger.info(f"[{name}] Current disk usage:\n{out}")
        return  # Cannot determine free space; proceed and let yum fail naturally

    if free_after < min_free_gb:
        # Show full df so the user can find what to delete
        _, df_out, _ = run_cmd("df -h")
        _, du_out, _ = run_cmd(
            "sudo du -sh /var/log /var/ossec /opt /home /tmp 2>/dev/null | sort -h"
        )
        raise RuntimeError(
            f"[{name}] Insufficient disk space: {free_after}G free, {min_free_gb}G needed.\n"
            f"Filesystem usage:\n{df_out}\n"
            f"Top directories:\n{du_out}\n"
            f"Free up space on {host}, then re-run the upgrade script."
        )


def wait_for_dpkg_lock(run_cmd, logger, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = run_cmd(
            "sudo fuser /var/lib/dpkg/lock /var/lib/apt/lists/lock "
            "/var/cache/apt/archives/lock 2>/dev/null"
        )
        if rc != 0:
            return
        logger.info("Waiting for dpkg/apt lock to be released...")
        time.sleep(5)
    logger.warning("dpkg/apt lock still held after %ds; proceeding anyway", timeout)


def _remove_if_broken(run_cmd, logger, pkg):
    """
    If pkg is in a broken dpkg state (desired=install but not 'install ok installed'),
    back up its config files and force-remove it so subsequent apt-get install calls
    do not trigger its failing postinst as a side-effect.

    Returns True if the package was removed.

    The broken states that cause apt-get to fail mid-install:
      'install ok unpacked'        — unpacked, postinst never ran
      'install ok half-configured' — postinst ran but failed
      'install ok half-installed'  — preinst or unpack failed
      'install reinstreq ...'      — marked for reinstall
    """
    rc, out, _ = run_cmd(f"dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null")
    if rc != 0:
        return False  # dpkg knows nothing about this package

    status = out.strip()
    if status == "install ok installed":
        return False  # clean — nothing to do
    if not (status.startswith("install ") or status.startswith("hold ")):
        return False  # deinstall / purge / unknown — not our concern

    logger.warning(f"Broken dpkg state for {pkg}: {status!r} — removing before upgrade")

    if pkg in {"wazuh-manager", "wazuh-indexer", "wazuh-dashboard"}:
        run_cmd(
            "sudo cp -a /var/ossec/etc /var/ossec/etc.pre-upgrade-backup 2>/dev/null || true"
        )
    if pkg == "filebeat":
        run_cmd(
            "sudo cp -a /etc/filebeat /etc/filebeat.pre-upgrade-backup 2>/dev/null || true"
        )

    rc2, _, err2 = run_cmd(f"sudo dpkg --remove --force-remove-reinstreq {pkg}")
    if rc2 != 0:
        logger.warning(f"dpkg --remove returned exit {rc2} for {pkg}: {err2}")
    else:
        logger.info(f"Removed broken {pkg}; will be reinstalled during upgrade")

    return True


def _prepare_apt(run_cmd, logger, name, components):
    """
    Pre-install housekeeping for apt nodes:
      1. Remove any stale policy-rc.d left by a previous failed run (would silently
         block service starts in all subsequent apt operations on this node).
      2. Proactively remove every Wazuh/filebeat package in a broken dpkg state so
         that apt-get install does not try to configure them as a side-effect and fail.
      3. Wait for any dpkg/apt lock to clear.
      4. Run dpkg --configure -a to finish any other pending configurations.
      5. Run apt-get update.

    Returns an updated components list (broken packages that were removed are added
    back in so they get freshly installed in the upgrade step).
    """
    components = list(components)

    # Remove any policy-rc.d left behind by a previous timed-out install run
    run_cmd("sudo rm -f /usr/sbin/policy-rc.d")

    for pkg in list(WAZUH_PKG_TO_COMPONENT):
        if _remove_if_broken(run_cmd, logger, pkg):
            comp = WAZUH_PKG_TO_COMPONENT[pkg]
            if comp not in components:
                components.append(comp)
                logger.info(
                    f"[{name}] Added '{comp}' to upgrade list (broken package removed, "
                    f"will be reinstalled)"
                )

    wait_for_dpkg_lock(run_cmd, logger)

    rc, out, err = run_cmd(
        "sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 dpkg --configure -a"
    )
    if out:
        logger.info(f"dpkg --configure -a output:\n{out}")
    if rc != 0:
        logger.warning(f"dpkg --configure -a returned exit {rc}: {err}")

    logger.info(f"[{name}] Running apt-get update")
    rc, out, err = run_cmd("sudo apt-get update")
    if out:
        logger.debug(f"apt-get update output:\n{out}")
    if rc != 0:
        logger.warning(f"apt-get update returned exit {rc}: {err}")

    return components


def _install_package(pm, run_cmd, logger, pkg, timeout=1200, tag=""):
    """
    Install or upgrade a single package; retry once after dpkg cleanup on failure.

    timeout: seconds before giving up on the install command (default 20 min).
    tag:     optional _node_tag() prefix for log lines.

    For apt nodes the install is wrapped with a policy-rc.d that returns 101,
    preventing the postinst from starting or restarting services via invoke-rc.d.
    Without this, wazuh-manager's postinst calls 'invoke-rc.d wazuh-manager start'
    which blocks waiting for the service to become active — up to 20+ minutes.
    Services are started explicitly by the caller after all packages are installed.

    NEEDRESTART_SUSPEND=1 prevents needrestart from opening an interactive prompt
    inside the apt subprocess.
    """
    if pm == "apt":
        # Wrap the apt install in a subshell that:
        #   1. Creates /usr/sbin/policy-rc.d (exit 101 = deny all service actions).
        #      invoke-rc.d (called by postinst) checks this file before starting
        #      services, so the postinst completes quickly without blocking on
        #      wazuh-manager startup.
        #   2. Runs apt-get install.
        #   3. Removes policy-rc.d in the same shell, whether apt succeeded or not.
        apt_inner = (
            f"sudo DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true "
            f"NEEDRESTART_SUSPEND=1 UCF_FORCE_CONFFNEW=1 "
            f"apt-get install -y -o Dpkg::options::='--force-confnew' {pkg}"
        )
        cmd = (
            f"( printf '#!/bin/sh\\nexit 101\\n' | sudo tee /usr/sbin/policy-rc.d > /dev/null "
            f"&& sudo chmod +x /usr/sbin/policy-rc.d; "
            f"{apt_inner}; "
            f"EXIT=$?; sudo rm -f /usr/sbin/policy-rc.d; exit $EXIT )"
        )
    else:
        cmd = f"sudo yum install -y {pkg}"

    pfx = f"{tag} " if tag else ""
    logger.info(f"{pfx}Installing {_cc(_C.BOLD, pkg) if _TTY else pkg} (timeout: {timeout}s)")
    logger.debug(f"{pfx}CMD: {apt_inner if pm == 'apt' else cmd}")
    rc, out, err = run_cmd(cmd, timeout=timeout)
    if out:
        logger.info(f"{pfx}OUTPUT:\n{out}")
    if err:
        logger.debug(f"{pfx}STDERR:\n{err}")

    if rc != 0:
        logger.warning(f"{pfx}Install failed (exit {rc}) — cleaning broken state and retrying")
        if pm == "apt":
            # Always remove policy-rc.d first (may have been left by a timed-out install)
            run_cmd("sudo rm -f /usr/sbin/policy-rc.d")

            # Kill orphaned child processes left by the timed-out install.
            # Python's process-group kill (in run_local) eliminates the direct
            # children, but systemd-spawned service processes can survive.
            run_cmd(
                "sudo systemctl kill wazuh-manager wazuh-dashboard "
                "wazuh-indexer filebeat 2>/dev/null || true"
            )
            run_cmd("sudo pkill -9 -x dpkg 2>/dev/null || true")
            run_cmd("sudo pkill -9 -f 'dpkg.*--configure' 2>/dev/null || true")
            time.sleep(2)

            # Release dpkg/apt lock files
            run_cmd(
                "sudo fuser -k /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend "
                "/var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>/dev/null || true"
            )
            run_cmd(
                "sudo rm -f /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend "
                "/var/cache/apt/archives/lock 2>/dev/null || true"
            )

            # Force-remove the broken package BEFORE running dpkg --configure -a.
            # If we don't do this, --configure -a tries to re-run the same postinst
            # that just caused the timeout and will hang again for another 20 min.
            logger.info(f"{pfx}Force-removing broken {pkg} to allow clean reinstall")
            run_cmd(
                f"sudo dpkg --remove --force-remove-reinstreq {pkg} 2>/dev/null || true"
            )

            # Fix any OTHER broken packages (not the one we just removed)
            for dep_pkg in list(WAZUH_PKG_TO_COMPONENT):
                if dep_pkg != pkg:
                    _remove_if_broken(run_cmd, logger, dep_pkg)

            # Now --configure -a has nothing to do for our target package
            rc_cfg, _, _ = run_cmd(
                "sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 "
                "dpkg --configure -a",
                timeout=120,
            )
            if rc_cfg != 0:
                logger.warning(f"{pfx}dpkg --configure -a returned non-zero — continuing")

        logger.info(f"{pfx}Retrying: {pkg}")
        rc, out, err = run_cmd(cmd, timeout=timeout)
        if out:
            logger.info(f"{pfx}OUTPUT:\n{out}")
        if err:
            logger.debug(f"{pfx}STDERR:\n{err}")
        if rc != 0:
            logger.error(f"{pfx}Install still failed (exit {rc})")
            raise RuntimeError(f"Package install failed: {pkg}")

    logger.info(f"{pfx}{_ok(f'{pkg} installed')}")


def check_cluster_health(run_cmd, logger, username="admin", password="admin"):
    # shlex.quote wraps the credential in single quotes so special characters in
    # the password (e.g. *, +, !) are not interpreted by the shell.
    creds = shlex.quote(f"{username}:{password}")
    cmd = f"curl -k -s -u {creds} https://localhost:9200/_cluster/health"
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        logger.warning(f"Cluster health curl failed (exit {rc}): {err.strip() or '(no stderr)'}")
        return False
    try:
        status = json.loads(out).get("status")
        logger.info(f"Cluster health: {status}")
        return status in ["green", "yellow"]
    except Exception as e:
        logger.warning(f"Could not parse cluster health response ({e}): {out!r}")
        return False


def _wait_for_green(runner, logger, indexer_user, indexer_pass, tag, timeout=600):
    """
    Post-security-init helper: reroute stuck shards then poll for GREEN health.

    - retry_failed reroute kicks replica shards whose allocation failed during the
      rolling upgrade (the most common cause of post-upgrade yellow state).
    - Polls until GREEN or timeout, repeating the reroute kick every 4 polls.
    - On timeout: queries /_cluster/allocation/explain and logs root-cause detail.
    - Auto-removes wazuh-statistics-* / wazuh-monitoring-* indices that report
      no_valid_shard_copy (all copies lost; Wazuh recreates these automatically).

    Returns True if GREEN is reached, False on timeout (non-fatal).
    """
    creds = shlex.quote(f"{indexer_user}:{indexer_pass}")

    def _curl(method, path, body=""):
        b = f" -H 'Content-Type: application/json' -d '{body}'" if body else ""
        _, out, _ = runner(
            f"curl -k -s -X {method} -u {creds}{b} https://localhost:9200{path}",
            timeout=30,
        )
        return out.strip()

    logger.info(f"{tag} Triggering cluster reroute (retry_failed=true)")
    _curl("POST", "/_cluster/reroute?retry_failed=true")

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
                logger.info(f"{tag} {_ok('Cluster health is GREEN')}")
                return True
            remaining = max(int(deadline - time.time()), 0)
            attempt_label = _cc(_C.BOLD, str(attempt)) if _TTY else str(attempt)
            status_label = _cc(_C.YELLOW + _C.BOLD, status) if _TTY else status
            logger.info(
                f"{tag} Green wait #{attempt_label}: {status_label} "
                f"(unassigned={unassigned} initializing={initializing}) — {remaining}s remaining"
            )
            if attempt % 4 == 0:
                _curl("POST", "/_cluster/reroute?retry_failed=true")
        except Exception as exc:
            logger.debug(f"{tag} Health parse error: {exc}")
        time.sleep(interval)

    # Timed out — diagnose and auto-clean safe-to-delete lost-shard indices
    logger.warning(f"{tag} Cluster did not reach GREEN within {timeout}s — diagnosing")
    explain_out = _curl("GET", "/_cluster/allocation/explain")
    if explain_out:
        try:
            explain = json.loads(explain_out)
            idx = explain.get("index", "")
            reason = explain.get("allocate_explanation") or str(
                explain.get("unassigned_info", {}).get("reason", "")
            )
            logger.warning(f"{tag} Stuck shard — index={idx!r} reason={reason!r}")
            _SAFE_PREFIXES = ("wazuh-statistics-", "wazuh-monitoring-")
            if "no_valid_shard_copy" in explain_out and idx:
                if any(idx.startswith(p) for p in _SAFE_PREFIXES):
                    logger.warning(
                        f"{tag} Auto-removing '{idx}' (all shard copies lost; "
                        "Wazuh recreates statistics/monitoring indices automatically)"
                    )
                    _curl("DELETE", f"/{idx}")
                    time.sleep(3)
                    _curl("POST", "/_cluster/reroute?retry_failed=true")
                    time.sleep(5)
                    final_out = _curl("GET", "/_cluster/health")
                    if json.loads(final_out).get("status") == "green":
                        logger.info(
                            f"{tag} {_ok('Cluster health is GREEN (after removing lost index)')}"
                        )
                        return True
                    logger.warning(
                        f"{tag} Still not GREEN after removing '{idx}' — "
                        "run allocation/explain again to find remaining stuck shards"
                    )
                else:
                    logger.warning(
                        f"{tag} '{idx}' has permanently lost all shard copies.\n"
                        "Delete it manually if safe to do so:\n"
                        f"  curl -k -u admin:'<PASSWORD>' -X DELETE "
                        f"https://localhost:9200/{idx}"
                    )
        except Exception:
            logger.warning(f"{tag} Allocation explain raw:\n{explain_out[:2000]}")
    return False


# ── Phase functions ────────────────────────────────────────────────────────────

def prepare_cluster_upgrade(indexer_node, ssh_cfg, private_key, config, logger):
    """
    Phase 1: Disable shard allocation and flush on the local indexer node.
    Runs locally so no SSH is needed for the cluster API calls.
    """
    _phase_banner(logger, 1, "PREPARE CLUSTER")

    name = indexer_node.get("name", indexer_node["host"])
    is_local = indexer_node.get("_local", False)
    tag = _node_tag(name, is_local, "indexer")
    runner, ssh = _make_runner(indexer_node, ssh_cfg, private_key, logger)

    try:
        indexer_user = config.get("wazuh", {}).get("indexer", {}).get("username", "admin")
        indexer_pass = config.get("wazuh", {}).get("indexer", {}).get("password", "admin")

        creds = shlex.quote(f"{indexer_user}:{indexer_pass}")

        logger.info(f"{tag} Disabling shard allocation")
        rc, out, _ = runner(
            f"curl -k -s -u {creds} -X PUT "
            "https://localhost:9200/_cluster/settings "
            "-H 'Content-Type: application/json' "
            "-d '{\"persistent\":{\"cluster.routing.allocation.enable\":\"primaries\"}}'"
        )
        if out:
            logger.debug(f"{tag} Shard allocation response: {out}")
        logger.info(f"{tag} {_ok('Shard allocation DISABLED')}")

        logger.info(f"{tag} Flushing cluster")
        rc, out, _ = runner(
            f"curl -k -s -u {creds} -X POST "
            "https://localhost:9200/_flush"
        )
        if out:
            logger.debug(f"{tag} Flush response: {out}")
        logger.info(f"{tag} {_ok('Cluster FLUSHED')}")

    finally:
        if ssh:
            ssh.close()


def upgrade_indexer_only(node, ssh_cfg, private_key, config, logger):
    """
    Phase 2 (per node, remote nodes first): stop all services, remove any broken
    Wazuh packages, upgrade wazuh-indexer, restart it.

    Security-init is deferred to Phase 3: OpenSearch requires all cluster nodes
    to be on the same version before security can be initialised.

    Manager / filebeat / dashboard are deferred to Phase 4: the wazuh-manager
    postinst script connects to the indexer for migration/keystore init, so the
    indexer must be running and security-initialised before those installs run.

    Stores _pm and _non_indexer_components on the node dict for Phase 4 reuse.
    """
    host = node["host"]
    name = node.get("name", host)
    is_local = node.get("_local", False)
    tag = _node_tag(name, is_local, "indexer")
    logger.info(f"\n{tag} Phase 2 — upgrading wazuh-indexer")

    runner, ssh = _make_runner(node, ssh_cfg, private_key, logger)

    try:
        pm = detect_package_manager(runner)
        expected = node.get("_expected_components", [])
        components = detect_components(runner, pm, expected)
        logger.info(f"{tag} Components detected: {', '.join(components) or '(none)'}")

        logger.info(f"{tag} Stopping all Wazuh services")
        for svc in ["wazuh-dashboard", "wazuh-manager", "filebeat", "wazuh-indexer"]:
            runner(f"sudo systemctl stop {svc} 2>/dev/null || true")

        if pm == "apt":
            components = _prepare_apt(runner, logger, name, components)
        else:
            _ensure_yum_disk_space(runner, logger, name, host)

        if "indexer" in components:
            _install_package(pm, runner, logger, "wazuh-indexer", tag=tag)
            runner("sudo systemctl daemon-reload && sudo systemctl enable wazuh-indexer")
            logger.info(
                f"{tag} Starting wazuh-indexer "
                f"(OpenSearch JVM initialisation may take 2-5 minutes)..."
            )
            rc, out, err = runner("sudo timeout 360 systemctl start wazuh-indexer")
            if rc != 0:
                raise RuntimeError(
                    f"wazuh-indexer failed to start (exit {rc}): {err.strip() or out.strip()}\n"
                    f"Check logs with: sudo journalctl -u wazuh-indexer -n 50 --no-pager"
                )
            logger.info(f"{tag} {_ok('wazuh-indexer upgraded and running')}")
        else:
            logger.info(f"{tag} wazuh-indexer not expected on this node — skipping")

        node["_pm"] = pm
        node["_non_indexer_components"] = [c for c in components if c != "indexer"]

        logger.info(f"{tag} {_ok('Phase 2 complete')}")
        json_logger.write("indexer_upgrade", "success", node=name)

    finally:
        if ssh:
            ssh.close()


def check_health_security_init_reenable(indexer_node, ssh_cfg, private_key, config, logger):
    """
    Phase 3 (once, on local indexer node): wait for cluster health, run
    indexer-security-init.sh once, re-enable shard allocation.

    Runs on the local node — no SSH needed for cluster API calls or the init script.
    All indexers are now the same version, so security-init succeeds.
    """
    _phase_banner(logger, 3, "HEALTH CHECK + SECURITY INIT + RE-ENABLE SHARDS")

    name = indexer_node.get("name", indexer_node["host"])
    is_local = indexer_node.get("_local", False)
    tag = _node_tag(name, is_local, "indexer")
    runner, ssh = _make_runner(indexer_node, ssh_cfg, private_key, logger)

    try:
        indexer_user = config.get("wazuh", {}).get("indexer", {}).get("username", "admin")
        indexer_pass = config.get("wazuh", {}).get("indexer", {}).get("password", "admin")
        creds = shlex.quote(f"{indexer_user}:{indexer_pass}")

        # Re-enable shard allocation FIRST.
        # Phase 1 set it to "primaries" to prevent shard movement during rolling upgrade.
        # All indexers are now on the same version, so it must be re-enabled before the
        # health check — the cluster cannot reach YELLOW with replicas unallocated, and
        # securityadmin times out waiting for YELLOW if allocation is still restricted.
        logger.info(f"{tag} Re-enabling shard allocation (restricted during rolling upgrade)")
        rc, out, _ = runner(
            f"curl -k -s -u {creds} -X PUT "
            "https://localhost:9200/_cluster/settings "
            "-H 'Content-Type: application/json' "
            "-d '{\"persistent\":{\"cluster.routing.allocation.enable\":\"all\"}}'"
        )
        if out:
            logger.debug(f"{tag} Shard allocation response: {out}")
        logger.info(f"{tag} {_ok('Shard allocation RE-ENABLED')}")

        logger.info(f"{tag} Waiting for cluster health (all nodes same version)...")

        max_retries = 12
        wait_time = 10
        healthy = False

        for attempt in range(1, max_retries + 1):
            time.sleep(wait_time)
            attempt_label = _cc(_C.BOLD, f"{attempt}/{max_retries}") if _TTY else f"{attempt}/{max_retries}"
            logger.info(f"{tag} Health check attempt {attempt_label}...")
            healthy = check_cluster_health(runner, logger, indexer_user, indexer_pass)
            if healthy:
                logger.info(f"{tag} {_ok('CLUSTER HEALTH CHECK PASSED')}")
                break
            wait_time = min(10 + (attempt * 5), 30)
            if attempt < max_retries:
                logger.warning(
                    f"{tag} Cluster not ready — retrying in {wait_time}s "
                    f"({max_retries - attempt} attempts left)"
                )

        # Run security init regardless of health check result.
        #
        # After a major version upgrade (e.g. 4.8 → 4.14), the OpenSearch security
        # plugin enters a bootstrap state where the _cluster/health endpoint does not
        # respond until security has been re-initialised — a chicken-and-egg situation.
        # The --accept-red-cluster flag tells securityadmin to skip the YELLOW wait and
        # apply the security configuration immediately.  It is safe to use here because
        # we know the cluster is in a post-upgrade state, not a genuine data-loss state.
        if healthy:
            logger.info(f"{tag} Running indexer-security-init.sh")
            rc, out, err = runner(
                "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"
            )
        else:
            logger.warning(
                f"{tag} Health check did not pass — running indexer-security-init.sh "
                f"with --options '--accept-red-cluster' (safe after major version upgrade)"
            )
            rc, out, err = runner(
                "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh "
                "--options '--accept-red-cluster'"
            )

        if out:
            logger.debug(f"{tag} Security init output:\n{out}")
        if rc != 0:
            raise RuntimeError(f"Security init failed (exit {rc}): {err.strip()}")
        logger.info(f"{tag} {_ok('Security initialisation complete')}")

        # Drive the cluster to GREEN: reroute stuck shards, set replicas=0 where
        # needed, poll until health is green.  Non-fatal if green is not reached
        # (package upgrades are already done); caller logs remediation steps.
        _wait_for_green(runner, logger, indexer_user, indexer_pass, tag)

    finally:
        if ssh:
            ssh.close()


def upgrade_non_indexer_components(node, ssh_cfg, private_key, config, logger,
                                    only_components=None):
    """
    Phase 4 (per node, remote nodes first): upgrade wazuh-manager, filebeat,
    wazuh-dashboard — only those present on this node.

    only_components: if given, only install components in this set (used by
    --wazuh-manager / --filebeat / --wazuh-dashboard flags to skip the rest).

    The wazuh-indexer must already be running and security-initialised (Phase 3)
    before this runs; the wazuh-manager postinst connects to the indexer API.
    """
    host = node["host"]
    name = node.get("name", host)
    is_local = node.get("_local", False)
    tag = _node_tag(name, is_local)
    logger.info(f"\n{tag} Phase 4 — upgrading manager / filebeat / dashboard")

    runner, ssh = _make_runner(node, ssh_cfg, private_key, logger)

    try:
        pm = node.get("_pm") or detect_package_manager(runner)
        components = node.get("_non_indexer_components")
        if components is None:
            expected = node.get("_expected_components", [])
            all_comps = detect_components(runner, pm, expected)
            components = [c for c in all_comps if c != "indexer"]

        # Honour component-scope flag: keep only what the user requested
        if only_components:
            components = [c for c in components if c in only_components]

        logger.info(f"{tag} Non-indexer components: {', '.join(components) or '(none)'}")

        for component, pkg in [
            ("manager", "wazuh-manager"),
            ("filebeat", "filebeat"),
            ("dashboard", "wazuh-dashboard"),
        ]:
            if component not in components:
                continue

            comp_tag = _node_tag(name, is_local, component)
            _install_package(pm, runner, logger, pkg, tag=comp_tag)

            if pkg == "wazuh-manager":
                runner(
                    "if [ -d /var/ossec/etc.pre-upgrade-backup ]; then "
                    "sudo cp -a /var/ossec/etc.pre-upgrade-backup/. /var/ossec/etc/ "
                    "2>/dev/null || true "
                    "&& sudo rm -rf /var/ossec/etc.pre-upgrade-backup "
                    "&& echo 'Restored ossec config from backup'; fi"
                )
            if pkg == "filebeat":
                runner(
                    "if [ -d /etc/filebeat.pre-upgrade-backup ]; then "
                    "sudo cp -a /etc/filebeat.pre-upgrade-backup/. /etc/filebeat/ "
                    "2>/dev/null || true "
                    "&& sudo rm -rf /etc/filebeat.pre-upgrade-backup; fi"
                )

        for svc, component in [
            ("wazuh-manager", "manager"),
            ("filebeat", "filebeat"),
            ("wazuh-dashboard", "dashboard"),
        ]:
            if component not in components:
                continue
            comp_tag = _node_tag(name, is_local, component)
            rc, _, _ = runner(f"sudo systemctl is-active {svc}")
            if rc != 0:
                logger.info(f"{comp_tag} Starting {svc}")
                runner(
                    f"sudo systemctl daemon-reload "
                    f"&& sudo systemctl enable {svc} "
                    f"&& sudo systemctl start {svc}"
                )
            logger.info(f"{comp_tag} {_ok(f'{svc} is running')}")

        logger.info(f"{tag} {_ok('Phase 4 complete')}")
        json_logger.write("node_upgrade", "success", node=name)

    finally:
        if ssh:
            ssh.close()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Upgrade Wazuh cluster — remote nodes first, then local",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Node scope (mutually exclusive — default: all nodes, remote first):
  --local          Upgrade only the local node (Phases 2 and 4 on local only).
  --remote-only    Upgrade only remote nodes (Phases 2 and 4 on remote only).
                   Phases 1 and 3 still run on the local node because shard
                   allocation and security-init are cluster-level operations.

Component scope (combinable — default: all components):
  --wazuh-indexer  Upgrade wazuh-indexer only  (Phases 1-3; skip Phase 4).
  --wazuh-manager  Upgrade wazuh-manager only  (Phase 4 only; skip Phases 1-3).
  --wazuh-dashboard Upgrade wazuh-dashboard only (Phase 4 only).
  --filebeat       Upgrade filebeat only        (Phase 4 only).
  --all            Upgrade all components (explicit alias for the default).

Examples:
  # Full upgrade of all nodes (default):
  python3 wazuh_upgrade_cluster.py --config config.yml

  # Re-run just manager and filebeat on the remote node after a partial failure:
  python3 wazuh_upgrade_cluster.py --config config.yml --remote-only --wazuh-manager --filebeat

  # Upgrade only the dashboard on all nodes:
  python3 wazuh_upgrade_cluster.py --config config.yml --wazuh-dashboard

  # Upgrade only the local node (all components):
  python3 wazuh_upgrade_cluster.py --config config.yml --local
        """,
    )
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--verbose", action="store_true")

    # ── Node scope ────────────────────────────────────────────────────────────
    node_scope = parser.add_mutually_exclusive_group()
    node_scope.add_argument(
        "--local",
        action="store_true",
        help="Upgrade only the local node (Phases 2 and 4 on local only)",
    )
    node_scope.add_argument(
        "--remote-only",
        action="store_true",
        dest="remote_only",
        help="Upgrade only remote nodes (Phases 1 and 3 still run on local)",
    )

    # ── Component scope ───────────────────────────────────────────────────────
    parser.add_argument(
        "--wazuh-indexer",
        action="store_true",
        dest="wazuh_indexer",
        help="Upgrade wazuh-indexer (triggers Phases 1-3)",
    )
    parser.add_argument(
        "--wazuh-manager",
        action="store_true",
        dest="wazuh_manager",
        help="Upgrade wazuh-manager (Phase 4 only)",
    )
    parser.add_argument(
        "--wazuh-dashboard",
        action="store_true",
        dest="wazuh_dashboard",
        help="Upgrade wazuh-dashboard (Phase 4 only)",
    )
    parser.add_argument(
        "--filebeat",
        action="store_true",
        help="Upgrade filebeat (Phase 4 only)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="upgrade_all",
        help="Upgrade all components — explicit alias for the default behaviour",
    )

    args = parser.parse_args()

    logger = setup_logger(args.verbose)

    # ── Resolve component scope ───────────────────────────────────────────────
    # If no component flag is given (or --all is explicit), upgrade everything.
    component_flags_given = any([
        args.wazuh_indexer, args.wazuh_manager, args.wazuh_dashboard, args.filebeat,
    ])
    if args.upgrade_all or not component_flags_given:
        requested_components = {"indexer", "manager", "filebeat", "dashboard"}
    else:
        requested_components = set()
        if args.wazuh_indexer:   requested_components.add("indexer")
        if args.wazuh_manager:   requested_components.add("manager")
        if args.wazuh_dashboard: requested_components.add("dashboard")
        if args.filebeat:        requested_components.add("filebeat")

    run_indexer_phases   = "indexer" in requested_components
    run_non_indexer_phase = bool(requested_components - {"indexer"})
    # Components for Phase 4 — only the non-indexer ones actually requested
    phase4_components = requested_components - {"indexer"} if run_non_indexer_phase else set()

    # ── Log effective scope ───────────────────────────────────────────────────
    node_scope_label = (
        "LOCAL only"  if args.local       else
        "REMOTE only" if args.remote_only else
        "ALL nodes (remote first, then local)"
    )
    border  = _cc(_C.BR_WHITE + _C.BOLD, "=" * 80) if _TTY else "=" * 80
    heading = _cc(_C.BR_WHITE + _C.BOLD, "WAZUH CLUSTER UPGRADE")       if _TTY else "WAZUH CLUSTER UPGRADE"
    logger.info(f"\n{border}")
    logger.info(heading)
    logger.info(border)
    logger.info(f"Node scope  : {_cc(_C.BOLD, node_scope_label) if _TTY else node_scope_label}")
    logger.info(f"Components  : {', '.join(sorted(requested_components))}")
    phases_str = (
        f"{'1 (prepare) ' if run_indexer_phases else ''}"
        f"{'2 (indexer) ' if run_indexer_phases else ''}"
        f"{'3 (security-init) ' if run_indexer_phases else ''}"
        f"{'4 (manager/filebeat/dashboard)' if run_non_indexer_phase else ''}"
    ).strip() or "(nothing to do)"
    logger.info(f"Phases      : {phases_str}")
    logger.info(border)

    if not run_indexer_phases and not run_non_indexer_phase:
        logger.error("No components selected.  Pass at least one component flag or --all.")
        return 1

    config = load_config(args.config)
    ssh_cfg = config["ssh"]
    private_key, public_key = resolve_ssh_key(ssh_cfg, logger)

    # Collect and deduplicate nodes across all role sections.
    # First-occurrence wins so the node name reflects the primary role
    # (indexers → servers → dashboards).  A host appearing in multiple sections
    # keeps the name from the first section it appears in.
    all_nodes_raw = []
    for role in ["indexers", "servers", "dashboards"]:
        all_nodes_raw.extend(config["nodes"].get(role, []))
    unique_nodes: dict = {}
    for node in all_nodes_raw:
        if node["host"] not in unique_nodes:
            unique_nodes[node["host"]] = node
    deduplicated_nodes = list(unique_nodes.values())

    # Classify local vs remote and annotate expected components
    classify_nodes(deduplicated_nodes, logger)
    annotate_expected_components(deduplicated_nodes, config)

    logger.info(
        "Nodes: "
        + ", ".join(
            f'{n.get("name", n["host"])} ({"local" if n.get("_local") else "remote"}, '
            f'expected: {", ".join(n.get("_expected_components", [])) or "none"})'
            for n in deduplicated_nodes
        )
    )

    # ── Build node lists ──────────────────────────────────────────────────────
    remote_nodes = [n for n in deduplicated_nodes if not n.get("_local", False)]
    local_nodes  = [n for n in deduplicated_nodes if     n.get("_local", False)]

    indexer_nodes = [
        n for n in deduplicated_nodes if "indexer" in n.get("_expected_components", [])
    ]
    if not indexer_nodes:
        indexer_nodes = deduplicated_nodes  # fallback if roles not set in config

    remote_indexer_nodes = [n for n in indexer_nodes if not n.get("_local", False)]
    local_indexer_nodes  = [n for n in indexer_nodes if     n.get("_local", False)]

    # Phases 1 and 3 always target the local indexer (cluster API lives there)
    phase1_3_node = local_indexer_nodes[0] if local_indexer_nodes else indexer_nodes[0]

    # Phase 2 node order: respect --local / --remote-only; default remote first
    if args.local:
        phase2_nodes = local_indexer_nodes
    elif args.remote_only:
        phase2_nodes = remote_indexer_nodes
    else:
        phase2_nodes = remote_indexer_nodes + local_indexer_nodes  # remote first

    # Phase 4 node order: same scoping rule
    if args.local:
        phase4_nodes = local_nodes
    elif args.remote_only:
        phase4_nodes = remote_nodes
    else:
        phase4_nodes = remote_nodes + local_nodes  # remote first

    # Deploy SSH public key to every remote node that will be touched this run
    nodes_needing_ssh = set()
    if run_indexer_phases:
        nodes_needing_ssh.update(n["host"] for n in phase2_nodes if not n.get("_local"))
    if run_non_indexer_phase:
        nodes_needing_ssh.update(n["host"] for n in phase4_nodes if not n.get("_local"))

    ssh_target_nodes = [n for n in remote_nodes if n["host"] in nodes_needing_ssh]
    if ssh_target_nodes:
        logger.info("Deploying SSH public key to remote nodes...")
        for node in ssh_target_nodes:
            try:
                deploy_ssh_key(node, ssh_cfg, public_key, logger)
            except Exception as e:
                logger.warning(f'SSH key deployment warning for {node["host"]}: {e}')

    # ── Run phases ────────────────────────────────────────────────────────────
    indexer_user = config.get("wazuh", {}).get("indexer", {}).get("username", "admin")
    indexer_pass = config.get("wazuh", {}).get("indexer", {}).get("password", "admin")
    creds = shlex.quote(f"{indexer_user}:{indexer_pass}")

    try:
        # ── PHASE 1: Prepare cluster ─────────────────────────────────────────
        if run_indexer_phases:
            prepare_cluster_upgrade(phase1_3_node, ssh_cfg, private_key, config, logger)
        else:
            logger.info("Skipping Phase 1 (indexer not in requested components)")

        # ── PHASE 2: Upgrade wazuh-indexer ───────────────────────────────────
        if run_indexer_phases:
            _phase_banner(logger, 2, f"UPGRADE INDEXER NODES ({node_scope_label})")
            if not phase2_nodes:
                logger.warning("No indexer nodes in scope for Phase 2 — skipping")
            for node in phase2_nodes:
                try:
                    upgrade_indexer_only(node, ssh_cfg, private_key, config, logger)
                except Exception as e:
                    logger.error(
                        f"Indexer upgrade failed on {node.get('name', node['host'])}: {e}"
                    )
                    return 1
        else:
            logger.info("Skipping Phase 2 (indexer not in requested components)")

        # ── PHASE 3: Health check + security-init + re-enable shards ─────────
        # Non-fatal: Phase 4 still runs so all packages reach the new version.
        phase3_error = None
        if run_indexer_phases:
            try:
                check_health_security_init_reenable(
                    phase1_3_node, ssh_cfg, private_key, config, logger
                )
            except Exception as e:
                phase3_error = str(e)
                logger.warning("\n" + "=" * 80)
                logger.warning(
                    "PHASE 3 FAILED — continuing to Phase 4 to complete package upgrades"
                )
                logger.warning(f"Reason: {phase3_error}")
                logger.warning(
                    "Re-run Phase 3 manually after Phase 4 finishes:\n"
                    "  sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh\n"
                    f"  curl -k -s -u {creds} -X PUT "
                    "https://localhost:9200/_cluster/settings "
                    "-H 'Content-Type: application/json' "
                    "-d '{\"persistent\":{\"cluster.routing.allocation.enable\":\"all\"}}'"
                )
                logger.warning("=" * 80 + "\n")
        else:
            logger.info("Skipping Phase 3 (indexer not in requested components)")

        # ── PHASE 4: Upgrade manager / filebeat / dashboard ───────────────────
        if run_non_indexer_phase:
            _phase_banner(
                logger, 4,
                f"UPGRADE {', '.join(sorted(phase4_components)).upper()} ({node_scope_label})"
            )
            if not phase4_nodes:
                logger.warning("No nodes in scope for Phase 4 — skipping")
            for node in phase4_nodes:
                try:
                    upgrade_non_indexer_components(
                        node, ssh_cfg, private_key, config, logger,
                        only_components=phase4_components,
                    )
                except Exception as e:
                    logger.error(
                        f"Component upgrade failed on {node.get('name', node['host'])}: {e}"
                    )
                    return 1
        else:
            logger.info("Skipping Phase 4 (no non-indexer components requested)")

        # ── Final summary ─────────────────────────────────────────────────────
        fin_border = _cc(_C.BR_WHITE + _C.BOLD, "=" * 80) if _TTY else "=" * 80
        logger.info(f"\n{fin_border}")
        if phase3_error:
            warn_head = (
                _cc(_C.BR_YELLOW + _C.BOLD, "ALL PACKAGE UPGRADES COMPLETE — PHASE 3 STILL NEEDS TO BE REPEATED")
                if _TTY else "ALL PACKAGE UPGRADES COMPLETE — PHASE 3 STILL NEEDS TO BE REPEATED"
            )
            logger.warning(warn_head)
            logger.warning(fin_border)
            logger.warning(
                "Phase 3 (health check + security-init + re-enable shards) did not "
                "complete.  Run these commands on the local indexer node:"
            )
            logger.warning("")
            logger.warning("  Step 1 — security init:")
            logger.warning("    sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh")
            logger.warning("")
            logger.warning("  Step 2 — re-enable shard allocation:")
            logger.warning(
                f"    curl -k -s -u {creds} -X PUT "
                "https://localhost:9200/_cluster/settings "
                "-H 'Content-Type: application/json' "
                "-d '{\"persistent\":{\"cluster.routing.allocation.enable\":\"all\"}}'"
            )
            logger.warning("")
            logger.warning("  Step 3 — verify cluster health:")
            logger.warning(
                f"    curl -k -s -u {creds} "
                "https://localhost:9200/_cluster/health | python3 -m json.tool"
            )
            logger.warning("=" * 80)
            return 2
        else:
            logger.info(_ok("CLUSTER UPGRADE COMPLETED SUCCESSFULLY"))
            logger.info(fin_border)
            logger.info("Post-upgrade checklist:")
            logger.info(
                f"  1. Verify cluster health: "
                f"curl -k -s -u {creds} https://localhost:9200/_cluster/health"
            )
            logger.info("  2. If a kernel upgrade is pending: ssh user@host 'sudo reboot'")
            logger.info("  3. Verify agents connect to upgraded managers")
            return 0

    except Exception as e:
        logger.error(f"Cluster upgrade failed: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
