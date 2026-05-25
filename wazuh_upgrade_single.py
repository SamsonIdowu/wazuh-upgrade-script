#!/usr/bin/env python3
"""
Upgrade all Wazuh central components on a single node.

This script follows the current Wazuh central-components upgrade flow:
  - Add the Wazuh repo
  - Upgrade indexer, server, filebeat, and dashboard
  - Apply version-gated ossec.conf updates when requested
  - Log every step and every failure

Requirements:
  pip install pyyaml
  python3 wazuh_upgrade_single.py --config config.yml

Run as root or with passwordless sudo.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from wazuh_upgrade_common import (
    Node,
    detect_pkg_mgr,
    disable_wazuh_repo,
    ensure_green_cluster_health,
    ensure_wazuh_repo,
    get_ssh_settings,
    indexer_cluster_reenable,
    load_yaml,
    package_installed,
    patch_ossec_conf,
    setup_logging,
    upgrade_dashboard,
    upgrade_filebeat,
    upgrade_indexer,
    upgrade_indexer_security,
    upgrade_manager,
    verify_versions,
    wait_for_indexer_health,
)


def build_single_node(cfg: Dict[str, Any]) -> Node:
    local = cfg.get("local", {}) or {}
    roles = list(local.get("roles", ["indexer", "server", "dashboard"]) or [])
    return Node(
        name=local.get("name", "local-node"),
        host=local.get("host", "127.0.0.1"),
        roles=roles,
        local=True,
        master=bool(local.get("master", True)),
        cluster_manager=bool(local.get("cluster_manager", True)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Upgrade Wazuh central components on one node")
    parser.add_argument("--config", default="config.yml", help="Path to config.yml")
    parser.add_argument("--log-file", default="wazuh_upgrade_single.log", help="Log file path")
    parser.add_argument("--source-version", default=None, help="Current Wazuh version, e.g. 4.12.3")
    parser.add_argument("--target-version", default="4.14.5", help="Target Wazuh version for Filebeat template URL")
    parser.add_argument("--skip-config-patches", action="store_true", help="Skip ossec.conf version-gated changes")
    args = parser.parse_args()

    logger = setup_logging(args.log_file)
    cfg = load_yaml(args.config)
    ssh = get_ssh_settings(cfg)

    node = build_single_node(cfg)
    source_version = args.source_version or cfg.get("source_version")
    target_version = args.target_version or cfg.get("target_version", "4.14.5")

    logger.info("Starting single-node upgrade on %s", node.display())

    indexer_user = (cfg.get("wazuh", {}).get("indexer", {}) or {}).get("username")
    indexer_pass = (cfg.get("wazuh", {}).get("indexer", {}) or {}).get("password")
    indexer_hosts = cfg.get("wazuh", {}).get("indexer", {}).get("hosts") or [node.host]

    family, pkg_bin = ensure_wazuh_repo(node, ssh, logger)

    indexer_present = package_installed(node, ssh, "wazuh-indexer", logger)
    manager_present = package_installed(node, ssh, "wazuh-manager", logger)
    dashboard_present = package_installed(node, ssh, "wazuh-dashboard", logger)
    filebeat_present = package_installed(node, ssh, "filebeat", logger)

    # In a one-node all-in-one layout, the manager should stop before the indexer goes down.
    if indexer_present and manager_present:
        from wazuh_upgrade_common import stop_service
        stop_service(node, ssh, "wazuh-manager", logger)

    if indexer_present:
        if indexer_user and indexer_pass:
            from wazuh_upgrade_common import indexer_cluster_prepare
            indexer_cluster_prepare(node, ssh, indexer_user, indexer_pass, logger)
        else:
            logger.warning("Indexer credentials not provided; skipping cluster-prep API calls")
        upgrade_indexer(node, ssh, pkg_bin, logger)

        if indexer_user and indexer_pass:
            wait_for_indexer_health(node, ssh, indexer_user, indexer_pass, logger)

        upgrade_indexer_security(node, ssh, logger)

        if indexer_user and indexer_pass:
            # Re-enable shard allocation (was restricted to 'primaries' by cluster-prep)
            # then drive the cluster to GREEN (sets replicas=0 on single-node so the
            # cluster never stays yellow due to unassignable replica shards).
            indexer_cluster_reenable(node, ssh, indexer_user, indexer_pass, logger)
            ensure_green_cluster_health(
                node, ssh, indexer_user, indexer_pass, logger, is_single_node=True
            )

    if manager_present:
        upgrade_manager(node, ssh, pkg_bin, logger)

        if not args.skip_config_patches:
            patch_ossec_conf(
                node,
                ssh,
                logger,
                source_version=source_version,
                indexer_hosts=[str(x) for x in indexer_hosts],
                apply_cdb_lists=True,
                apply_vuln_detection=True,
            )
            # Restart to load the patched config if anything changed.
            from wazuh_upgrade_common import restart_service
            restart_service(node, ssh, "wazuh-manager", logger)

    if filebeat_present:
        upgrade_filebeat(node, ssh, pkg_bin, target_version, logger)

    if dashboard_present:
        upgrade_dashboard(node, ssh, pkg_bin, logger)

    disable_wazuh_repo(node, ssh, family, logger)
    verify_versions(node, ssh, family, logger)

    logger.info("Single-node upgrade complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
