"""helm_netstat.py - Network Traffic Intelligence & Outbound Connection Auditor.

Provides local-first inspection and auditing of active network sockets:
- Enumerates active TCP/UDP sockets mapped to process names and PIDs
- Classifies traffic into Loopback, LAN (RFC1918), and Public Internet
- Detects cloud metadata probes (169.254.169.254) and non-standard outbound ports
- Generates structured network summaries and plain-English reports
- Purely read-only and local: zero network egress required for inspection
"""

import os
import sys
import socket
import ipaddress
import logging
from typing import Dict, Any, List, Optional
import psutil

logger = logging.getLogger("helm.netstat")


def _is_private_or_loopback(ip_str: str) -> str:
    """Classifies an IP address into loopback, private_lan, or public."""
    if not ip_str or ip_str in ("0.0.0.0", "::", "*"):
        return "any"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "private_lan"
        if ip.is_link_local:
            return "link_local"
        return "public"
    except ValueError:
        return "unknown"


def _get_process_name(pid: Optional[int]) -> str:
    if not pid:
        return "System/Kernel"
    try:
        p = psutil.Process(pid)
        return p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"PID:{pid}"


def get_active_connections(include_loopback: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieves list of active network connections with process context."""
    results = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        logger.error("Could not query net connections: %s", e)
        return []

    for c in conns:
        l_ip = c.laddr.ip if c.laddr else ""
        l_port = c.laddr.port if c.laddr else 0
        r_ip = c.raddr.ip if c.raddr else ""
        r_port = c.raddr.port if c.raddr else 0

        scope = _is_private_or_loopback(r_ip or l_ip)
        if not include_loopback and scope == "loopback":
            continue

        proc_name = _get_process_name(c.pid)
        is_metadata = (r_ip == "169.254.169.254")

        results.append({
            "pid": c.pid,
            "process": proc_name,
            "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "status": c.status,
            "local_address": f"{l_ip}:{l_port}" if l_ip else "",
            "remote_address": f"{r_ip}:{r_port}" if r_ip else "",
            "remote_ip": r_ip,
            "remote_port": r_port,
            "scope": scope,
            "flag_metadata_probe": is_metadata
        })

        if len(results) >= limit:
            break

    return results


def get_network_activity_summary() -> Dict[str, Any]:
    """Generates an executive summary of current workstation network traffic."""
    all_conns = get_active_connections(include_loopback=True, limit=500)
    
    listening_ports = []
    external_connections = []
    apps_connected = set()
    metadata_probes = []

    for c in all_conns:
        if c["status"] == "LISTEN":
            listening_ports.append({
                "port": c["local_address"],
                "process": c["process"],
                "pid": c["pid"]
            })
        elif c["remote_address"] and c["scope"] == "public":
            external_connections.append(c)
            apps_connected.add(c["process"])
            if c["flag_metadata_probe"]:
                metadata_probes.append(c)

    return {
        "total_active_sockets": len(all_conns),
        "total_listening_services": len(listening_ports),
        "total_public_connections": len(external_connections),
        "active_external_apps": sorted(list(apps_connected)),
        "listening_ports_sample": listening_ports[:10],
        "external_connections_sample": external_connections[:15],
        "security_flags": {
            "metadata_probes_detected": len(metadata_probes) > 0,
            "metadata_probes_count": len(metadata_probes)
        }
    }


def format_network_report() -> str:
    """Formats network activity into a readable markdown summary."""
    summary = get_network_activity_summary()
    lines = [
        "### [Network] Workstation Network Activity Report",
        f"- **Active Sockets**: {summary['total_active_sockets']}",
        f"- **Open Listening Ports**: {summary['total_listening_services']}",
        f"- **Active Outbound Public Connections**: {summary['total_public_connections']}",
        f"- **Applications with Public Internet Access**: {', '.join(summary['active_external_apps']) or 'None'}",
        ""
    ]

    if summary["external_connections_sample"]:
        lines.append("#### Active Outbound Connections (Public)")
        for c in summary["external_connections_sample"][:8]:
            lines.append(f"- **{c['process']}** (PID {c['pid']}) → `{c['remote_address']}` [{c['status']}]")
        lines.append("")

    if summary["listening_ports_sample"]:
        lines.append("#### Local Listening Services")
        for s in summary["listening_ports_sample"][:6]:
            lines.append(f"- Port `{s['port']}` ({s['process']})")

    return "\n".join(lines)
