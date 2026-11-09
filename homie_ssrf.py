"""homie_ssrf.py - Outbound SSRF Protection for Homie Workstation Assistant.

Blocks requests and tool executions targeting:
1. Cloud metadata services (AWS, GCP, Azure, Alibaba): 169.254.169.254, metadata.google.internal, etc.
2. Private & loopback RFC1918 / RFC4193 CIDRs: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7.
3. IPv4-mapped / IPv4-compatible IPv6 variants: e.g. ::ffff:127.0.0.1, ::ffff:169.254.169.254.
4. Disguised IPv4 encodings: decimal (2130706433), hex (0x7f000001), octal, short-dotted (127.1).
5. DNS rebinding & unresolved hostnames (fail-closed by default).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("homie.ssrf")

# Cloud metadata endpoints to block
BLOCKED_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "100.100.100.200",  # Alibaba Cloud metadata
    "instance-data",
})

# Private and reserved networks
BLOCKED_CIDR = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / metadata
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),          # Unspecified
    ipaddress.ip_network("::1/128"),        # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),        # Unique local IPv6
    ipaddress.ip_network("fe80::/10"),       # Link-local IPv6
    ipaddress.ip_network("ff00::/8"),        # Multicast IPv6
]


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Extract embedded IPv4 for mapped/compatible IPv6 addresses."""
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return mapped
    packed = addr.packed
    if (
        packed[:12] == b"\x00" * 12
        and addr != ipaddress.IPv6Address("::")
        and addr != ipaddress.IPv6Address("::1")
    ):
        return ipaddress.IPv4Address(packed[12:])
    return None


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to private/loopback/metadata CIDRs."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            addr = embedded

    return any(addr in net for net in BLOCKED_CIDR)


def _disguised_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Return canonical IPv4 for non-standard formats (hex, decimal, octal, short-dotted)."""
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    addr = ipaddress.IPv4Address(packed)
    if str(addr) == host:
        return None  # Standard dotted-quad already handled by ip_address
    return addr


def check_ssrf(target: str, allow_loopback: bool = False) -> Optional[str]:
    """Check a URL or hostname for SSRF risks.
    Returns:
        None if safe.
        Error message string describing reason for blocking if unsafe.
    """
    if not target or not isinstance(target, str):
        return "Empty or invalid target"

    target_str = target.strip()
    if "://" in target_str:
        parsed = urlparse(target_str)
        hostname = parsed.hostname
        if not hostname:
            return "No valid hostname found in URL"
    else:
        # Split off port or path if present
        host_part = target_str.split("/")[0]
        if ":" in host_part and not host_part.startswith("["):
            hostname = host_part.split(":")[0]
        else:
            hostname = host_part

    if not hostname:
        return "No hostname found in target"

    hostname_lower = hostname.lower().strip("[]")

    # 1. Blocked cloud metadata hosts
    if hostname_lower in BLOCKED_HOSTS:
        return f"Blocked host: {hostname_lower} (cloud metadata endpoint)"

    # 2. Direct IP address literal check
    try:
        literal = ipaddress.ip_address(hostname_lower)
    except ValueError:
        literal = None

    if literal is not None:
        if isinstance(literal, ipaddress.IPv6Address):
            embedded = _embedded_ipv4(literal)
            if embedded is not None:
                mapped_str = str(embedded)
                if mapped_str in BLOCKED_HOSTS:
                    return f"Blocked host: {mapped_str} (cloud metadata endpoint)"
                if not allow_loopback and is_private_ip(mapped_str):
                    return f"URL resolves to private IP: {mapped_str}"
        if not allow_loopback and is_private_ip(hostname_lower):
            return f"URL resolves to private IP: {hostname_lower}"
        return None

    # 3. Disguised IPv4 encodings (hex, decimal, octal, short-dotted)
    disguised = _disguised_ipv4(hostname_lower)
    if disguised is not None:
        disguised_str = str(disguised)
        if disguised_str in BLOCKED_HOSTS:
            return f"Blocked host: {disguised_str} (cloud metadata endpoint)"
        if not allow_loopback and is_private_ip(disguised_str):
            return f"URL resolves to private IP: {disguised_str}"
        return None

    # 4. Localhost names
    if not allow_loopback and hostname_lower in ("localhost", "ip6-localhost", "ip6-loopback"):
        return f"Blocked loopback host: {hostname_lower}"

    # 5. DNS Resolution & fail-closed validation
    try:
        resolved = socket.getaddrinfo(
            hostname_lower,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        if os.environ.get("HOMIE_SSRF_FAIL_OPEN", "").lower() in ("1", "true"):
            return None
        return f"Could not resolve host (blocked, fail-closed): {hostname_lower}"

    for family, stype, proto, canonname, sockaddr in resolved:
        ip = sockaddr[0]
        if not allow_loopback and is_private_ip(ip):
            return f"URL resolves to private IP: {ip}"

    return None  # Target is safe
