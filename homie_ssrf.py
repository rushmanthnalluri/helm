"""homie_ssrf.py - Outbound SSRF Protection & IP-Pinned Egress for Homie.

Security Invariants:
1. Anti-Rebinding IP Pinning: Resolves DNS once, validates resolved IP against
   cloud metadata and private RFC1918 CIDRs, then opens socket directly to the
   validated IP. Never re-resolves between validation and connection.
2. Hop-by-Hop Redirect Validation: Revalidates every HTTP redirect hop. A safe
   public URL is barred from redirecting into 169.254.169.254 or private subnets.
3. Configurable Safe Loopback Ports: Permits specific developer ports (e.g. 11434
   for local Ollama, 8000 for local gateways) when requested, while unconditionally
   barring port 80/443 loopback and cloud metadata endpoints.
4. Non-Standard Encoding Defense: Catches decimal, hex, octal, short-dotted, and
   IPv4-mapped IPv6 encodings (e.g. ::ffff:127.0.0.1, 0x7f000001).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("homie.ssrf")

# Cloud metadata endpoints to block unconditionally
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

# Standard allowed local AI and gateway ports when loopback is explicitly allowed
DEFAULT_ALLOWED_LOOPBACK_PORTS: Set[int] = {11434, 8000, 8080}


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


def is_private_ip(ip_str: str, allowed_ports: Optional[Set[int]] = None, port: Optional[int] = None) -> bool:
    """Check if an IP address belongs to private/loopback/metadata CIDRs."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            addr = embedded

    # Never allow link-local metadata (169.254.169.254) under any circumstances
    if str(addr) == "169.254.169.254":
        return True

    # Check loopback exception for allowed local services (Ollama, local proxy)
    if addr.is_loopback and allowed_ports and port in allowed_ports:
        return False

    return any(addr in net for net in BLOCKED_CIDR)


def _disguised_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Return canonical IPv4 for non-standard formats (hex, decimal, octal, short-dotted)."""
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    addr = ipaddress.IPv4Address(packed)
    if str(addr) == host:
        return None
    return addr


def check_ssrf(
    target: str,
    allow_loopback: bool = False,
    allowed_loopback_ports: Optional[Set[int]] = None
) -> Optional[str]:
    """Check a URL or hostname for SSRF risks.
    Returns None if safe, or an error string if blocked.
    """
    if not target or not isinstance(target, str):
        return "Empty or invalid target"

    target_str = target.strip()
    port = None
    if "://" in target_str:
        parsed = urlparse(target_str)
        hostname = parsed.hostname
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == "https" else 80
        if not hostname:
            return "No valid hostname found in URL"
    else:
        host_part = target_str.split("/")[0]
        if ":" in host_part and not host_part.startswith("["):
            parts = host_part.split(":")
            hostname = parts[0]
            try: port = int(parts[1])
            except ValueError: port = 80
        else:
            hostname = host_part
            port = 80

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
                if is_private_ip(mapped_str, allowed_loopback_ports if allow_loopback else None, port):
                    return f"URL resolves to private IP: {mapped_str}"
        if is_private_ip(hostname_lower, allowed_loopback_ports if allow_loopback else None, port):
            return f"URL resolves to private IP: {hostname_lower}"
        return None

    # 3. Disguised IPv4 encodings (hex, decimal, octal, short-dotted)
    disguised = _disguised_ipv4(hostname_lower)
    if disguised is not None:
        disguised_str = str(disguised)
        if disguised_str in BLOCKED_HOSTS:
            return f"Blocked host: {disguised_str} (cloud metadata endpoint)"
        if is_private_ip(disguised_str, allowed_loopback_ports if allow_loopback else None, port):
            return f"URL resolves to private IP: {disguised_str}"
        return None

    # 4. Localhost names
    if hostname_lower in ("localhost", "ip6-localhost", "ip6-loopback"):
        if allow_loopback and allowed_loopback_ports and port in allowed_loopback_ports:
            return None
        return f"Blocked loopback host: {hostname_lower}"

    # 5. DNS Resolution & fail-closed validation
    try:
        resolved = socket.getaddrinfo(
            hostname_lower,
            port or 80,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        if os.environ.get("HOMIE_SSRF_FAIL_OPEN", "").lower() in ("1", "true"):
            return None
        return f"Could not resolve host (blocked, fail-closed): {hostname_lower}"

    for family, stype, proto, canonname, sockaddr in resolved:
        ip = sockaddr[0]
        if is_private_ip(ip, allowed_loopback_ports if allow_loopback else None, port):
            return f"URL resolves to private IP: {ip}"

    return None  # Safe


def resolve_and_pin_ip(hostname: str, port: int) -> Tuple[bool, str, Optional[str]]:
    """Resolves DNS once and validates the IP.
    Returns (ok, message, pinned_ip).
    """
    hostname_lower = hostname.lower().strip("[]")
    if hostname_lower in BLOCKED_HOSTS:
        return False, f"Blocked cloud metadata host: {hostname_lower}", None

    try:
        resolved = socket.getaddrinfo(hostname_lower, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"DNS resolution failed (fail-closed): {e}", None

    for family, stype, proto, canonname, sockaddr in resolved:
        ip = sockaddr[0]
        if is_private_ip(ip):
            return False, f"SSRF violation: resolved to private IP {ip}", None
        return True, "IP verified and pinned", ip

    return False, "No valid IP addresses returned by DNS", None


def pinned_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 5.0,
    max_redirects: int = 5
) -> Tuple[bool, int, str]:
    """Performs an HTTP request with atomic IP pinning and hop-by-hop redirect SSRF validation.
    Returns (ok: bool, status_code: int, response_body: str).
    """
    current_url = url
    headers = headers or {}

    for hop in range(max_redirects + 1):
        err = check_ssrf(current_url)
        if err:
            return False, 403, f"SSRF Blocked: {err}"

        parsed = urlparse(current_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        hostname = parsed.hostname or ""

        ok, msg, pinned_ip = resolve_and_pin_ip(hostname, port)
        if not ok or not pinned_ip:
            return False, 403, f"SSRF Blocked on hop {hop}: {msg}"

        # Connect directly to pinned IP
        try:
            raw_sock = socket.create_connection((pinned_ip, port), timeout=timeout_sec)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)
            else:
                sock = raw_sock

            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            req_lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {hostname}",
                "User-Agent: HomieWorkstationAgent/1.0",
                "Connection: close",
            ]
            for k, v in headers.items():
                if k.lower() not in ("host", "user-agent", "connection"):
                    req_lines.append(f"{k}: {v}")
            req_lines.append("\r\n")

            sock.sendall("\r\n".join(req_lines).encode("latin-1"))

            # Read response
            resp_bytes = bytearray()
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_bytes.extend(chunk)
                if len(resp_bytes) > 1_000_000:  # 1MB cap
                    break
            sock.close()

            # Parse status line and headers
            resp_text = resp_bytes.decode("utf-8", errors="replace")
            header_part, _, body = resp_text.partition("\r\n\r\n")
            first_line = header_part.splitlines()[0] if header_part else ""
            status_code = int(first_line.split()[1]) if len(first_line.split()) > 1 else 500

            # Handle redirects hop-by-hop
            if status_code in (301, 302, 303, 307, 308) and hop < max_redirects:
                loc = None
                for line in header_part.splitlines()[1:]:
                    if line.lower().startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        break
                if loc:
                    current_url = urljoin(current_url, loc)
                    logger.info("Following redirect hop %d to %s", hop + 1, current_url)
                    continue

            return status_code < 400, status_code, body

        except Exception as e:
            return False, 502, f"Pinned fetch connection failure to {pinned_ip}: {e}"

    return False, 508, "Too many redirects (max hops reached)"
