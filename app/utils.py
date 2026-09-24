"""URL validation, SSRF protection, and utility helper functions."""

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse, urlunparse

# Set ALLOW_LOCAL_TARGETS=1 only in local development/testing testbeds
ALLOW_LOCAL_TARGETS = os.getenv("ALLOW_LOCAL_TARGETS", "0").lower() in ("1", "true", "yes")

# RFC 1918, RFC 3927 (link-local), RFC 5737, loopback, multicast, broadcast, cloud metadata
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Checks if an IP address string belongs to private, loopback, or reserved subnets."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_multicast:
            return True
        for net in PRIVATE_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


def validate_and_normalize_url(raw_url: str) -> str:
    """
    Validates, sanitizes, and normalizes a user-provided URL.

    Requirements:
    - Automatically prepends https:// if scheme is missing.
    - Only allows http and https schemes.
    - Validates domain name syntax.
    - Prevents SSRF attacks by blocking internal IP ranges unless configured.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL cannot be empty.")

    cleaned = raw_url.strip()

    # Prepend https:// if missing scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid URL structure: {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only 'http' and 'https' protocols are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid domain name or public IP address.")

    # Disallow localhost explicitly if SSRF protection is active
    if not ALLOW_LOCAL_TARGETS:
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            raise ValueError(
                f"Scanning internal destination '{hostname}' is blocked for SSRF protection."
            )

        # Check if the hostname is a direct IP address
        if is_private_or_reserved_ip(hostname):
            raise ValueError(
                f"Scanning private IP address '{hostname}' is blocked for defensive safety."
            )

        # Attempt DNS resolution to verify destination IP is not a private address
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
            for family, socktype, proto, canonname, sockaddr in addr_info:
                resolved_ip = sockaddr[0]
                if is_private_or_reserved_ip(resolved_ip):
                    raise ValueError(
                        f"Resolved IP '{resolved_ip}' for host '{hostname}' is within a restricted private range."
                    )
        except socket.gaierror:
            # DNS resolution errors will be handled gracefully during scanning
            pass

    # Reconstruct normalized URL with standard default path if empty
    path = parsed.path if parsed.path else "/"
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        parsed.params,
        parsed.query,
        ""  # strip fragments
    ))

    return normalized


def sanitize_headers_for_storage(headers: dict) -> dict:
    """
    Sanitizes HTTP headers by stripping sensitive credentials like
    Authorization, Proxy-Authorization, Set-Cookie raw values, or tokens.
    """
    sensitive_keys = {
        "authorization", "proxy-authorization", "x-api-key", "cookie",
        "set-cookie", "x-auth-token", "jwt", "session"
    }
    sanitized = {}
    for k, v in headers.items():
        if k.lower() not in sensitive_keys:
            # Truncate very long headers to prevent resource exhaustion
            sanitized[k] = str(v)[:1000]
    return sanitized
