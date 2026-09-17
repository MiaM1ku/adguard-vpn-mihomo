from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

import yaml


def flag_emoji(cc: str) -> str:
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def _endpoint_sni(endpoint: dict) -> tuple[str, str]:
    domain = endpoint.get("domain_name") or endpoint.get("server_name") or ""
    remote = endpoint.get("remote_identifier") or ""
    sni = domain
    verify = remote or domain
    return sni, verify


def _proxy_name(loc: dict, index: int, total: int, relay: bool) -> str:
    flag = flag_emoji(loc.get("country_code") or "")
    cc = (loc.get("country_code") or "XX").upper()
    city = loc.get("city_name") or loc.get("id") or "node"
    name = f"{flag} AG-{cc}-{city}"
    if loc.get("virtual") and not loc.get("skip_virtual_label"):
        name += "-V"
    if total > 1:
        name += f"-{index}"
    if relay:
        name += "-relay"
    return name


def _one_proxy(
    *,
    name: str,
    server: str,
    username: str,
    password: str,
    sni: str,
    verify: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "type": "trusttunnel",
        "server": server,
        "port": 443,
        "username": username,
        "password": password,
        "sni": sni,
        "name-cert-verify": verify,
        "client-fingerprint": "chrome",
        "alpn": ["h2"],
        "udp": True,
        "health-check": True,
        "max-connections": 8,
        "min-streams": 5,
    }


def iter_endpoints(loc: dict, include_relay: bool) -> Iterable[tuple[dict, bool]]:
    endpoints = list(loc.get("endpoints") or [])
    for ep in endpoints:
        yield ep, False
    if include_relay:
        for ep in loc.get("relay_endpoints") or []:
            yield ep, True


def build_proxies(
    locations: list[dict],
    username: str,
    password: str,
    *,
    include_relay: bool = True,
    only: str | None = None,
) -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    used: set[str] = set()
    for loc in locations:
        if only == "shanghai" and not loc.get("injected") and (loc.get("country_code") or "").upper() != "CN":
            continue
        if only == "shanghai" and (loc.get("country_code") or "").upper() != "CN":
            continue
        pairs = list(iter_endpoints(loc, include_relay=include_relay))
        main_count = sum(1 for _, relay in pairs if not relay)
        relay_count = sum(1 for _, relay in pairs if relay)
        main_i = 0
        relay_i = 0
        for endpoint, relay in pairs:
            server = endpoint.get("ipv4_address") or endpoint.get("alt_ipv4_address")
            if not server:
                continue
            sni, verify = _endpoint_sni(endpoint)
            if not sni:
                continue
            if relay:
                relay_i += 1
                name = _proxy_name(loc, relay_i, relay_count, True)
            else:
                main_i += 1
                name = _proxy_name(loc, main_i, main_count, False)
            original = name
            n = 2
            while name in used:
                name = f"{original}-{n}"
                n += 1
            used.add(name)
            proxies.append(
                _one_proxy(
                    name=name,
                    server=server,
                    username=username,
                    password=password,
                    sni=sni,
                    verify=verify,
                )
            )
    return proxies


def dumps_yaml(payload: dict[str, Any], comments: list[str] | None = None) -> str:
    body = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False, default_flow_style=False)
    if not comments:
        return body
    header = "".join(f"# {line}\n" for line in comments)
    return header + "\n" + body


def provider_yaml(
    proxies: list[dict[str, Any]],
    *,
    cred_ttl: int | None = None,
    shanghai_injected: bool = False,
) -> str:
    comments = [
        "AdGuard VPN -> mihomo TrustTunnel proxy-provider",
        "kernel: mihomo >= 1.19.21",
        f"generated_at: {datetime.now(timezone.utc).isoformat()}",
        f"proxies: {len(proxies)}",
        f"shanghai_injected: {str(shanghai_injected).lower()}",
    ]
    if cred_ttl is not None:
        comments.append(f"proxy_credentials_expires_in_sec: {cred_ttl}")
    return dumps_yaml({"proxies": proxies}, comments)


def full_config_yaml(
    provider_url: str,
    *,
    api_token: str | None = None,
    inline_proxies: list[dict[str, Any]] | None = None,
) -> str:
    comments = [
        "mihomo config using AdGuard TrustTunnel proxy-provider",
        "kernel: mihomo >= 1.19.21",
        "Do not send AdGuard entry IPs / superbaby.tv through another TUN on the same host.",
    ]
    if inline_proxies is not None:
        payload: dict[str, Any] = {
            "mixed-port": 7890,
            "allow-lan": False,
            "bind-address": "*",
            "mode": "rule",
            "log-level": "info",
            "ipv6": True,
            "unified-delay": True,
            "tcp-concurrent": True,
            "dns": {
                "enable": True,
                "ipv6": True,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "nameserver": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
            },
            "proxies": inline_proxies,
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [p["name"] for p in inline_proxies] + ["DIRECT"],
                },
                {
                    "name": "AUTO",
                    "type": "url-test",
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300,
                    "proxies": [p["name"] for p in inline_proxies],
                },
            ],
            "rules": ["GEOIP,private,DIRECT,no-resolve", "MATCH,PROXY"],
        }
        return dumps_yaml(payload, comments)

    provider: dict[str, Any] = {
        "type": "http",
        "url": provider_url,
        "path": "./proxy_providers/adguard.yaml",
        "interval": 3600,
        "health-check": {
            "enable": True,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "lazy": True,
            "expected-status": 204,
        },
    }
    if api_token:
        provider["header"] = {"Authorization": [f"Bearer {api_token}"]}
    payload = {
        "mixed-port": 7890,
        "allow-lan": False,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "dns": {
            "enable": True,
            "ipv6": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
        },
        "proxy-providers": {"adguard": provider},
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "use": ["adguard"], "proxies": ["AUTO", "DIRECT"]},
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "use": ["adguard"],
            },
        ],
        "rules": ["GEOIP,private,DIRECT,no-resolve", "MATCH,PROXY"],
    }
    return dumps_yaml(payload, comments)


def nodes_payload(locations: list[dict], include_relay: bool = True) -> dict[str, Any]:
    nodes = []
    for loc in locations:
        for endpoint, relay in iter_endpoints(loc, include_relay=include_relay):
            sni, verify = _endpoint_sni(endpoint)
            server = endpoint.get("ipv4_address") or endpoint.get("alt_ipv4_address")
            if not server or not sni:
                continue
            nodes.append(
                {
                    "name": _proxy_name(
                        loc,
                        1,
                        1,
                        relay,
                    ),
                    "country_code": loc.get("country_code"),
                    "country": loc.get("country_name"),
                    "city": loc.get("city_name"),
                    "virtual": bool(loc.get("virtual")),
                    "injected": bool(loc.get("injected")),
                    "premium_only": bool(loc.get("premium_only") or endpoint.get("premium_only")),
                    "domain": sni,
                    "ipv4": server,
                    "ipv6": endpoint.get("ipv6_address"),
                    "port": 443,
                    "remote_identifier": verify if verify != sni else None,
                    "relay": relay,
                }
            )
    shanghai = next((n for n in nodes if n.get("country_code") == "CN"), None)
    return {
        "count_locations": len(locations),
        "count_endpoints": len(nodes),
        "protocol": "trusttunnel",
        "port": 443,
        "shanghai": shanghai,
        "nodes": nodes,
    }
