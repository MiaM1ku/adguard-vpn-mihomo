from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def _prepare() -> None:
    load_dotenv()
    os.chdir(Path(__file__).resolve().parent.parent)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    host = args.host or os.environ.get("ADG2MIHOMO_HOST") or "127.0.0.1"
    port = int(args.port or os.environ.get("ADG2MIHOMO_PORT") or 8787)
    uvicorn.run("adg2mihomo.app:app", host=host, port=port, reload=False)
    return 0


def cmd_login(_: argparse.Namespace) -> int:
    from .client import AdGuardClient

    client = AdGuardClient()
    try:
        pending = client.start_device_login()
        uri = pending.get("verification_uri_complete") or pending.get("verification_uri")
        print("Open this URL and confirm the device code:")
        print(uri)
        print(f"user_code: {pending.get('user_code')}")
        print("Waiting for confirmation...")
        client.wait_device_login()
        print("Login saved to", client.store.root)
        print(json.dumps(client.public_status(), ensure_ascii=False, indent=2))
    finally:
        client.close()
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    from .client import AdGuardClient

    client = AdGuardClient()
    try:
        print(json.dumps(client.public_status(), ensure_ascii=False, indent=2))
    finally:
        client.close()
    return 0


def cmd_refresh(_: argparse.Namespace) -> int:
    from .client import AdGuardClient

    client = AdGuardClient()
    try:
        client.refresh_vpn_token()
        client.refresh_proxy_credentials(force=True)
        client.fetch_locations()
        print(json.dumps(client.public_status(), ensure_ascii=False, indent=2))
    finally:
        client.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .client import AdGuardClient
    from .convert import build_proxies, full_config_yaml, nodes_payload, provider_yaml

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    client = AdGuardClient()
    try:
        snap = client.snapshot(platform=args.platform)
        proxies = build_proxies(
            snap["locations"],
            snap["username"],
            snap["password"],
            include_relay=not args.no_relay,
        )
        provider = provider_yaml(
            proxies,
            cred_ttl=snap.get("proxy_credentials_expires_in_sec"),
            shanghai_injected=bool(snap.get("shanghai_injected")),
        )
        inline = full_config_yaml("http://127.0.0.1:8787/proxies.yaml", inline_proxies=proxies)
        provider_cfg = full_config_yaml("http://127.0.0.1:8787/proxies.yaml")
        nodes = nodes_payload(snap["locations"], include_relay=not args.no_relay)
        (out / "proxies.yaml").write_text(provider, encoding="utf-8")
        (out / "mihomo-inline.yaml").write_text(inline, encoding="utf-8")
        (out / "mihomo.yaml").write_text(provider_cfg, encoding="utf-8")
        (out / "nodes.json").write_text(json.dumps(nodes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # keep compatibility copies in repo root for local use (gitignored)
        if args.legacy:
            Path("mihomo-adguard-proxies.yaml").write_text(provider, encoding="utf-8")
            Path("mihomo-adguard.yaml").write_text(inline, encoding="utf-8")
            Path("nodes.json").write_text(json.dumps(nodes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"exported {len(proxies)} proxies -> {out}")
        print(json.dumps(client.public_status(), ensure_ascii=False, indent=2))
    finally:
        client.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    _prepare()
    parser = argparse.ArgumentParser(prog="adg2mihomo", description="AdGuard VPN -> mihomo TrustTunnel proxy-provider")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run proxy-provider HTTP API")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", default=None)
    p_serve.set_defaults(func=cmd_serve)

    p_login = sub.add_parser("login", help="AdGuard device-code login and save credentials locally")
    p_login.set_defaults(func=cmd_login)

    p_status = sub.add_parser("status", help="show local login / credential TTL")
    p_status.set_defaults(func=cmd_status)

    p_refresh = sub.add_parser("refresh", help="refresh vpn token, proxy credentials, locations")
    p_refresh.set_defaults(func=cmd_refresh)

    p_export = sub.add_parser("export", help="write proxies.yaml / mihomo.yaml / nodes.json")
    p_export.add_argument("-o", "--out", default="dist")
    p_export.add_argument("--platform", default="android")
    p_export.add_argument("--no-relay", action="store_true")
    p_export.add_argument("--legacy", action="store_true", help="also write gitignored root yaml files")
    p_export.set_defaults(func=cmd_export)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
