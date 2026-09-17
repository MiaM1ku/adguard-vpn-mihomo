from __future__ import annotations

import base64
import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .shanghai import merge_shanghai
from .store import Store

API_BASE = "https://api.adguard.io"
AUTH_BASE = "https://auth.adguard.io"
CLIENT_ID = "adguard-vpn-cli"
BASIC = base64.b64encode(f"{CLIENT_ID}:".encode()).decode()
CRED_REFRESH_SEC = 12 * 3600
LOCATIONS_TTL_SEC = 10 * 60


class AdGuardError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat()


class AdGuardClient:
    def __init__(self, store: Store | None = None) -> None:
        self.store = store or Store()
        self.http = httpx.Client(
            timeout=20.0,
            headers={"User-Agent": "adg2mihomo/1.0", "Accept": "application/json"},
            follow_redirects=True,
        )

    def close(self) -> None:
        self.http.close()

    def app_id(self) -> str:
        env = os.environ.get("ADG2MIHOMO_APP_ID")
        if env:
            return env
        creds = self.store.load("proxy_credentials.json") or {}
        if creds.get("app_id"):
            return creds["app_id"]
        return "1e977a6caf67053e"

    def vpn_token(self) -> str:
        data = self.store.load("vpn_token.json") or {}
        token = data.get("token")
        if not token:
            raise AdGuardError("VPN token missing. Run: python -m adg2mihomo login")
        return token

    def logged_in(self) -> bool:
        data = self.store.load("vpn_token.json") or {}
        return bool(data.get("token"))

    def start_device_login(self) -> dict[str, Any]:
        r = self.http.post(
            f"{AUTH_BASE}/oauth/device_authorization",
            data={"client_id": CLIENT_ID, "response_type": "device_code"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code >= 400:
            raise AdGuardError("device_authorization failed", r.status_code, r.text)
        payload = r.json()
        payload["client_id"] = CLIENT_ID
        payload["started_at"] = _iso()
        self.store.save("device_auth.json", payload)
        return payload

    def poll_device_login(self, device_code: str | None = None) -> dict[str, Any] | None:
        if not device_code:
            pending = self.store.load("device_auth.json") or {}
            device_code = pending.get("device_code")
        if not device_code:
            raise AdGuardError("no device_code; start login first")
        r = self.http.post(
            f"{AUTH_BASE}/oauth/token",
            data={
                "grant_type": "device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
            },
            headers={
                "Authorization": f"Basic {BASIC}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code >= 400:
            err = data.get("error") if isinstance(data, dict) else None
            if err in {"authorization_pending", "slow_down"}:
                return None
            raise AdGuardError(err or "oauth token failed", r.status_code, r.text)
        data["saved_at"] = _iso()
        self.store.save("oauth.json", data)
        self.refresh_vpn_token()
        self.refresh_proxy_credentials(force=True)
        return data

    def wait_device_login(self, timeout: int = 1800) -> dict[str, Any]:
        pending = self.store.load("device_auth.json") or {}
        interval = int(pending.get("interval") or 5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.poll_device_login()
            if result:
                return result
            time.sleep(max(interval, 3))
        raise AdGuardError("device login timed out")

    def refresh_vpn_token(self) -> dict[str, Any]:
        oauth = self.store.load("oauth.json") or {}
        access = oauth.get("access_token")
        if not access:
            current = self.store.load("vpn_token.json")
            if current and current.get("token"):
                return current
            raise AdGuardError("oauth access_token missing. Run: python -m adg2mihomo login")
        r = self.http.get(
            f"{API_BASE}/account/api/1.0/products/licenses/vpn.json",
            headers={"Authorization": f"Bearer {access}"},
        )
        if r.status_code >= 400:
            current = self.store.load("vpn_token.json")
            if current and current.get("token"):
                return current
            raise AdGuardError("vpn token request failed", r.status_code, r.text)
        payload = r.json()
        payload["saved_at"] = _iso()
        self.store.save("vpn_token.json", payload)
        return payload

    def refresh_proxy_credentials(self, force: bool = False) -> dict[str, Any]:
        current = self.store.load("proxy_credentials.json") or {}
        result = current.get("result") or {}
        expires = result.get("expires_in_sec")
        saved_at = current.get("saved_at")
        remaining = None
        if expires is not None:
            remaining = int(expires)
            if saved_at:
                try:
                    age = (_now() - datetime.fromisoformat(saved_at)).total_seconds()
                    remaining = int(expires) - int(age)
                except ValueError:
                    remaining = int(expires)
        if (
            not force
            and result.get("username")
            and result.get("credentials")
            and remaining is not None
            and remaining > CRED_REFRESH_SEC
        ):
            return current
        r = self.http.post(
            f"{API_BASE}/api/v1/proxy_credentials",
            params={"app_id": self.app_id(), "token": self.vpn_token()},
        )
        if r.status_code >= 400:
            if result.get("username"):
                return current
            raise AdGuardError("proxy_credentials failed", r.status_code, r.text)
        payload = r.json()
        payload["app_id"] = self.app_id()
        payload["vpn_token"] = self.vpn_token()
        payload["saved_at"] = _iso()
        self.store.save("proxy_credentials.json", payload)
        return payload

    def fetch_locations(self, platform: str = "android", language: str = "zh-CN") -> dict[str, Any]:
        r = self.http.get(
            f"{API_BASE}/api/v2/locations/{platform}",
            params={"app_id": self.app_id(), "token": self.vpn_token(), "language": language},
        )
        if r.status_code >= 400:
            cached = self.store.load("locations_cache.json")
            if cached:
                return cached
            raise AdGuardError("locations request failed", r.status_code, r.text)
        payload = r.json()
        locations, injected = merge_shanghai(list(payload.get("locations") or []))
        payload["locations"] = locations
        payload["shanghai_injected"] = injected
        payload["platform"] = platform
        payload["saved_at"] = _iso()
        self.store.save("locations_cache.json", payload)
        return payload

    def credentials(self) -> tuple[str, str, int | None]:
        payload = self.refresh_proxy_credentials()
        result = payload.get("result") or {}
        username = result.get("username")
        password = result.get("credentials")
        if not username or not password:
            raise AdGuardError("proxy username/password missing")
        remaining = result.get("expires_in_sec")
        saved_at = payload.get("saved_at")
        if remaining is not None and saved_at:
            try:
                age = (_now() - datetime.fromisoformat(saved_at)).total_seconds()
                remaining = max(0, int(remaining) - int(age))
            except ValueError:
                remaining = int(remaining)
        return username, password, remaining

    def snapshot(self, platform: str = "android") -> dict[str, Any]:
        vpn = self.store.load("vpn_token.json") or {}
        tokens = vpn.get("tokens") or []
        primary = next((t for t in tokens if t.get("token") == vpn.get("token")), tokens[0] if tokens else {})
        locations = self.fetch_locations(platform=platform)
        username, password, cred_ttl = self.credentials()
        return {
            "app_id": self.app_id(),
            "license_status": primary.get("license_status") or vpn.get("license_status"),
            "vpn_token_expires_iso": primary.get("time_expires_iso"),
            "vpn_token_expires_sec": primary.get("time_expires_sec"),
            "proxy_credentials_expires_in_sec": cred_ttl,
            "username": username,
            "password": password,
            "locations": locations.get("locations") or [],
            "shanghai_injected": bool(locations.get("shanghai_injected")),
            "platform": platform,
        }

    def public_status(self) -> dict[str, Any]:
        vpn = self.store.load("vpn_token.json") or {}
        creds = self.store.load("proxy_credentials.json") or {}
        cache = self.store.load("locations_cache.json") or {}
        tokens = vpn.get("tokens") or []
        primary = next((t for t in tokens if t.get("token") == vpn.get("token")), tokens[0] if tokens else {})
        remaining = (creds.get("result") or {}).get("expires_in_sec")
        saved_at = creds.get("saved_at")
        if remaining is not None and saved_at:
            try:
                age = (_now() - datetime.fromisoformat(saved_at)).total_seconds()
                remaining = max(0, int(remaining) - int(age))
            except ValueError:
                pass
        return {
            "logged_in": self.logged_in(),
            "license_status": primary.get("license_status"),
            "vpn_token_expires_iso": primary.get("time_expires_iso"),
            "proxy_credentials_expires_in_sec": remaining,
            "app_id": self.app_id() if self.logged_in() else None,
            "locations": len(cache.get("locations") or []),
            "shanghai_injected": bool(cache.get("shanghai_injected")),
        }
