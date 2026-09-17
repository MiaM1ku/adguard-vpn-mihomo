from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import __version__
from .client import AdGuardClient, AdGuardError
from .convert import build_proxies, full_config_yaml, nodes_payload, provider_yaml

API_TOKEN = os.environ.get("ADG2MIHOMO_API_TOKEN") or ""


def _client() -> AdGuardClient:
    return AdGuardClient()


def _check_token(authorization: str | None, token: str | None) -> None:
    if not API_TOKEN:
        return
    got = token
    if authorization:
        prefix, _, value = authorization.partition(" ")
        if prefix.lower() in {"bearer", "token"}:
            got = value.strip()
        else:
            got = authorization.strip()
    if got != API_TOKEN:
        raise HTTPException(status_code=401, detail="invalid api token")


def create_app() -> FastAPI:
    app = FastAPI(title="adg2mihomo", version=__version__)

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/")
    def index() -> dict:
        return {
            "name": "adg2mihomo",
            "version": __version__,
            "endpoints": [
                "/health",
                "/status",
                "/proxies.yaml",
                "/mihomo.yaml",
                "/nodes.json",
                "/auth/device/start",
                "/auth/device/poll",
                "/auth/refresh",
            ],
        }

    @app.get("/status")
    def status(
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
    ) -> dict:
        _check_token(authorization, token)
        client = _client()
        try:
            return client.public_status()
        finally:
            client.close()

    def _snapshot(platform: str):
        client = _client()
        try:
            return client.snapshot(platform=platform)
        except AdGuardError as exc:
            raise HTTPException(status_code=exc.status or 500, detail=str(exc)) from exc
        finally:
            client.close()

    @app.get("/proxies.yaml")
    def proxies_yaml(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
        platform: str = Query(default="android"),
        include_relay: bool = Query(default=True),
        only: Optional[str] = Query(default=None),
    ):
        _check_token(authorization, token)
        snap = _snapshot(platform)
        proxies = build_proxies(
            snap["locations"],
            snap["username"],
            snap["password"],
            include_relay=include_relay,
            only=only,
        )
        body = provider_yaml(
            proxies,
            cred_ttl=snap.get("proxy_credentials_expires_in_sec"),
            shanghai_injected=bool(snap.get("shanghai_injected")),
        )
        return PlainTextResponse(body, media_type="text/yaml; charset=utf-8")

    @app.get("/mihomo.yaml")
    def mihomo_yaml(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
        platform: str = Query(default="android"),
        include_relay: bool = Query(default=True),
        inline: bool = Query(default=False),
        only: Optional[str] = Query(default=None),
    ):
        _check_token(authorization, token)
        provider_url = str(request.url_for("proxies_yaml"))
        if only:
            provider_url += ("&" if "?" in provider_url else "?") + f"only={only}"
        if inline:
            snap = _snapshot(platform)
            proxies = build_proxies(
                snap["locations"],
                snap["username"],
                snap["password"],
                include_relay=include_relay,
                only=only,
            )
            body = full_config_yaml(provider_url, api_token=API_TOKEN or None, inline_proxies=proxies)
        else:
            body = full_config_yaml(provider_url, api_token=API_TOKEN or None)
        return PlainTextResponse(body, media_type="text/yaml; charset=utf-8")

    @app.get("/nodes.json")
    def nodes_json(
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
        platform: str = Query(default="android"),
        include_relay: bool = Query(default=True),
    ):
        _check_token(authorization, token)
        snap = _snapshot(platform)
        return JSONResponse(nodes_payload(snap["locations"], include_relay=include_relay))

    @app.post("/auth/device/start")
    def auth_start(
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
    ):
        _check_token(authorization, token)
        client = _client()
        try:
            payload = client.start_device_login()
        except AdGuardError as exc:
            raise HTTPException(status_code=exc.status or 500, detail=str(exc)) from exc
        finally:
            client.close()
        return {
            "user_code": payload.get("user_code"),
            "verification_uri": payload.get("verification_uri"),
            "verification_uri_complete": payload.get("verification_uri_complete"),
            "expires_in": payload.get("expires_in"),
            "interval": payload.get("interval"),
        }

    @app.post("/auth/device/poll")
    def auth_poll(
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
    ):
        _check_token(authorization, token)
        client = _client()
        try:
            result = client.poll_device_login()
        except AdGuardError as exc:
            raise HTTPException(status_code=exc.status or 500, detail=str(exc)) from exc
        finally:
            client.close()
        if result is None:
            return {"status": "pending"}
        return {"status": "ok", "logged_in": True}

    @app.post("/auth/refresh")
    def auth_refresh(
        authorization: Optional[str] = Header(default=None),
        token: Optional[str] = Query(default=None),
    ):
        _check_token(authorization, token)
        client = _client()
        try:
            client.refresh_vpn_token()
            client.refresh_proxy_credentials(force=True)
            client.fetch_locations()
            return client.public_status()
        except AdGuardError as exc:
            raise HTTPException(status_code=exc.status or 500, detail=str(exc)) from exc
        finally:
            client.close()

    return app


app = create_app()
