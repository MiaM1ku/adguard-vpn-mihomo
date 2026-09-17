from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


LEGACY_MAP = {
    "oauth.json": ".adguard_oauth.json",
    "vpn_token.json": ".adguard_vpn_token.json",
    "proxy_credentials.json": ".adguard_proxy_credentials.json",
    "device_auth.json": ".adguard_device_auth.json",
}


class Store:
    def __init__(self, root: Path | None = None) -> None:
        if root is None:
            env = os.environ.get("ADG2MIHOMO_DATA")
            root = Path(env) if env else Path.cwd() / "data"
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy()

    def _migrate_legacy(self) -> None:
        cwd = Path.cwd()
        for name, legacy in LEGACY_MAP.items():
            dest = self.root / name
            src = cwd / legacy
            if dest.exists() or not src.exists():
                continue
            dest.write_bytes(src.read_bytes())

    def path(self, name: str) -> Path:
        return self.root / name

    def load(self, name: str, default: Any = None) -> Any:
        path = self.path(name)
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, name: str, payload: Any) -> None:
        path = self.path(name)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)

    def exists(self, name: str) -> bool:
        return self.path(name).exists()
