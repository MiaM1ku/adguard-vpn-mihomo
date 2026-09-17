"""China Shanghai is geo-filtered from the public locations API.

The Android app still receives `cn_shanghai` (base64 `Y25fc2hhbmdoYWk=`)
when the client public IP is in CN. The working TrustTunnel profile uses
a camouflage SNI (`superbaby.tv`) while the certificate CN is
`singlecustom.live`. The entry IP is Datacamp Hong Kong; the advertised
city is virtual.
"""

from __future__ import annotations

SHANGHAI_ID = "Y25fc2hhbmdoYWk="
SHANGHAI_ID_PLAIN = "cn_shanghai"

SHANGHAI_LOCATION = {
    "id": SHANGHAI_ID,
    "country_name": "中国",
    "country_code": "CN",
    "city_name": "上海",
    "premium_only": True,
    "latitude": 31.2304,
    "longitude": 121.4737,
    "ping_bonus": 0,
    "virtual": True,
    "injected": True,
    "skip_virtual_label": True,
    "endpoints": [
        {
            "domain_name": "superbaby.tv",
            "server_name": "superbaby.tv",
            "remote_identifier": "singlecustom.live",
            "ipv4_address": "213.182.218.34",
            "alt_ipv4_address": None,
            "ipv6_address": None,
            "premium_only": True,
        }
    ],
    "relay_endpoints": [
        {
            "domain_name": "superbaby.tv",
            "server_name": "superbaby.tv",
            "remote_identifier": "singlecustom.live",
            "ipv4_address": "157.254.131.80",
            "alt_ipv4_address": None,
            "ipv6_address": None,
            "premium_only": True,
        }
    ],
}


def _is_shanghai(loc: dict) -> bool:
    loc_id = str(loc.get("id") or "")
    city = str(loc.get("city_name") or "")
    country = str(loc.get("country_code") or "").upper()
    return loc_id in {SHANGHAI_ID, SHANGHAI_ID_PLAIN} or (
        country == "CN" and ("上海" in city or city.lower() == "shanghai")
    )


def merge_shanghai(locations: list[dict]) -> tuple[list[dict], bool]:
    """Force the Android Shanghai camouflage profile onto the location list."""
    injected = False
    out: list[dict] = []
    seen = False
    for loc in locations:
        if _is_shanghai(loc):
            seen = True
            merged = {**loc, **SHANGHAI_LOCATION}
            merged["endpoints"] = SHANGHAI_LOCATION["endpoints"]
            merged["relay_endpoints"] = SHANGHAI_LOCATION["relay_endpoints"]
            out.append(merged)
            injected = True
        else:
            out.append(loc)
    if not seen:
        out = [dict(SHANGHAI_LOCATION), *out]
        injected = True
    return out, injected
