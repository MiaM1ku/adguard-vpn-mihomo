import unittest

from adg2mihomo.convert import build_proxies, provider_yaml
from adg2mihomo.shanghai import SHANGHAI_LOCATION, merge_shanghai


class ConvertTests(unittest.TestCase):
    def test_merge_inserts_shanghai_first(self):
        locations, injected = merge_shanghai(
            [{"id": "hk", "country_code": "HK", "city_name": "香港", "endpoints": []}]
        )
        self.assertTrue(injected)
        self.assertEqual(locations[0]["id"], SHANGHAI_LOCATION["id"])
        self.assertEqual(locations[0]["endpoints"][0]["domain_name"], "superbaby.tv")

    def test_merge_overrides_api_shanghai(self):
        locations, injected = merge_shanghai(
            [
                {
                    "id": "Y25fc2hhbmdoYWk=",
                    "country_code": "CN",
                    "city_name": "上海市",
                    "endpoints": [{"domain_name": "m9009-cn-sha-01-fake.adguard.io", "ipv4_address": "1.2.3.4"}],
                }
            ]
        )
        self.assertTrue(injected)
        self.assertEqual(locations[0]["endpoints"][0]["ipv4_address"], "213.182.218.34")
        self.assertEqual(locations[0]["endpoints"][0]["remote_identifier"], "singlecustom.live")

    def test_build_shanghai_proxy(self):
        locations, _ = merge_shanghai([])
        proxies = build_proxies(locations, "user", "pass", include_relay=True)
        self.assertGreaterEqual(len(proxies), 2)
        sh = proxies[0]
        self.assertEqual(sh["type"], "trusttunnel")
        self.assertEqual(sh["server"], "213.182.218.34")
        self.assertEqual(sh["sni"], "superbaby.tv")
        self.assertEqual(sh["name-cert-verify"], "singlecustom.live")
        self.assertTrue(sh["name"].startswith("🇨🇳 CN-上海"))
        self.assertEqual(proxies[1]["server"], "157.254.131.80")
        yaml_text = provider_yaml(proxies, shanghai_injected=True)
        self.assertIn("type: trusttunnel", yaml_text)
        self.assertIn("superbaby.tv", yaml_text)


if __name__ == "__main__":
    unittest.main()
