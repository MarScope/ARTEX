import json, os, sys, threading, unittest, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from aar import checks_bigip, checks_xc
from aar.engine import assess, build_report, load_catalog, tier_for
from aar.report import to_html, to_markdown
from aar.gui import make_server


def snap(name):
    with open(os.path.join(ROOT, "samples", name)) as f:
        return json.load(f)


class Catalog(unittest.TestCase):
    def test_every_control_has_a_check_and_unique_id(self):
        cat = load_catalog()
        ids = [c["id"] for c in cat["controls"]]
        self.assertEqual(len(ids), len(set(ids)))
        for c in cat["controls"]:
            mod = checks_bigip if c["platform"] == "bigip" else checks_xc
            self.assertTrue(callable(getattr(mod, c["check"], None)), c["id"])
            self.assertIn(c["domain"], cat["domains"])
            self.assertTrue(set(c["ttps"]) <= set(cat["ttps"]), c["id"])
            self.assertTrue(os.path.exists(os.path.join(ROOT, c["config_ref"])), c["config_ref"])


class Scoring(unittest.TestCase):
    def setUp(self):
        self.b, self.x = assess(snap("bigip-demo-snapshot.json")), assess(snap("xc-demo-snapshot.json"))
        self.by = {r["id"]: r for t in (self.b, self.x) for r in t["results"]}

    def test_expected_findings(self):
        exp = {"BIP-MGT-02": "PASS", "BIP-MGT-03": "FAIL", "BIP-MGT-04": "PARTIAL", "BIP-WAF-02": "PARTIAL",
               "BIP-WAF-04": "PASS", "BIP-AFM-01": "NOT_PROVISIONED", "BIP-LOG-01": "PARTIAL", "BIP-APM-01": "FAIL",
               "XC-WAF-01": "PASS", "XC-RL-01": "PARTIAL", "XC-BOT-01": "PARTIAL", "XC-LOG-01": "FAIL"}
        for k, v in exp.items():
            self.assertEqual(self.by[k]["status"], v, k)

    def test_partial_credit_is_object_fraction(self):
        self.assertAlmostEqual(self.by["BIP-WAF-02"]["score"], 0.5)
        self.assertAlmostEqual(self.by["XC-WAF-02"]["score"], 2 / 3.0)

    def test_access_virtual_excluded_from_waf_coverage(self):
        self.assertIn("2 of 3", self.by["BIP-WAF-01"]["evidence"][0])

    def test_unprovisioned_module_lowers_readiness_not_config_score(self):
        self.assertLess(self.b["readiness"], self.b["configuration_score"])
        self.assertLess(self.b["capability_coverage"], 100)
        self.assertEqual(self.x["capability_coverage"], 100)

    def test_critical_gate(self):
        self.assertIn("BIP-APM-01", self.b["critical_gaps"])
        self.assertEqual(tier_for(92, True), "Exposed")
        self.assertEqual(tier_for(92, False), "Ready")
        self.assertEqual(tier_for(40, True), "Unprepared")

    def test_hardened_snapshot_scores_100(self):
        s = snap("xc-demo-snapshot.json")
        d = s["data"]
        d["http_loadbalancers"] = {"retail/www": d["http_loadbalancers"]["retail/www"]}
        sp = d["http_loadbalancers"]["retail/www"]["spec"]
        sp.pop("disable_api_definition")
        sp.update(api_specification={"api_definition": {"name": "v2"}, "validation_all_spec_endpoints": {}}, jwt_validation={"action": {"block": {}}})
        d["global_log_receivers"]["shared"]["items"] = [{"name": "siem"}]
        t = assess(s)
        self.assertEqual(t["readiness"], 100.0, [(r["id"], r["evidence"]) for r in t["results"] if r["status"] != "PASS"])
        self.assertEqual(t["tier"], "Ready")


class Robustness(unittest.TestCase):
    def test_api_errors_become_unknown_not_fail_or_crash(self):
        s = snap("bigip-demo-snapshot.json")
        for k in list(s["data"]):
            if k.startswith("/mgmt/tm/asm/") or k == "/mgmt/tm/sys/httpd":
                s["data"][k] = {"_error": "HTTP 403"}
        t = assess(s)
        by = {r["id"]: r for r in t["results"]}
        for cid in ("BIP-WAF-02", "BIP-WAF-06", "BIP-MGT-02", "BIP-MGT-07"):
            self.assertEqual(by[cid]["status"], "UNKNOWN", cid)
        self.assertLess(t["assessed_pct"], 100)

    def test_empty_device(self):
        t = assess({"platform": "bigip", "target": "x", "data": {"/mgmt/tm/sys/provision": {"items": []}}})
        self.assertTrue(all(r["status"] in ("UNKNOWN", "NOT_PROVISIONED") for r in t["results"]))

    def test_unexpected_shapes_do_not_raise(self):
        s = snap("xc-demo-snapshot.json")
        s["data"]["http_loadbalancers"]["retail/www"]["spec"]["enable_ip_reputation"] = "yes"
        self.assertEqual(len(assess(s)["results"]), 18)

    def test_reports_render_and_escape(self):
        s = snap("xc-demo-snapshot.json"); s["target"] = "<script>alert(1)</script>"
        rep = build_report([snap("bigip-demo-snapshot.json"), s])
        h = to_html(rep)
        self.assertNotIn("<script>alert(1)", h)
        self.assertIn("Agentic Adversary Readiness Report", h)
        self.assertIn("BIP-MGT-03", to_markdown(rep))


class Gui(unittest.TestCase):
    def test_token_and_host_enforced_and_demo_runs(self):
        srv, token = make_server(0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % port
        try:
            page = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("Run assessment", page)
            def post(tok, host=None):
                h = {"Content-Type": "application/json", "X-AAR-Token": tok}
                if host:
                    h["Host"] = host
                req = urllib.request.Request(base + "/api/assess", data=b'{"demo":true}', headers=h)
                try:
                    r = urllib.request.urlopen(req); return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, {}
            self.assertEqual(post("wrong")[0], 403)
            self.assertEqual(post(token, "evil.example.com")[0], 403)
            code, body = post(token)
            self.assertEqual(code, 200)
            self.assertEqual(len(body["report"]["targets"]), 2)
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
