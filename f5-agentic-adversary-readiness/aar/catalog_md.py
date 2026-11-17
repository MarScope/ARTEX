"""Render the catalog as a Markdown reference (docs/CONTROL-CATALOG.md is generated from this)."""
PLAT = {"bigip": "BIG-IP", "xc": "F5 Distributed Cloud"}


def render(cat):
    out = ["# Control catalog", "", "Generated from `controls/catalog.json` (version %s) with `python -m aar catalog`. Do not edit by hand." % cat["version"], "",
           "Weights: " + ", ".join("%s %d" % kv for kv in cat["severity_weight"].items()) + ".", "", "## Adversary behaviors referenced", "",
           "| Tag | Behavior |", "|---|---|"]
    out += ["| %s | %s |" % kv for kv in cat["ttps"].items()]
    for plat in ("bigip", "xc"):
        out += ["", "## %s" % PLAT[plat], ""]
        for c in [c for c in cat["controls"] if c["platform"] == plat]:
            out += ["### %s: %s" % (c["id"], c["title"]), "",
                    "- Module: `%s` | Domain: %s | Severity: %s | Check confidence: %s" % (c["module"], cat["domains"][c["domain"]], c["severity"], c["confidence"]),
                    "- Counters: %s" % ", ".join(c["ttps"]),
                    "- Recommendation: %s" % c["recommendation"],
                    "- Why: %s" % c["rationale"],
                    "- Reference config: `%s`" % c["config_ref"]]
            if c.get("params"):
                out.append("- Tunable parameters: `%s`" % c["params"])
            out.append("")
    return "\n".join(out)
