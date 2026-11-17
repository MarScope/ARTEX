"""Catalog loading, check dispatch and scoring."""
import datetime, json, os
from . import checks_bigip, checks_xc, __version__
from .clients import provisioned

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(os.path.dirname(HERE), "controls", "catalog.json")
ALWAYS = {"base", "ltm"}
TIERS = [(85, "Ready"), (70, "Mostly ready"), (50, "Exposed"), (0, "Unprepared")]


def load_catalog(path=None):
    with open(path or CATALOG) as f:
        return json.load(f)


def _status(score):
    if score is None:
        return "UNKNOWN"
    return "PASS" if score >= 0.999 else ("FAIL" if score <= 0.001 else "PARTIAL")


def _pct(num, den):
    return round(100.0 * num / den, 1) if den else None


def tier_for(score, gated):
    if score is None:
        return "Not assessed"
    name = next(n for floor, n in TIERS if score >= floor)
    if gated and name in ("Ready", "Mostly ready"):
        return "Exposed"
    return name


def assess(snapshot, catalog=None):
    """Run every catalog control for the snapshot's platform. Returns one target report."""
    catalog = catalog or load_catalog()
    plat, data = snapshot["platform"], dict(snapshot["data"])
    data["_collected_at"] = snapshot.get("collected_at", "")
    mods = provisioned(data) | ALWAYS if plat == "bigip" else None
    results = []
    for c in catalog["controls"]:
        if c["platform"] != plat:
            continue
        r = {k: c[k] for k in ("id", "module", "domain", "severity", "weight", "confidence", "ttps", "title",
                                "recommendation", "rationale", "config_ref")}
        if mods is not None and not (set(c["module"].split("|")) & mods):
            r.update(status="NOT_PROVISIONED", score=0.0,
                     evidence=["Module %s is not provisioned on this device, so this control is not available." % c["module"].replace("|", " or ")])
        else:
            fn = getattr(checks_bigip if plat == "bigip" else checks_xc, c["check"])
            try:
                score, ev = fn(data, c.get("params") or {})
            except Exception as e:  # a schema surprise must not sink the whole run
                score, ev = None, ["Check could not be evaluated (%s: %s)." % (type(e).__name__, e)]
            r.update(status=_status(score), score=score, evidence=ev)
        results.append(r)
    return {"platform": plat, "target": snapshot.get("target", "?"), "collected_at": snapshot.get("collected_at", ""),
            "modules": sorted(mods) if mods else None, "results": results, **summarize(results, catalog)}


def summarize(results, catalog):
    known = [r for r in results if r["status"] != "UNKNOWN"]
    avail = [r for r in known if r["status"] != "NOT_PROVISIONED"]
    w = lambda rs: sum(r["weight"] for r in rs)
    got = lambda rs: sum(r["weight"] * r["score"] for r in rs)
    readiness = _pct(got(known), w(known))
    gates = [r["id"] for r in known if r["severity"] == "critical" and r["score"] < 0.5]
    domains = []
    for key, label in catalog["domains"].items():
        rs = [r for r in known if r["domain"] == key]
        if rs or any(r["domain"] == key for r in results):
            domains.append({"key": key, "label": label, "score": _pct(got(rs), w(rs)), "controls": len(rs),
                            "failing": sum(1 for r in rs if r["score"] < 0.999)})
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"readiness": readiness, "configuration_score": _pct(got(avail), w(avail)),
            "capability_coverage": _pct(w(avail), w(known)), "assessed_pct": _pct(w(known), w(results)),
            "tier": tier_for(readiness, bool(gates)), "critical_gaps": gates, "domains": domains, "counts": counts}


def build_report(snapshots, catalog=None):
    catalog = catalog or load_catalog()
    targets = [assess(s, catalog) for s in snapshots]
    allr = [r for t in targets for r in t["results"]]
    return {"tool_version": __version__, "catalog_version": catalog["version"],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ttps": catalog["ttps"], "overall": summarize(allr, catalog), "targets": targets}
