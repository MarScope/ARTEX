"""Report renderers: self-contained HTML, Markdown, JSON."""
import html, json

E = lambda s: html.escape(str(s), quote=True)
ICON = {"PASS": ("✓", "Pass", "good"), "PARTIAL": ("◐", "Partial", "warn"), "FAIL": ("✕", "Fail", "crit"),
        "UNKNOWN": ("?", "Unknown", "mute"), "NOT_PROVISIONED": ("⊘", "Not provisioned", "crit")}
PLAT = {"bigip": "BIG-IP", "xc": "Distributed Cloud"}
ORDER = {"FAIL": 0, "NOT_PROVISIONED": 1, "PARTIAL": 2, "UNKNOWN": 3, "PASS": 4}

CSS = """
:root{--bg:#fcfcfb;--panel:#fff;--ink:#0b0b0b;--ink2:#52514e;--mute:#898781;--line:#e4e3df;--bar:#2f6fde;--track:#ecebe7;
--good:#0ca30c;--warn:#fab219;--crit:#d03b3b}
@media(prefers-color-scheme:dark){:root{--bg:#1a1a19;--panel:#232322;--ink:#f0efec;--ink2:#c3c2b7;--line:#3a3a37;--bar:#6b9bf0;--track:#30302e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 20px 60px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:34px 0 10px}
h3{font-size:14px;margin:0 0 8px}.sub{color:var(--ink2);margin:0}.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin-top:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.big{font-size:44px;font-weight:650;line-height:1.1}
.unit{font-size:16px;color:var(--mute);font-weight:400}.lab{color:var(--ink2);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.dot{display:inline-block;width:1.5em;height:1.5em;line-height:1.5em;text-align:center;border-radius:50%;color:#fff;font-size:11px;font-weight:700;margin-right:6px}
.good{background:var(--good)}.warn{background:var(--warn);color:#0b0b0b}.crit{background:var(--crit)}.mute{background:var(--mute)}
.row{display:grid;grid-template-columns:230px 1fr 110px;gap:12px;align-items:center;padding:5px 0}
.track{background:var(--track);border-radius:4px;height:10px;overflow:hidden}.fill{background:var(--bar);height:10px;border-radius:0 4px 4px 0}
.num{text-align:right;font-variant-numeric:tabular-nums;color:var(--ink2)}
table{width:100%;border-collapse:collapse}th{text-align:left;font-size:12px;color:var(--ink2);font-weight:600;border-bottom:1px solid var(--line);padding:6px 8px}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}td.st,td code{white-space:nowrap}code{font:12px ui-monospace,Menlo,Consolas,monospace}
details summary{cursor:pointer;font-weight:550}details div{color:var(--ink2);margin-top:6px}ul{margin:4px 0 4px 18px;padding:0}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}.filters button{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:16px;padding:4px 12px;cursor:pointer;font:inherit}
.filters button[aria-pressed=true]{border-color:var(--ink);font-weight:600}.note{color:var(--ink2);font-size:13px}.gap{border-left:3px solid var(--crit);padding-left:12px}
@media(max-width:640px){.row{grid-template-columns:1fr 70px}.row .track{grid-column:1/-1;order:3}}
@media print{.filters{display:none}details div{display:block}}
"""
JS = """
document.querySelectorAll('.filters').forEach(function(f){f.addEventListener('click',function(e){var b=e.target.closest('button');if(!b)return;
f.querySelectorAll('button').forEach(function(x){x.setAttribute('aria-pressed',x===b)});var want=b.dataset.f;
f.parentNode.querySelectorAll('tbody tr').forEach(function(r){r.hidden=!(want==='all'||(want==='open'?r.dataset.s!=='PASS':r.dataset.s===want))})})});
"""


def _fmt(v, suffix="%"):
    return "n/a" if v is None else ("%g%s" % (v, suffix))


def _chip(status):
    ic, label, cls = ICON[status]
    return '<span class="dot %s" aria-hidden="true">%s</span>%s' % (cls, ic, label)


def _tiles(s, title):
    gate = ""
    if s["critical_gaps"]:
        gate = '<p class="note gap">Critical controls failing (tier cannot rise above <b>Exposed</b> until these are fixed): %s</p>' % E(", ".join(s["critical_gaps"]))
    c = s["counts"]
    return """<div class="grid">
<div class="card"><div class="lab">%s readiness</div><div class="big">%s<span class="unit"> / 100</span></div><div><b>%s</b></div></div>
<div class="card"><div class="lab">Configuration score</div><div class="big">%s</div><div class="note">Provisioned capabilities only</div></div>
<div class="card"><div class="lab">Capability coverage</div><div class="big">%s</div><div class="note">Catalog weight available on what is provisioned</div></div>
<div class="card"><div class="lab">Controls</div><div>%s %d<br>%s %d<br>%s %d<br>%s %d<br>%s %d</div></div>
</div>%s""" % (E(title), _fmt(s["readiness"], ""), E(s["tier"]), _fmt(s["configuration_score"]), _fmt(s["capability_coverage"]),
               _chip("PASS"), c.get("PASS", 0), _chip("PARTIAL"), c.get("PARTIAL", 0), _chip("FAIL"), c.get("FAIL", 0),
               _chip("NOT_PROVISIONED"), c.get("NOT_PROVISIONED", 0), _chip("UNKNOWN"), c.get("UNKNOWN", 0), gate)


def _domains(s):
    rows = []
    for d in s["domains"]:
        v = d["score"]
        rows.append('<div class="row" title="%s: %s, %d of %d controls with gaps"><div>%s</div><div class="track"><div class="fill" style="width:%s%%"></div></div>'
                    '<div class="num">%s &middot; %d open</div></div>' % (E(d["label"]), _fmt(v), d["failing"], d["controls"], E(d["label"]),
                                                                        0 if v is None else v, _fmt(v), d["failing"]))
    return '<div class="card"><h3>Readiness by defensive domain</h3>%s</div>' % "".join(rows)


def _table(t, ttps):
    rows = []
    for r in sorted(t["results"], key=lambda r: (ORDER[r["status"]], -r["weight"], r["id"])):
        ev = "".join("<li>%s</li>" % E(x) for x in r["evidence"])
        tt = "".join("<li><b>%s</b> %s</li>" % (E(k), E(ttps.get(k, ""))) for k in r["ttps"])
        heur = ' <span class="note">(heuristic check, verify manually)</span>' if r["confidence"] == "heuristic" else ""
        rows.append('<tr data-s="%s"><td class="st">%s</td><td><code>%s</code></td><td><details><summary>%s</summary><div>'
                    '<b>Evidence</b>%s<ul>%s</ul><b>Recommendation</b><p>%s</p><b>Why it matters against agentic adversaries</b><p>%s</p>'
                    '<ul>%s</ul><p>Reference config: <code>%s</code></p></div></details></td><td>%s</td></tr>'
                    % (r["status"], _chip(r["status"]), E(r["id"]), E(r["title"]), heur, ev, E(r["recommendation"]), E(r["rationale"]),
                       tt, E(r["config_ref"]), E(r["severity"].capitalize())))
    return """<div class="filters" role="group" aria-label="Filter controls"><button data-f="open" aria-pressed="true">Gaps</button>
<button data-f="all" aria-pressed="false">All</button><button data-f="FAIL" aria-pressed="false">Fail</button>
<button data-f="PARTIAL" aria-pressed="false">Partial</button><button data-f="UNKNOWN" aria-pressed="false">Unknown</button>
<button data-f="PASS" aria-pressed="false">Pass</button></div>
<table><thead><tr><th>Status</th><th>Control</th><th>Finding (expand for evidence and fix)</th><th>Severity</th></tr></thead><tbody>%s</tbody></table>""" % "".join(
        r if 'data-s="PASS"' not in r else r.replace("<tr ", "<tr hidden ", 1) for r in rows)


def to_html(rep):
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
             '<title>Agentic Adversary Readiness Report</title><style>%s</style></head><body><main>' % CSS,
             '<h1>Agentic Adversary Readiness Report</h1><p class="sub">F5 BIG-IP and Distributed Cloud &middot; generated %s &middot; catalog %s &middot; tool %s</p>'
             % (E(rep["generated_at"]), E(rep["catalog_version"]), E(rep["tool_version"]))]
    if len(rep["targets"]) > 1:
        parts.append(_tiles(rep["overall"], "Overall"))
    for t in rep["targets"]:
        parts.append("<h2>%s &middot; %s</h2><p class='sub'>Collected %s%s</p>" % (
            E(PLAT[t["platform"]]), E(t["target"]), E(t["collected_at"]),
            (" &middot; provisioned: " + E(", ".join(m for m in t["modules"] if m not in ("base",)))) if t["modules"] else ""))
        parts.append(_tiles(t, PLAT[t["platform"]]))
        parts.append('<div style="margin-top:14px">%s</div>' % _domains(t))
        parts.append('<div class="card" style="margin-top:14px"><h3>Controls</h3>%s</div>' % _table(t, rep["ttps"]))
    parts.append("""<h2>How to read this</h2><div class="card note"><p><b>Readiness</b> is the weighted share of catalog controls that are in place
(critical 10, high 6, medium 3, low 1; partial credit by fraction of objects compliant). Controls that depend on a module that is not provisioned
score zero, because an agent does not care why a control is missing. <b>Configuration score</b> counts only what the platform can do today,
so the difference between the two is the licensing or provisioning gap. Unknown controls are excluded from both and listed for manual review.</p>
<p>This score covers the F5 enforcement points only. Reported agentic intrusions also work through identity providers, cloud control planes and
supplier trust, none of which this tool can see. A high score here is necessary, not sufficient.</p></div><script>%s</script></main></body></html>""" % JS)
    return "".join(parts)


def to_markdown(rep):
    out = ["# Agentic Adversary Readiness Report", "", "Generated %s, catalog %s." % (rep["generated_at"], rep["catalog_version"]), ""]
    for t in rep["targets"]:
        out += ["## %s: %s" % (PLAT[t["platform"]], t["target"]), "",
                "- Readiness: **%s / 100** (%s)" % (_fmt(t["readiness"], ""), t["tier"]),
                "- Configuration score: %s" % _fmt(t["configuration_score"]),
                "- Capability coverage: %s" % _fmt(t["capability_coverage"]),
                "- Critical gaps: %s" % (", ".join(t["critical_gaps"]) or "none"), "",
                "| Domain | Score | Controls with gaps |", "|---|---|---|"]
        out += ["| %s | %s | %d of %d |" % (d["label"], _fmt(d["score"]), d["failing"], d["controls"]) for d in t["domains"]]
        out += ["", "| Status | ID | Severity | Control | Evidence |", "|---|---|---|---|---|"]
        for r in sorted(t["results"], key=lambda r: (ORDER[r["status"]], -r["weight"], r["id"])):
            out.append("| %s | %s | %s | %s | %s |" % (ICON[r["status"]][1], r["id"], r["severity"], r["title"],
                                                      " ".join(r["evidence"][:4]).replace("|", "/")))
        out.append("")
    return "\n".join(out)


def to_json(rep):
    return json.dumps(rep, indent=1)
