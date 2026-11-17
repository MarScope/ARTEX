"""Command line entry point:  python -m aar <command>"""
import argparse, getpass, json, os, sys
from . import __version__
from .clients import CollectError, collect_bigip, collect_xc
from .engine import build_report, load_catalog
from .report import to_html, to_json, to_markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = [os.path.join(ROOT, "samples", n) for n in ("bigip-demo-snapshot.json", "xc-demo-snapshot.json")]


def _secret(env, prompt):
    return os.environ.get(env) or getpass.getpass(prompt)


def _write(rep, out, quiet=False):
    os.makedirs(out, exist_ok=True)
    for name, fn in (("report.html", to_html), ("report.json", to_json), ("report.md", to_markdown)):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(fn(rep))
    if not quiet:
        for t in rep["targets"]:
            print("%-18s %-40s readiness %s/100  [%s]  config %s%%  coverage %s%%" % (
                t["platform"], t["target"], t["readiness"], t["tier"], t["configuration_score"], t["capability_coverage"]))
            if t["critical_gaps"]:
                print("  critical gaps: " + ", ".join(t["critical_gaps"]))
        print("Reports written to %s (report.html, report.json, report.md)" % os.path.abspath(out))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aar", description="F5 Agentic Adversary Readiness validator (read-only).")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    def common(p):
        p.add_argument("--out", default="aar-report", help="output directory (default: aar-report)")
        p.add_argument("--save-snapshot", metavar="FILE", help="also save the raw collected configuration")
        p.add_argument("--fail-under", type=float, metavar="N", help="exit 2 if readiness is below N")
        p.add_argument("-v", "--verbose", action="store_true")
    b = sub.add_parser("bigip", help="collect from a BIG-IP and assess"); common(b)
    b.add_argument("--host", required=True); b.add_argument("--user", required=True)
    b.add_argument("--ca-file", help="CA bundle for the management certificate")
    b.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed management cert)")
    x = sub.add_parser("xc", help="collect from a Distributed Cloud tenant and assess"); common(x)
    x.add_argument("--tenant", required=True, help="tenant name or full console hostname")
    x.add_argument("--namespace", action="append", help="namespace to assess (repeatable; default all application namespaces)")
    a = sub.add_parser("assess", help="assess previously saved snapshot files (offline)"); common(a)
    a.add_argument("snapshots", nargs="+")
    d = sub.add_parser("demo", help="assess the bundled sample snapshots"); common(d)
    g = sub.add_parser("gui", help="start the local web GUI")
    g.add_argument("--port", type=int, default=8765); g.add_argument("--no-browser", action="store_true")
    c = sub.add_parser("catalog", help="print the control catalog as Markdown")
    args = ap.parse_args(argv)

    if args.cmd == "gui":
        from .gui import serve
        return serve(args.port, not args.no_browser)
    if args.cmd == "catalog":
        from .catalog_md import render
        print(render(load_catalog())); return 0
    prog = (lambda m: print("  " + m, file=sys.stderr)) if args.verbose else (lambda m: None)
    try:
        if args.cmd == "bigip":
            snaps = [collect_bigip(args.host, args.user, _secret("BIGIP_PASSWORD", "BIG-IP password: "),
                                   verify=not args.insecure, ca_file=args.ca_file, progress=prog)]
        elif args.cmd == "xc":
            snaps = [collect_xc(args.tenant, _secret("XC_API_TOKEN", "XC API token: "), args.namespace, progress=prog)]
        else:
            snaps = []
            for p in (SAMPLES if args.cmd == "demo" else args.snapshots):
                with open(p) as f:
                    snaps.append(json.load(f))
    except CollectError as e:
        print("error: %s" % e, file=sys.stderr); return 1
    if args.save_snapshot:
        with open(args.save_snapshot, "w") as f:
            json.dump(snaps[0] if len(snaps) == 1 else snaps, f, indent=1)
    snaps = [s for x in snaps for s in (x if isinstance(x, list) else [x])]
    rep = build_report(snaps)
    _write(rep, args.out)
    worst = min((t["readiness"] for t in rep["targets"] if t["readiness"] is not None), default=0)
    return 2 if (args.fail_under is not None and worst < args.fail_under) else 0


if __name__ == "__main__":
    sys.exit(main())
