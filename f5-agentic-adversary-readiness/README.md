# F5 Agentic Adversary Readiness

Defensive guidance and a read-only validator for F5 BIG-IP and F5 Distributed Cloud (XC) against AI-driven attack harnesses such as ARTEX.

| Path | What it is |
|---|---|
| `docs/BEST-PRACTICES-GUIDE.md` | The guide: what changed, principles, recommended settings per module, detections, scoring method |
| `docs/CONTROL-CATALOG.md` | All 55 controls with rationale (generated) |
| `controls/` | Machine-readable catalog (`catalog.json`) and its source (`build_catalog.py`) |
| `config/bigip/`, `config/xc/` | Reference configuration: tmsh, declarative WAF policy, iRule, XC object JSON |
| `aar/` | The validator: CLI, scoring engine, report renderers, local web GUI |
| `samples/` | Synthetic snapshots for the demo |
| `tests/` | Unit tests |

## Quick start

Python 3.8 or later. No third-party packages.

```bash
cd f5-agentic-adversary-readiness

python3 -m aar demo                       # synthetic data, writes aar-report/report.html
python3 -m aar gui                        # local web GUI on http://127.0.0.1:8765

# BIG-IP (prompts for the password, or set BIGIP_PASSWORD)
python3 -m aar bigip --host bigip.example.com --user auditor --ca-file mgmt-ca.pem

# Distributed Cloud (prompts for the token, or set XC_API_TOKEN)
python3 -m aar xc --tenant acme-corp --namespace retail --namespace partners

# Collect in one place, assess in another
python3 -m aar bigip --host 10.1.1.245 --user auditor --insecure --save-snapshot bigip.json
python3 -m aar assess bigip.json xc.json --out combined-report

# Pipeline gate
python3 -m aar assess bigip.json --fail-under 70      # exit code 2 below 70
```

Each run writes `report.html` (self-contained, printable), `report.json` and `report.md`.

## What it touches

- **Read-only.** Every call is an HTTP GET, except the BIG-IP token login. Nothing is changed on either platform.
- **BIG-IP account:** the Auditor role is enough for system, LTM, AFM and APM checks. Advanced WAF policy details may need a role with Application Security read access; where a call is refused the control is reported as Unknown instead of failing.
- **XC token:** a monitor-level API token for the namespaces you want assessed.
- **Credentials** are held in memory for the run. They are not written to disk or to the snapshot. The GUI listens on 127.0.0.1 only and rejects requests without its per-run token.
- **Snapshots contain configuration**, including object names and management allow lists. Treat them as sensitive.

## Status and limits

- **Not yet run against a live BIG-IP or XC tenant.** The checks were built from API knowledge and exercised against synthetic snapshots. Expect some field-name mismatches on first contact, especially across TMOS versions; they surface as Unknown results with the reason shown. Run with `--save-snapshot` and adjust the check or open an issue with the redacted snapshot.
- **The configuration under `config/` is reference material.** Validate in a lab before applying anything.
- Checks marked *heuristic* in the report infer from names or optional fields (for example, finding an MFA step in an APM policy). Confirm by hand.
- All HTTP virtual servers are assessed as if internet-facing. Internal-only listeners will pull coverage scores down.
- The score covers the F5 enforcement points. Identity providers, cloud control planes and supplier trust are out of scope; see section 1 of the guide.

## Changing the catalog

Edit `controls/build_catalog.py`, then:

```bash
python3 controls/build_catalog.py
python3 -m aar catalog > docs/CONTROL-CATALOG.md
python3 samples/make_samples.py
python3 -m unittest discover tests
```

A control is one row: ID, platform, module, domain, severity, the behaviors it counters, recommendation, rationale, the check function and its parameters. Thresholds such as minimum TMOS version or password length are parameters, not code.
