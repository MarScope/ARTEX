"""BIG-IP checks. Each takes (snapshot_data, params) and returns (score, evidence).

score: 1.0 pass, 0.0 fail, in between partial (usually the fraction of objects compliant),
None when the answer cannot be determined from what was collected.
"""
import datetime, re

V = "/mgmt/tm/ltm/virtual?expandSubcollections=true"


def _items(d, path):
    o = d.get(path)
    if not isinstance(o, dict) or "_error" in o:
        return None
    return o.get("items", []) or []


def _obj(d, path):
    o = d.get(path)
    return None if (not isinstance(o, dict) or "_error" in o) else o


def _err(d, path):
    o = d.get(path)
    return "not collected" if o is None else o.get("_error", "unreadable")


def _ratio(pairs, noun, empty="No %s found, nothing to assess."):
    """pairs: [(name, ok_bool_or_float, note)]."""
    if not pairs:
        return None, [empty % noun if "%s" in empty else empty]
    bad = ["%s: %s" % (n, note) for n, ok, note in pairs if ok < 1]
    score = sum(float(ok) for _, ok, _ in pairs) / len(pairs)
    head = "%d of %d %s compliant." % (sum(1 for _, ok, _ in pairs if ok >= 1), len(pairs), noun)
    return score, [head] + bad[:25] + (["... %d more" % (len(bad) - 25)] if len(bad) > 25 else [])


def _profiles(v):
    return [p.get("fullPath") or ("/Common/" + p.get("name", "")) for p in
            ((v.get("profilesReference") or {}).get("items") or [])]


def _virtuals(d):
    vs = _items(d, V)
    return None if vs is None else [v for v in vs if not v.get("disabled")]


def _http_virtuals(d):
    vs = _virtuals(d)
    if vs is None:
        return None
    http = {p.get("fullPath") for p in (_items(d, "/mgmt/tm/ltm/profile/http") or [])} | {"/Common/http"}
    # APM access virtuals are assessed by the APM controls; WAF/bot coverage is not expected on a VPN listener.
    access = {p.get("fullPath") for p in (_items(d, "/mgmt/tm/apm/profile/access") or [])}
    return [v for v in vs if http & set(_profiles(v)) and not access & set(_profiles(v))]


def _asm_policies(d):
    pols = _items(d, "/mgmt/tm/asm/policies")
    if pols is None:
        return None
    attached = [p for p in pols if p.get("virtualServers")]
    return attached or pols


def _sub(d, pol, sub):
    return d.get("/mgmt/tm/asm/policies/%s/%s" % (pol.get("id"), sub))


def _truthy(v):
    return v is True or str(v).lower() in ("true", "enabled", "yes")


# ------------------------------------------------------------------ management
def bigip_version(d, p):
    o = _obj(d, "/mgmt/tm/sys/version")
    try:
        ent = next(iter(o["entries"].values()))["nestedStats"]["entries"]
        ver = ent["Version"]["description"]
        major = int(ver.split(".")[0])
    except Exception:
        return None, ["Could not read software version."]
    if major >= p["min_major"]:
        return 1.0, ["Running %s." % ver]
    if major >= p["partial_major"]:
        return 0.5, ["Running %s. Supported only if on the current maintenance release; plan the move to %d.x." % (ver, p["min_major"])]
    return 0.0, ["Running %s, below the minimum supported line in this catalog (%d.x)." % (ver, p["partial_major"])]


def _allow(d, path, what):
    o = _obj(d, path)
    if o is None:
        return None, ["%s settings unreadable (%s)." % (what, _err(d, path))]
    allow = o.get("allow")
    if allow is None:
        return 0.0, ["%s allow list is not set, which permits all sources." % what]
    vals = [str(a).lower() for a in (allow if isinstance(allow, list) else [allow])]
    if "all" in vals:
        return 0.0, ["%s allow list is 'All'." % what]
    return 1.0, ["%s restricted to: %s" % (what, ", ".join(vals))]


def bigip_httpd_allow(d, p):
    return _allow(d, "/mgmt/tm/sys/httpd", "httpd")


def bigip_sshd_allow(d, p):
    return _allow(d, "/mgmt/tm/sys/sshd", "sshd")


def bigip_self_lockdown(d, p):
    selfs = _items(d, "/mgmt/tm/net/self")
    if selfs is None:
        return None, ["Self IPs unreadable (%s)." % _err(d, "/mgmt/tm/net/self")]
    pairs = []
    for s in selfs:
        a = s.get("allowService")
        if a == "all" or a == ["all"]:
            pairs.append((s.get("fullPath"), 0, "Allow All"))
        elif a == ["default"] or a == "default":
            pairs.append((s.get("fullPath"), 0.5, "Allow Default (exposes 443/22 on the self IP)"))
        else:
            pairs.append((s.get("fullPath"), 1, ""))
    return _ratio(pairs, "self IPs")


def bigip_password_policy(d, p):
    o = _obj(d, "/mgmt/tm/auth/password-policy")
    if o is None:
        return None, ["Password policy unreadable."]
    checks = [(_truthy(o.get("policyEnforcement")), "policy enforcement is %s" % o.get("policyEnforcement")),
              (int(o.get("minimumLength", 0) or 0) >= p["min_length"], "minimum length is %s (want >= %d)" % (o.get("minimumLength"), p["min_length"])),
              (0 < int(o.get("maxLoginFailures", 0) or 0) <= p["max_failures"], "max login failures is %s (want 1-%d)" % (o.get("maxLoginFailures"), p["max_failures"]))]
    ok = sum(1 for c, _ in checks if c)
    return ok / 3.0, ["%d of 3 settings compliant." % ok] + [m for c, m in checks if not c]


def bigip_remote_syslog(d, p):
    o = _obj(d, "/mgmt/tm/sys/syslog")
    if o is None:
        return None, ["Syslog settings unreadable."]
    rs = o.get("remoteServers") or []
    if rs:
        return 1.0, ["Remote syslog: " + ", ".join("%s:%s" % (r.get("host"), r.get("remotePort", 514)) for r in rs)]
    if "destination" in str(o.get("include") or ""):
        return 1.0, ["Custom syslog-ng include with a destination is present."]
    return 0.0, ["No remote syslog servers configured."]


def bigip_idle_timeout(d, p):
    o = _obj(d, "/mgmt/tm/sys/httpd")
    if o is None or o.get("authPamIdleTimeout") is None:
        return None, ["Idle timeout unreadable."]
    t = int(o["authPamIdleTimeout"])
    return (1.0 if t <= p["max_seconds"] else 0.0), ["auth-pam-idle-timeout is %d s." % t]


# ------------------------------------------------------------------ LTM
def bigip_tls_versions(d, p):
    vs, profs = _virtuals(d), _items(d, "/mgmt/tm/ltm/profile/client-ssl")
    if vs is None or profs is None:
        return None, ["Virtual servers or client SSL profiles unreadable."]
    used = {x for v in vs for x in _profiles(v)}
    pairs = []
    for pr in profs:
        if pr.get("fullPath") not in used:
            continue
        opts = [str(o).lower() for o in (pr.get("tmOptions") or [])]
        ciphers = str(pr.get("ciphers") or "").lower()
        missing = [o for o in ("no-tlsv1", "no-tlsv1.1") if o not in opts]
        if missing and pr.get("cipherGroup") not in (None, "none"):
            pairs.append((pr["fullPath"], 0.5, "protocol options allow TLS 1.0/1.1; cipher group %s may exclude them, verify" % pr.get("cipherGroup")))
        elif missing and not ("!tlsv1:" in ciphers + ":" and "!tlsv1_1" in ciphers):
            pairs.append((pr["fullPath"], 0, "missing options: " + ", ".join(missing)))
        else:
            pairs.append((pr["fullPath"], 1, ""))
    return _ratio(pairs, "client SSL profiles in use")


def bigip_marker_irule(d, p):
    vs = _http_virtuals(d)
    if vs is None:
        return None, ["Virtual servers unreadable."]
    pat = p["name_pattern"].lower()
    def has(v):
        names = list(v.get("rules") or []) + [x.get("fullPath", "") for x in ((v.get("policiesReference") or {}).get("items") or [])]
        return any(pat in n.lower() for n in names)
    return _ratio([(v["fullPath"], 1 if has(v) else 0, "no iRule or LTM policy with '%s' in its name" % pat) for v in vs], "HTTP virtual servers")


# ------------------------------------------------------------------ AWAF
def bigip_waf_coverage(d, p):
    vs, pols = _http_virtuals(d), _items(d, "/mgmt/tm/asm/policies")
    if vs is None or pols is None:
        return None, ["Virtual servers or ASM policies unreadable (%s)." % _err(d, "/mgmt/tm/asm/policies")]
    covered = {x for pol in pols for x in (pol.get("virtualServers") or [])}
    def ok(v):
        return v["fullPath"] in covered or any(x.endswith("/websecurity") for x in _profiles(v))
    return _ratio([(v["fullPath"], 1 if ok(v) else 0, "no security policy") for v in vs], "HTTP virtual servers")


def _per_policy(d, fn, noun="security policies"):
    pols = _asm_policies(d)
    if pols is None:
        return None, ["ASM policies unreadable (%s)." % _err(d, "/mgmt/tm/asm/policies")]
    pairs, unknown = [], []
    for pol in pols:
        r = fn(pol)
        if r is None:
            unknown.append(pol.get("fullPath") or pol.get("name"))
        else:
            pairs.append((pol.get("fullPath") or pol.get("name"),) + r)
    if not pairs:
        return None, (["No security policies exist."] if not pols else ["Setting unreadable on: " + ", ".join(unknown)])
    score, ev = _ratio(pairs, noun)
    return score, ev + (["Unreadable on: " + ", ".join(unknown)] if unknown else [])


def bigip_waf_blocking(d, p):
    return _per_policy(d, lambda pol: (1 if pol.get("enforcementMode") == "blocking" else 0, "enforcement mode is %s" % pol.get("enforcementMode")))


def bigip_waf_staging(d, p):
    def f(pol):
        s = _sub(d, pol, "signature-settings")
        if not isinstance(s, dict) or "_error" in s or "signatureStaging" not in s:
            return None
        return (0, "signature staging is enabled") if _truthy(s["signatureStaging"]) else (1, "")
    return _per_policy(d, f)


def _sub_items(d, pol, sub):
    s = _sub(d, pol, sub)
    return None if (not isinstance(s, dict) or "_error" in s) else (s.get("items") or [])


def bigip_waf_sigsets(d, p):
    def f(pol):
        it = _sub_items(d, pol, "signature-sets")
        if it is None:
            return None
        if not it:
            return 0, "no signature sets assigned"
        return (1, "") if any(_truthy(x.get("block")) for x in it) else (0.5, "signature sets assigned but none has Block enabled")
    return _per_policy(d, f)


def bigip_sig_freshness(d, p):
    path = "/mgmt/tm/live-update/asm-attack-signatures/installations"
    it = _items(d, path)
    if it is None:
        return None, ["Live update status unreadable (%s). Check Security > Security Updates manually." % _err(d, path)]
    stamps = []
    for x in it:
        if str(x.get("status", "")).lower() not in ("install-complete", "installed", "ok", ""):
            continue
        for k in ("loadDateTime", "addDateTime", "createDateTime", "lastUpdateMicros"):
            m = re.match(r"(\d{4}-\d{2}-\d{2})", str(x.get(k) or ""))
            if m:
                stamps.append(m.group(1)); break
    if not stamps:
        return None, ["No completed signature installation with a readable date was found."]
    newest = max(stamps)
    ref = d.get("_collected_at", "")[:10] or datetime.date.today().isoformat()
    age = (datetime.date.fromisoformat(ref) - datetime.date.fromisoformat(newest)).days
    return (1.0 if age <= p["max_age_days"] else 0.0), ["Most recent attack signature install: %s (%d days before collection)." % (newest, age)]


def bigip_waf_bruteforce(d, p):
    def f(pol):
        lp, bf = _sub_items(d, pol, "login-pages"), _sub_items(d, pol, "brute-force-attack-preventions")
        if lp is None or bf is None:
            return None
        if not lp:
            return 0, "no login pages defined, so brute force protection has nothing to protect"
        return (1, "") if bf else (0, "login pages defined but no brute force protection")
    return _per_policy(d, f)


def bigip_waf_session_tracking(d, p):
    def f(pol):
        s = _sub(d, pol, "session-tracking")
        if not isinstance(s, dict) or "_error" in s:
            return None
        cfg = s.get("sessionTrackingConfiguration") or {}
        return (1, "") if _truthy(cfg.get("enableSessionAwareness")) else (0, "session awareness disabled")
    return _per_policy(d, f)


def _enabled_sub(sub, label):
    def check(d, p):
        def f(pol):
            s = _sub(d, pol, sub)
            if not isinstance(s, dict) or "_error" in s or "enabled" not in s:
                return None
            return (1, "") if _truthy(s["enabled"]) else (0, label + " disabled")
        return _per_policy(d, f)
    return check


bigip_waf_dataguard = _enabled_sub("data-guard", "Data Guard")
bigip_waf_ipi = _enabled_sub("ip-intelligence", "IP Intelligence")


def bigip_waf_violation(d, p):
    def f(pol):
        it = _sub_items(d, pol, "blocking-settings/violations")
        if it is None:
            return None
        hits = [x for x in it if any(m in str(x.get("description", "")).lower() for m in p["match"])]
        if not hits:
            return None
        bad = [x.get("description") for x in hits if not _truthy(x.get("block"))]
        return (1, "") if not bad else (1 - len(bad) / float(len(hits)), "not blocking: " + "; ".join(bad))
    return _per_policy(d, f)


def bigip_waf_filetypes(d, p):
    def f(pol):
        it = _sub_items(d, pol, "filetypes")
        if it is None:
            return None
        denied = {str(x.get("name", "")).lower() for x in it if x.get("allowed") is False}
        if any(x.get("name") == "*" and x.get("allowed") is False for x in it):
            return 1, ""
        missing = [r for r in p["required"] if r not in denied]
        return (1, "") if not missing else (1 - len(missing) / float(len(p["required"])), "not disallowed: " + ", ".join(missing))
    return _per_policy(d, f)


def bigip_waf_api_schema(d, p):
    def f(pol):
        oa, js = _sub_items(d, pol, "open-api-files"), _sub_items(d, pol, "json-profiles")
        if oa is None and js is None:
            return None
        if oa:
            return 1, ""
        custom = [x for x in (js or []) if str(x.get("name", "")).lower() != "default"]
        return (0.5, "JSON profiles only, no OpenAPI definition") if custom else (0, "no OpenAPI definition or custom JSON profile (not applicable if this app has no API)")
    return _per_policy(d, f)


# ------------------------------------------------------------------ Bot / DoS
def _coverage(d, coll_path, noun, missing):
    vs, profs = _http_virtuals(d), _items(d, coll_path)
    if vs is None or profs is None:
        return None, ["%s unreadable (%s)." % (noun, _err(d, coll_path))], set()
    names = {x.get("fullPath") for x in profs}
    pairs = [(v["fullPath"], 1 if names & set(_profiles(v)) else 0, missing) for v in vs]
    used = {x for v in vs for x in _profiles(v)} & names
    s, e = _ratio(pairs, "HTTP virtual servers")
    return s, e, used


def bigip_bot_coverage(d, p):
    return _coverage(d, "/mgmt/tm/security/bot-defense/profile", "Bot Defense profiles", "no Bot Defense profile")[:2]


def bigip_bot_field(d, p):
    path = "/mgmt/tm/security/bot-defense/profile"
    profs = _items(d, path)
    if profs is None:
        return None, ["Bot Defense profiles unreadable (%s)." % _err(d, path)]
    used = _coverage(d, path, "", "")[2]
    profs = [x for x in profs if x.get("fullPath") in used]
    if not profs:
        return 0.0, ["No Bot Defense profile is attached to any HTTP virtual server."]
    pairs = []
    for x in profs:
        val = str(x.get(p["field"])).lower()
        ok = (val in p["good"]) if "good" in p else (val not in p["bad"] and x.get(p["field"]) is not None)
        pairs.append((x["fullPath"], 1 if ok else 0, "%s is %s" % (p["field"], x.get(p["field"]))))
    return _ratio(pairs, "attached Bot Defense profiles")


def bigip_dos_coverage(d, p):
    path = "/mgmt/tm/security/dos/profile?expandSubcollections=true"
    vs, profs = _http_virtuals(d), _items(d, path)
    if vs is None or profs is None:
        return None, ["DoS profiles unreadable (%s)." % _err(d, path)]
    quality = {}
    for x in profs:
        apps = ((x.get("applicationReference") or {}).get("items") or x.get("application") or [])
        if not apps:
            quality[x.get("fullPath")] = (0.25, "DoS profile has no application security section")
            continue
        sb = (apps[0].get("stressBased") or {})
        beh = (sb.get("behavioral") or {})
        if sb.get("mode") == "blocking" and _truthy(beh.get("dosDetection")):
            quality[x.get("fullPath")] = (1, "")
        elif _truthy(beh.get("dosDetection")) or sb.get("mode") in ("blocking", "transparent"):
            quality[x.get("fullPath")] = (0.5, "stress-based mode is %s, behavioral detection %s" % (sb.get("mode"), beh.get("dosDetection")))
        else:
            quality[x.get("fullPath")] = (0.25, "application DoS present but stress-based/behavioral detection is off")
    pairs = []
    for v in vs:
        hit = [quality[x] for x in _profiles(v) if x in quality]
        pairs.append((v["fullPath"],) + (max(hit) if hit else (0, "no DoS profile")))
    return _ratio(pairs, "HTTP virtual servers")


# ------------------------------------------------------------------ AFM
def bigip_afm_policy(d, p):
    g = _obj(d, "/mgmt/tm/security/firewall/global-rules")
    if g and g.get("enforcedPolicy"):
        return 1.0, ["Global enforced policy: %s" % g["enforcedPolicy"]]
    vs = _virtuals(d)
    if vs is None:
        return None, ["Virtual servers unreadable."]
    return _ratio([(v["fullPath"], 1 if v.get("fwEnforcedPolicy") else 0, "no enforced firewall policy") for v in vs], "virtual servers")


def bigip_afm_ipi(d, p):
    g = _obj(d, "/mgmt/tm/security/ip-intelligence/global-policy")
    if g and g.get("ipIntelligencePolicy"):
        return 1.0, ["Global IP Intelligence policy: %s" % g["ipIntelligencePolicy"]]
    vs = _virtuals(d)
    if vs is None:
        return None, ["Virtual servers unreadable."]
    return _ratio([(v["fullPath"], 1 if v.get("ipIntelligencePolicy") else 0, "no IP Intelligence policy") for v in vs], "virtual servers")


def bigip_afm_mgmt_rules(d, p):
    path = "/mgmt/tm/security/firewall/management-ip-rules"
    o = _obj(d, path)
    if o is None:
        return None, ["Management IP rules unreadable (%s)." % _err(d, path)]
    rules = (o.get("rulesReference") or {}).get("items") or o.get("rules") or []
    return (1.0, ["%d management-IP rules defined." % len(rules)]) if rules else (0.0, ["No management-IP firewall rules defined."])


def bigip_log_profile_coverage(d, p):
    vs = _http_virtuals(d)
    if vs is None:
        return None, ["Virtual servers unreadable."]
    def ok(v):
        lp = [x for x in (v.get("securityLogProfiles") or []) if "global-network" not in x]
        return 1 if lp else 0
    return _ratio([(v["fullPath"], ok(v), "no security log profile") for v in vs], "HTTP virtual servers")


# ------------------------------------------------------------------ APM
def _access_profiles(d):
    it = _items(d, "/mgmt/tm/apm/profile/access")
    if it is None:
        return None
    # the built-in parent profile is a template, not a deployed policy
    return [x for x in it if x.get("fullPath") != "/Common/access"]


def _per_access(d, fn):
    profs = _access_profiles(d)
    if profs is None:
        return None, ["Access profiles unreadable (%s)." % _err(d, "/mgmt/tm/apm/profile/access")]
    return _ratio([(x.get("fullPath"),) + fn(x) for x in profs], "access profiles")


def bigip_apm_mfa(d, p):
    profs, items = _access_profiles(d), _items(d, "/mgmt/tm/apm/policy/policy-item")
    if profs is None or items is None:
        return None, ["Access policy items unreadable (%s). Review each access policy for a second factor." % _err(d, "/mgmt/tm/apm/policy/policy-item")]
    def f(x):
        prefix = (x.get("fullPath") or "") + "_"
        names = [str(i.get("fullPath") or i.get("name", "")).lower() for i in items if str(i.get("fullPath", "")).startswith(prefix)]
        strong = sorted({m for m in p["markers"] for n in names if m in n[len(prefix):]})
        if not names:
            return 0.5, "no policy items matched this profile by name; review manually"
        return (1, "") if strong else (0, "no second-factor item found by name (heuristic); review manually")
    return _per_access(d, f)


def bigip_apm_session_binding(d, p):
    def f(x):
        keys = ["restrictToSingleClientIp", "secureCookie", "httponlyCookie"]
        bad = [k for k in keys if not _truthy(x.get(k))]
        return 1 - len(bad) / 3.0, "disabled: " + ", ".join(bad)
    return _per_access(d, f)


def bigip_apm_timeouts(d, p):
    def f(x):
        bad = []
        if int(x.get("inactivityTimeout", 0) or 0) > p["max_inactivity"] or not int(x.get("inactivityTimeout", 0) or 0):
            bad.append("inactivity timeout %s s" % x.get("inactivityTimeout"))
        if int(x.get("maxSessionTimeout", 0) or 0) > p["max_session"] or not int(x.get("maxSessionTimeout", 0) or 0):
            bad.append("max session timeout %s s" % x.get("maxSessionTimeout"))
        return 1 - len(bad) / 2.0, "; ".join(bad)
    return _per_access(d, f)


def bigip_apm_inprogress(d, p):
    def f(x):
        n = int(x.get("maxInProgressSessions", 0) or 0)
        return (1, "") if 0 < n <= p["max"] else (0, "max in-progress sessions per client IP is %s" % (n or "unlimited"))
    return _per_access(d, f)


def bigip_apm_per_request(d, p):
    vs, profs = _virtuals(d), _access_profiles(d)
    if vs is None or profs is None:
        return None, ["Virtual servers or access profiles unreadable."]
    names = {x.get("fullPath") for x in profs}
    acc = [v for v in vs if names & set(_profiles(v))]
    return _ratio([(v["fullPath"], 1 if v.get("perFlowRequestAccessPolicy") else 0, "no per-request policy") for v in acc],
                  "access virtual servers")
