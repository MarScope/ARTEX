"""F5 Distributed Cloud checks. Same contract as checks_bigip: (data, params) -> (score, evidence)."""
from .checks_bigip import _ratio


def _spec(o):
    if not isinstance(o, dict) or "_error" in o:
        return None
    return o.get("spec") or o.get("get_spec") or {}


def _lbs(d):
    return [(k, _spec(v)) for k, v in sorted((d.get("http_loadbalancers") or {}).items()) if _spec(v) is not None]


def _per_lb(d, fn):
    lbs = _lbs(d)
    if not lbs:
        return None, ["No HTTP load balancers were readable in the selected namespaces."]
    pairs, unknown = [], []
    for k, s in lbs:
        r = fn(k, s)
        (unknown.append(k) if r is None else pairs.append((k,) + r))
    if not pairs:
        return None, ["Could not determine on: " + ", ".join(unknown)]
    score, ev = _ratio(pairs, "HTTP load balancers")
    return score, ev + (["Could not determine on: " + ", ".join(unknown)] if unknown else [])


def _fw(d, key, s):
    ref = s.get("app_firewall") or {}
    if not ref.get("name"):
        return None
    ns = ref.get("namespace") or key.split("/")[0]
    return _spec((d.get("app_firewalls") or {}).get("%s/%s" % (ns, ref["name"])))


def xc_waf_attached(d, p):
    return _per_lb(d, lambda k, s: (1, "") if (s.get("app_firewall") or {}).get("name") else (0, "WAF disabled"))


def _per_fw(d, fn):
    def f(k, s):
        if not (s.get("app_firewall") or {}).get("name"):
            return 0, "no App Firewall attached"
        fw = _fw(d, k, s)
        return None if fw is None else fn(fw)
    return _per_lb(d, f)


def xc_waf_blocking(d, p):
    def f(fw):
        if "blocking" in fw:
            return 1, ""
        if "monitoring" in fw:
            return 0, "App Firewall is in monitoring mode"
        return None
    return _per_fw(d, f)


def xc_waf_detection(d, p):
    def f(fw):
        if "default_detection_settings" in fw or "detection_settings" not in fw:
            return 1, ""
        ds = fw["detection_settings"] or {}
        bad = []
        if "disable_threat_campaigns" in ds:
            bad.append("Threat Campaigns disabled")
        if "only_high_accuracy_signatures" in (ds.get("signature_selection_setting") or {}):
            bad.append("only high-accuracy signatures selected")
        return 1 - len(bad) / 2.0, "; ".join(bad)
    return _per_fw(d, f)


def xc_waf_bot_setting(d, p):
    def f(fw):
        bp = fw.get("bot_protection_setting") or (fw.get("detection_settings") or {}).get("bot_protection_setting")
        if bp is None:
            return 1, ""  # default bot setting blocks malicious bots
        if bp.get("malicious_bot_action") != "BLOCK":
            return 0, "malicious bot action is %s" % bp.get("malicious_bot_action")
        if bp.get("suspicious_bot_action") in ("IGNORE", None):
            return 0.5, "suspicious bot action is %s" % bp.get("suspicious_bot_action")
        return 1, ""
    return _per_fw(d, f)


def xc_bot_defense(d, p):
    def f(k, s):
        if "bot_defense" in s or "bot_defense_advanced" in s:
            return 1, ""
        for c in ("policy_based_challenge", "js_challenge", "captcha_challenge"):
            if c in s:
                return 0.5, "no Bot Defense; %s configured as a partial substitute" % c
        return 0, "no Bot Defense and no client challenge"
    return _per_lb(d, f)


def xc_malicious_user(d, p):
    def f(k, s):
        if "enable_malicious_user_detection" not in s:
            return 0, "Malicious User Detection disabled"
        if "enable_challenge" in s or "policy_based_challenge" in s:
            return 1, ""
        return 0.5, "detection enabled but no malicious user mitigation challenge, so nothing acts on the score"
    return _per_lb(d, f)


def xc_rate_limit(d, p):
    return _per_lb(d, lambda k, s: (1, "") if ("rate_limit" in s or "api_rate_limit" in s) else (0, "no rate limiting"))


def xc_ip_reputation(d, p):
    def f(k, s):
        rep = s.get("enable_ip_reputation")
        if rep is None:
            return 0, "IP Reputation disabled"
        cats = rep.get("ip_threat_categories") or []
        missing = [c for c in p["required"] if c not in cats]
        return (1, "") if not missing else (0.5, "categories not selected: " + ", ".join(missing))
    return _per_lb(d, f)


def xc_flag(d, p):
    def f(k, s):
        if any(x in s for x in p["on"]):
            return 1, ""
        return 0, ("explicitly disabled" if any(x in s for x in p["off"]) else "not enabled")
    return _per_lb(d, f)


def xc_l7_ddos(d, p):
    def f(k, s):
        prot = s.get("l7_ddos_protection") or {}
        if "l7_ddos_action_none" in s or "mitigation_none" in prot:
            return 0, "L7 DDoS auto-mitigation set to none"
        keys = [x for x in list(s) + list(prot) if x.startswith(("l7_ddos_action", "mitigation_", "enable_ddos_detection"))]
        return (1, "") if keys else None
    return _per_lb(d, f)


def xc_api_definition(d, p):
    def f(k, s):
        spec = s.get("api_specification") or {}
        if not (spec.get("api_definition") or {}).get("name"):
            return 0, "no API definition attached (not applicable if this load balancer serves no API)"
        if "validation_disabled" in spec:
            return 0.5, "API definition attached but validation is disabled"
        return 1, ""
    return _per_lb(d, f)


def xc_api_authz(d, p):
    def f(k, s):
        rules = (s.get("api_protection_rules") or {})
        if "jwt_validation" in s or rules.get("api_endpoint_rules") or rules.get("api_groups_rules"):
            return 1, ""
        return 0, "no JWT validation and no API protection rules"
    return _per_lb(d, f)


def xc_data_guard(d, p):
    return _per_lb(d, lambda k, s: (1, "") if s.get("data_guard_rules") else (0, "no Data Guard rules"))


def xc_service_policies(d, p):
    def f(k, s):
        if (s.get("active_service_policies") or {}).get("policies"):
            return 1, ""
        if "no_service_policies" in s:
            return 0, "service policies disabled"
        return 0.5, "inherits the namespace service policy set; confirm it contains deny rules"
    return _per_lb(d, f)


def xc_tls(d, p):
    def f(k, s):
        h = s.get("https_auto_cert") or s.get("https")
        if h is None:
            return 0, "HTTP only"
        cfg = h.get("tls_config") or (h.get("tls_parameters") or {}).get("tls_config") or (h.get("tls_cert_params") or {}).get("tls_config") or {}
        if "low_security" in cfg:
            return 0, "TLS security level is Low"
        mv = str((cfg.get("custom_security") or {}).get("min_version", ""))
        if mv in ("TLS_AUTO", "TLSv1_0", "TLSv1_1"):
            return 0, "custom TLS minimum version is %s" % mv
        if not h.get("http_redirect"):
            return 0.5, "HTTP to HTTPS redirect is off"
        return 1, ""
    return _per_lb(d, f)


def xc_hsts(d, p):
    def f(k, s):
        h = s.get("https_auto_cert") or s.get("https") or {}
        return (1, "") if h.get("add_hsts") else (0, "HSTS not enabled")
    return _per_lb(d, f)


def xc_log_receiver(d, p):
    recv = d.get("global_log_receivers") or {}
    ok = [v for v in recv.values() if isinstance(v, dict) and "_error" not in v]
    if not ok:
        return None, ["Global log receivers unreadable with this token. Check Shared Configuration > Global Log Receiver."]
    n = sum(len(v.get("items") or []) for v in ok)
    return (1.0, ["%d global log receiver(s) configured." % n]) if n else (0.0, ["No global log receiver configured."])
