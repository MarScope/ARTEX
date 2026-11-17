"""Read-only collectors. Every call is an HTTP GET except the BIG-IP token login.

A collector returns a *snapshot*: {"platform", "target", "collected_at", "data": {key: json}}.
Checks run only against snapshots, so collection and assessment can happen on
different machines and a snapshot can be reviewed before it leaves the customer.
"""
import base64, datetime, json, ssl, urllib.error, urllib.parse, urllib.request


class CollectError(Exception):
    pass


def _ctx(verify, ca_file=None):
    if not verify:
        c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
        return c
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Http:
    def __init__(self, base, headers, verify=True, ca_file=None, timeout=30):
        self.base, self.headers, self.timeout = base.rstrip("/"), dict(headers), timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx(verify, ca_file)))

    def request(self, path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        h = dict(self.headers)
        if data:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        with self.opener.open(req, timeout=self.timeout) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def get(self, path):
        """GET that never raises: failures are recorded so checks can report UNKNOWN."""
        try:
            return self.request(path)
        except urllib.error.HTTPError as e:
            return {"_error": "HTTP %s" % e.code}
        except Exception as e:  # network, TLS, JSON
            return {"_error": "%s: %s" % (type(e).__name__, e)}


# --------------------------------------------------------------------------- BIG-IP
ASM_SUBS = ["signature-settings", "brute-force-attack-preventions", "login-pages", "session-tracking",
            "data-guard", "ip-intelligence", "blocking-settings/violations", "signature-sets",
            "filetypes", "open-api-files", "json-profiles"]

BIGIP_BASE = ["/mgmt/tm/sys/version", "/mgmt/tm/sys/provision", "/mgmt/tm/sys/httpd", "/mgmt/tm/sys/sshd",
              "/mgmt/tm/sys/syslog", "/mgmt/tm/auth/password-policy", "/mgmt/tm/net/self",
              "/mgmt/tm/ltm/virtual?expandSubcollections=true", "/mgmt/tm/ltm/profile/client-ssl",
              "/mgmt/tm/ltm/profile/http"]
BIGIP_SEC = ["/mgmt/tm/security/bot-defense/profile", "/mgmt/tm/security/dos/profile?expandSubcollections=true",
             "/mgmt/tm/security/log/profile"]
BIGIP_ASM = ["/mgmt/tm/asm/policies", "/mgmt/tm/live-update/asm-attack-signatures/installations"]
BIGIP_AFM = ["/mgmt/tm/security/firewall/policy", "/mgmt/tm/security/firewall/global-rules",
             "/mgmt/tm/security/firewall/management-ip-rules", "/mgmt/tm/security/ip-intelligence/policy",
             "/mgmt/tm/security/ip-intelligence/global-policy"]
BIGIP_APM = ["/mgmt/tm/apm/profile/access", "/mgmt/tm/apm/policy/policy-item"]


def provisioned(data):
    out = set()
    for it in (data.get("/mgmt/tm/sys/provision") or {}).get("items", []) or []:
        if it.get("level", "none") != "none":
            out.add(it.get("name"))
    return out


def collect_bigip(host, username, password, verify=True, ca_file=None, progress=lambda m: None):
    base = "https://" + host
    try:
        login = _Http(base, {}, verify, ca_file).request(
            "/mgmt/shared/authn/login", "POST",
            {"username": username, "password": password, "loginProviderName": "tmos"})
        http = _Http(base, {"X-F5-Auth-Token": login["token"]["token"]}, verify, ca_file)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise CollectError("BIG-IP rejected the credentials (HTTP 401).")
        basic = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        http = _Http(base, {"Authorization": "Basic " + basic}, verify, ca_file)
    except ssl.SSLError as e:
        raise CollectError("TLS verification failed for %s (%s). Supply --ca-file, or --insecure to skip "
                           "verification of a self-signed management certificate." % (host, e))
    except Exception as e:
        raise CollectError("Cannot reach %s: %s" % (host, e))

    data = {}
    def grab(paths):
        for p in paths:
            progress("GET " + p); data[p] = http.get(p)
    grab(BIGIP_BASE)
    if "_error" in data["/mgmt/tm/sys/provision"]:
        raise CollectError("Authenticated but cannot read configuration (%s). The account needs at least "
                           "the Auditor role." % data["/mgmt/tm/sys/provision"]["_error"])
    mods = provisioned(data)
    if mods & {"asm", "afm"}:
        grab(BIGIP_SEC)
    if "asm" in mods:
        grab(BIGIP_ASM)
        for pol in data["/mgmt/tm/asm/policies"].get("items", []) or []:
            for sub in ASM_SUBS:
                p = "/mgmt/tm/asm/policies/%s/%s" % (pol["id"], sub)
                progress("GET " + p); data[p] = http.get(p)
    if "afm" in mods:
        grab(BIGIP_AFM)
    if "apm" in mods:
        grab(BIGIP_APM)
    return {"platform": "bigip", "target": host, "collected_at": _now(), "data": data}


# --------------------------------------------------------------------------- Distributed Cloud
def collect_xc(tenant, api_token, namespaces=None, progress=lambda m: None):
    host = tenant if "." in tenant else tenant + ".console.ves.volterra.io"
    http = _Http("https://" + host, {"Authorization": "APIToken " + api_token})
    data = {}
    who = http.get("/api/web/namespaces")
    if "_error" in who:
        raise CollectError("Cannot list namespaces on %s (%s). Check the tenant name and API token." % (host, who["_error"]))
    all_ns = [n.get("name") for n in who.get("items", []) if n.get("name")]
    targets = namespaces or [n for n in all_ns if n not in ("system", "shared", "ves-io-shared")]
    data["namespaces"] = targets
    data["http_loadbalancers"], data["app_firewalls"] = {}, {}
    for ns in targets:
        lst = http.get("/api/config/namespaces/%s/http_loadbalancers" % ns)
        for it in lst.get("items", []) or []:
            name = it.get("name")
            progress("GET http_loadbalancer %s/%s" % (ns, name))
            lb = http.get("/api/config/namespaces/%s/http_loadbalancers/%s" % (ns, name))
            data["http_loadbalancers"]["%s/%s" % (ns, name)] = lb
            ref = ((lb.get("spec") or {}).get("app_firewall") or {})
            if ref.get("name"):
                key = "%s/%s" % (ref.get("namespace") or ns, ref["name"])
                if key not in data["app_firewalls"]:
                    progress("GET app_firewall " + key)
                    data["app_firewalls"][key] = http.get("/api/config/namespaces/%s/app_firewalls/%s" % tuple(key.split("/", 1)))
    data["global_log_receivers"] = {ns: http.get("/api/config/namespaces/%s/global_log_receivers" % ns)
                                    for ns in ("shared", "system")}
    return {"platform": "xc", "target": host, "collected_at": _now(), "data": data}
