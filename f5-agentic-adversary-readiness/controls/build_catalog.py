#!/usr/bin/env python3
"""Source of truth for the control catalog. Run to regenerate catalog.json.

Kept as Python (not hand-edited JSON) so rows stay one-per-line and reviewable.
"""
import json, os

TTPS = {
    "R1": "Low-and-slow recon: directory fuzzing (500+ requests), crawling and vulnerability scanning with wrapped tools (nuclei, httpx, katana, ffuf, dalfox, nmap) paced at 2-20 req/s per host",
    "R2": "Client-side intel harvesting: source maps, runtime config (/env.js, /assets/config.json), OpenAPI docs, and a not-found canary path before guessing",
    "C1": "Password spray / credential stuffing at a fixed ~1 s rhythm in 20-60 minute bursts, new User-Agent per burst",
    "C2": "Token forgery: unsigned (alg=none) JWTs, forged OAuth callbacks, unsigned SAML assertions",
    "C3": "Account recovery, sign-up and self-registration abuse",
    "E1": "Web exploitation: SQLi, command injection, SSTI, XXE, SSRF, auth bypass, anonymous file upload",
    "E2": "Web shell deployment (JSP / PHP / ASPX)",
    "A1": "API abuse: unauthenticated internal routes, IDOR, sequential enumeration and bulk record lookups",
    "X1": "Exfiltration of structured PII / financial records over HTTPS",
    "P1": "Source rotation: residential proxies, Tor, SOCKS relays; blocked IPs replaced within minutes; pivot to another endpoint after a rate limit",
    "V1": "Remote access with stolen VPN configurations and leaked credentials",
    "M1": "Exposed management and administrative interfaces",
    "S1": "Speed: targeting to privileged access in under three hours, many targets in parallel",
}

DOMAINS = {
    "exposure": "Management plane and exposure",
    "recon": "Recon and enumeration resistance",
    "bot": "Automation and bot defense",
    "cred": "Credential and identity abuse",
    "exploit": "Exploit prevention",
    "api": "API protection",
    "network": "Network controls and source reputation",
    "access": "Zero trust access",
    "data": "Data leakage",
    "visibility": "Visibility and response",
}

SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}

# (id, platform, module, domain, severity, confidence, ttps, title, recommendation, rationale, check, params, config_ref)
C = []
def add(*row):
    keys = ["id", "platform", "module", "domain", "severity", "confidence", "ttps", "title",
            "recommendation", "rationale", "check", "params", "config_ref"]
    d = dict(zip(keys, row)); d["weight"] = SEVERITY_WEIGHT[d["severity"]]; C.append(d)

B, X = "bigip", "xc"
# ---------------- BIG-IP: platform / management ----------------
add("BIP-MGT-01", B, "base", "exposure", "critical", "high", ["M1", "S1"],
    "TMOS is on a supported, current release line",
    "Run a release line that still receives security fixes (catalog default: major version >= 17) and apply the latest quarterly security notification fixes. Verify against K5903 before relying on the threshold.",
    "Agentic frameworks chain public CVEs against edge devices within hours of targeting. An unpatched ADC is the entry point, not the defense.",
    "bigip_version", {"min_major": 17, "partial_major": 16}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-02", B, "base", "exposure", "critical", "high", ["M1"],
    "Configuration utility (httpd) is restricted to named management networks",
    "Set `sys httpd allow` to explicit admin subnets or jump hosts. Never `All`.",
    "The FBI's first mitigation group is restricting device management to trusted networks. A reachable TMUI gives an agent a login page to spray and a CVE surface to probe.",
    "bigip_httpd_allow", {}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-03", B, "base", "exposure", "high", "high", ["M1"],
    "SSH is restricted to named management networks",
    "Set `sys sshd allow` to explicit admin subnets. Never `All`.",
    "Same reasoning as the configuration utility: no spray surface for management credentials.",
    "bigip_sshd_allow", {}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-04", B, "base", "exposure", "critical", "high", ["M1"],
    "Self IPs use port lockdown (no Allow All, no Allow Default on exposed VLANs)",
    "Set `allow-service none` on data-plane self IPs, or an explicit custom list (for example tcp:4353 and udp:1026 on the HA VLAN only).",
    "Allow Default exposes TCP 443 and 22 on the self IP, which publishes the management plane on every VLAN the self IP lives on.",
    "bigip_self_lockdown", {}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-05", B, "base", "exposure", "medium", "high", ["M1", "C1"],
    "Local account password policy and lockout are enforced",
    "Enable `auth password-policy policy-enforcement`, minimum length >= 14, and `max-login-failures` between 3 and 10. Prefer remote auth (TACACS+/RADIUS with MFA) for administrators.",
    "A one-attempt-per-second spray is only stopped by lockout or by not being reachable at all.",
    "bigip_password_policy", {"min_length": 14, "max_failures": 10}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-06", B, "base", "visibility", "high", "high", ["S1"],
    "System logs are forwarded off-box",
    "Configure remote syslog (or a log publisher to your SIEM) so audit and security events survive a compromise and can drive automated response.",
    "With sub-three-hour intrusions, detections that live only on the device are read after the fact.",
    "bigip_remote_syslog", {}, "config/bigip/01-management-plane.tmsh")
add("BIP-MGT-07", B, "base", "exposure", "low", "high", ["M1"],
    "Configuration utility idle timeout is 20 minutes or less",
    "Set `sys httpd auth-pam-idle-timeout` to 1200 seconds or less.",
    "Limits the value of a hijacked administrator session.",
    "bigip_idle_timeout", {"max_seconds": 1200}, "config/bigip/01-management-plane.tmsh")
# ---------------- BIG-IP: LTM / TLS ----------------
add("BIP-TLS-01", B, "ltm", "exposure", "medium", "high", ["E1"],
    "Client SSL profiles on virtual servers disable TLS 1.0 and 1.1",
    "Add `no-tlsv1` and `no-tlsv1.1` to client SSL profile options (or use a cipher group that excludes them).",
    "Legacy protocol support is one of the first findings an automated scanner records and builds on.",
    "bigip_tls_versions", {}, "config/bigip/02-ltm-baseline.tmsh")
add("BIP-LTM-01", B, "ltm", "recon", "medium", "heuristic", ["R2", "C2"],
    "Agentic recon marker iRule is attached to HTTP virtual servers",
    "Attach the supplied `agentic_recon_markers` iRule (or equivalent LTM policy) to internet-facing HTTP virtual servers. It rejects alg=none JWTs, known harness User-Agents, canary probe paths and source-map requests, and logs each hit.",
    "These markers are free, high-signal detections of the current tooling. They are trivially changed by an operator, so treat them as an early-warning tripwire, never as the control.",
    "bigip_marker_irule", {"name_pattern": "agentic"}, "config/bigip/06-irule-agentic-recon-markers.tcl")
# ---------------- BIG-IP: Advanced WAF ----------------
add("BIP-WAF-01", B, "asm", "exploit", "critical", "high", ["E1", "E2"],
    "Every HTTP virtual server has an Advanced WAF policy",
    "Attach a security policy to every internet-facing HTTP virtual server, including partner portals, mobile backends and legacy apps.",
    "Reported intrusions started at peripheral applications, not the flagship app. Coverage matters more than tuning depth on one policy.",
    "bigip_waf_coverage", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-02", B, "asm", "exploit", "critical", "high", ["E1", "S1"],
    "Security policies are in blocking enforcement mode",
    "Set enforcement mode to Blocking on all policies attached to virtual servers.",
    "A transparent policy produces a log entry that a human reads after the agent has moved on.",
    "bigip_waf_blocking", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-03", B, "asm", "exploit", "critical", "high", ["E1", "S1"],
    "Attack signatures are enforced, not held in staging",
    "Disable signature staging on internet-facing policies (or enforce all signatures whose staging period has elapsed) and do not re-stage on signature update.",
    "Staged signatures never block. A seven-day staging window is longer than a full agentic campaign.",
    "bigip_waf_staging", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-04", B, "asm", "exploit", "high", "high", ["E1"],
    "Signature sets are assigned with Block enabled",
    "Assign at minimum the Generic Detection (High/Medium Accuracy) set plus the sets for your server technologies, with Learn/Alarm/Block all enabled.",
    "SQL injection, command injection, SSTI and XXE are the reported initial-access classes; they are signature-detectable.",
    "bigip_waf_sigsets", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-05", B, "asm", "exploit", "high", "heuristic", ["E1"],
    "Attack signature package is recent",
    "Schedule live update for attack signatures, bot signatures and threat campaigns; install within 30 days of release.",
    "Agents pick up newly published exploit templates automatically; signature age is your exposure window.",
    "bigip_sig_freshness", {"max_age_days": 45}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-06", B, "asm", "cred", "critical", "high", ["C1", "C3"],
    "Brute force protection is configured with defined login pages",
    "Define a login page for every authentication, recovery and registration endpoint and enable brute force protection keyed on username and device ID, not source IP alone. Detect distributed attacks and credential stuffing.",
    "Sprays rotate source address and User-Agent per burst. Per-IP counters see one failure per source; per-username and per-device counters see the campaign.",
    "bigip_waf_bruteforce", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-07", B, "asm", "api", "high", "high", ["A1", "P1"],
    "Session tracking is enabled",
    "Enable session awareness with username tracking and device ID, and set violation-based thresholds that block the session, user or device after repeated violations.",
    "Lets the policy act on the actor across requests and source addresses, which is the only stable handle on a rotating agent.",
    "bigip_waf_session_tracking", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-08", B, "asm", "data", "medium", "high", ["X1"],
    "Data Guard is enabled",
    "Enable Data Guard (mask or block) for card numbers, national identifiers and custom patterns relevant to the application.",
    "Limits what a successful injection or IDOR can carry out in responses.",
    "bigip_waf_dataguard", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-09", B, "asm", "network", "medium", "high", ["P1"],
    "IP Intelligence is enabled in the security policy",
    "Enable IP Intelligence and block at minimum Anonymous Proxy, Tor Proxies, Scanners, Web Attacks and Botnets.",
    "Raises the cost of proxy rotation. It does not stop residential proxies, so pair it with device- and behavior-based controls.",
    "bigip_waf_ipi", {}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-10", B, "asm", "exploit", "high", "heuristic", ["E1", "S1"],
    "Threat Campaigns violation is set to block",
    "License and enable Threat Campaigns; set the Threat Campaign violation to Alarm and Block with no staging.",
    "Threat campaign signatures are near-zero false positive by design and can be enforced immediately.",
    "bigip_waf_violation", {"match": ["threat campaign"]}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-11", B, "asm", "exploit", "medium", "heuristic", ["E1"],
    "Evasion and HTTP protocol compliance violations are set to block",
    "Block 'Evasion technique detected' and 'HTTP protocol compliance failed'.",
    "Tool-generated traffic and payload mutation by an LLM trip these checks more often than browsers do.",
    "bigip_waf_violation", {"match": ["evasion technique", "http protocol compliance"]}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-12", B, "asm", "recon", "high", "high", ["R2", "E2"],
    "Disallowed file types cover source maps, backups, VCS and environment files",
    "Add `map`, `env`, `git`, `bak`, `old`, `config`, `sql`, `log` to disallowed file types, and remove source maps and runtime config from production.",
    "Reported activity read source maps and config files, then called internal API routes minutes later.",
    "bigip_waf_filetypes", {"required": ["map", "env", "bak"]}, "config/bigip/03-awaf-policy.json")
add("BIP-WAF-13", B, "asm", "api", "medium", "heuristic", ["A1"],
    "API traffic is validated against a schema",
    "Import the OpenAPI specification for API endpoints (or at minimum define JSON profiles) so undeclared paths, methods and parameters are rejected.",
    "A positive model blocks the route guessing that follows source-map analysis.",
    "bigip_waf_api_schema", {}, "config/bigip/03-awaf-policy.json")
# ---------------- BIG-IP: Bot Defense / DoS ----------------
add("BIP-BOT-01", B, "asm", "bot", "critical", "high", ["R1", "C1", "P1"],
    "Every HTTP virtual server has a Bot Defense profile",
    "Attach a Bot Defense profile to every internet-facing HTTP virtual server.",
    "The framework's workers are curl, python-requests, Go clients and headless tools. Client verification is the control that does not depend on request rate.",
    "bigip_bot_coverage", {}, "config/bigip/04-bot-defense.tmsh")
add("BIP-BOT-02", B, "asm", "bot", "critical", "high", ["R1", "C1", "S1"],
    "Bot Defense profiles are in blocking enforcement mode",
    "Set `enforcement-mode blocking`.",
    "Transparent mode only classifies.",
    "bigip_bot_field", {"field": "enforcementMode", "good": ["blocking"]}, "config/bigip/04-bot-defense.tmsh")
add("BIP-BOT-03", B, "asm", "bot", "high", "high", ["R1", "C1"],
    "Bot Defense profiles use the balanced or strict template",
    "Use `template strict` on authentication and high-value flows, `balanced` elsewhere. Relaxed does not verify browsers.",
    "The relaxed template blocks only known malicious signatures, which a per-burst User-Agent change defeats.",
    "bigip_bot_field", {"field": "template", "good": ["strict", "balanced"]}, "config/bigip/04-bot-defense.tmsh")
add("BIP-BOT-04", B, "asm", "bot", "high", "high", ["P1", "C1"],
    "Device ID is generated for clients",
    "Set `deviceid-mode generate-after-access` (or `generate-before-access` on login flows).",
    "Device ID follows the client across proxy rotation and feeds brute force protection and session tracking.",
    "bigip_bot_field", {"field": "deviceidMode", "bad": ["none"]}, "config/bigip/04-bot-defense.tmsh")
add("BIP-BOT-05", B, "asm", "bot", "medium", "high", ["A1"],
    "Strict mitigation is applied to API access",
    "Set `api-access-strict-mitigation enabled` and onboard mobile apps with the Anti-Bot Mobile SDK where browsers cannot be challenged.",
    "API endpoints cannot run a JavaScript challenge, so they need an explicit mitigation choice instead of a silent pass.",
    "bigip_bot_field", {"field": "apiAccessStrictMitigation", "good": ["enabled"]}, "config/bigip/04-bot-defense.tmsh")
add("BIP-DOS-01", B, "asm", "bot", "high", "heuristic", ["R1", "S1"],
    "A behavioral application DoS profile is attached to HTTP virtual servers",
    "Attach a DoS profile with application security enabled, stress-based detection in blocking mode and Behavioral DoS detection with signatures enabled.",
    "Behavioral baselining reacts to a change in traffic shape at 2-20 req/s that fixed TPS thresholds will never reach.",
    "bigip_dos_coverage", {}, "config/bigip/04-bot-defense.tmsh")
# ---------------- BIG-IP: AFM ----------------
add("BIP-AFM-01", B, "afm", "network", "high", "high", ["R1", "M1"],
    "Network firewall policy is enforced globally or on every virtual server",
    "Enforce an AFM policy at the global context or per virtual server, default-deny, permitting only the service ports each application needs.",
    "Removes port-scan findings (the nmap stage) and stops non-application ports from being reachable through a wildcard listener.",
    "bigip_afm_policy", {}, "config/bigip/05-afm.tmsh")
add("BIP-AFM-02", B, "afm", "network", "high", "high", ["P1"],
    "An IP Intelligence policy is applied globally or per virtual server",
    "Apply an IP Intelligence policy that drops Tor, anonymous proxies, scanners and botnets, and add a feed list for your own IOC feed so SOAR can push blocks in seconds.",
    "Published infrastructure indicators rotate quickly. A feed list is the mechanism that lets automated response keep up; a manually edited address list is not.",
    "bigip_afm_ipi", {}, "config/bigip/05-afm.tmsh")
add("BIP-AFM-03", B, "afm", "exposure", "high", "high", ["M1"],
    "Management port firewall rules are defined",
    "Define management-IP rules that permit only admin subnets to TCP 443/22 and drop everything else.",
    "Defense in depth behind httpd/sshd allow lists, and the only one of the three that logs the attempts.",
    "bigip_afm_mgmt_rules", {}, "config/bigip/05-afm.tmsh")
add("BIP-LOG-01", B, "asm|afm", "visibility", "high", "high", ["S1"],
    "Security logging profiles are attached to virtual servers",
    "Attach a security log profile (application security: all requests or illegal requests with responses; bot defense; network firewall; DoS) that publishes to a remote high-speed log destination.",
    "The behavioral hunts published for ARTEX (canary path, unsigned token, spray rhythm) all run on request logs. No log profile, no hunt.",
    "bigip_log_profile_coverage", {}, "config/bigip/05-afm.tmsh")
# ---------------- BIG-IP: APM ----------------
add("BIP-APM-01", B, "apm", "access", "critical", "heuristic", ["V1", "C1"],
    "Access policies include a strong second factor",
    "Require phishing-resistant MFA (client certificate, FIDO2 through SAML/OIDC IdP, or at minimum OTP/RADIUS push) in every access policy that grants network access or portal access.",
    "Stolen VPN configurations and leaked credentials are a reported initial-access path. A password-only policy converts a leak into a session.",
    "bigip_apm_mfa", {"markers": ["otp", "radius", "saml", "oauth", "cert", "duo", "mfa", "fido", "securid", "tacacs"]}, "config/bigip/07-apm.tmsh")
add("BIP-APM-02", B, "apm", "access", "high", "high", ["V1"],
    "Access sessions are bound to the client IP and use Secure, HttpOnly cookies",
    "Enable `restrict-to-single-client-ip`, `secure-cookie` and `httponly-cookie` on access profiles. Where mobile roaming makes IP binding impractical, compensate with device posture and a per-request policy.",
    "Stops replay of a harvested MRHSession cookie from attacker infrastructure.",
    "bigip_apm_session_binding", {}, "config/bigip/07-apm.tmsh")
add("BIP-APM-03", B, "apm", "access", "medium", "high", ["V1"],
    "Access session lifetime is bounded",
    "Inactivity timeout <= 900 s and maximum session timeout <= 12 hours.",
    "Bounds how long a stolen session stays useful.",
    "bigip_apm_timeouts", {"max_inactivity": 900, "max_session": 43200}, "config/bigip/07-apm.tmsh")
add("BIP-APM-04", B, "apm", "access", "medium", "high", ["C1"],
    "In-progress sessions per client IP are limited",
    "Set `max-in-progress-sessions` per client IP to a small value (for example 32 or lower) and keep a non-zero logon failure delay.",
    "Throttles a spray against the logon page before an AAA lockout is reached.",
    "bigip_apm_inprogress", {"max": 64}, "config/bigip/07-apm.tmsh")
add("BIP-APM-05", B, "apm", "access", "high", "high", ["V1", "A1"],
    "Access virtual servers enforce a per-request policy",
    "Attach a per-request policy that re-evaluates authorization (group, posture, URL category, step-up) on every request rather than once at logon.",
    "Per-session-only access gives an attacker with one valid session the whole published surface.",
    "bigip_apm_per_request", {}, "config/bigip/07-apm.tmsh")
# ---------------- F5 Distributed Cloud ----------------
P = "config/xc/http-loadbalancer-security.json"
add("XC-WAF-01", X, "waap", "exploit", "critical", "high", ["E1", "E2"],
    "Every HTTP load balancer has an App Firewall",
    "Attach an App Firewall to every HTTP load balancer.", "Peripheral applications are the reported entry point.",
    "xc_waf_attached", {}, P)
add("XC-WAF-02", X, "waap", "exploit", "critical", "high", ["E1", "S1"],
    "App Firewalls are in blocking mode",
    "Set enforcement mode to Blocking.", "Monitoring mode logs the intrusion; it does not interrupt it.",
    "xc_waf_blocking", {}, "config/xc/app-firewall.json")
add("XC-WAF-03", X, "waap", "exploit", "high", "high", ["E1", "S1"],
    "Threat Campaigns are enabled and signature accuracy includes medium",
    "Use custom detection settings only where needed; keep Threat Campaigns enabled and select High + Medium accuracy signatures at minimum.",
    "Threat campaigns block active exploitation patterns with very low false-positive risk.",
    "xc_waf_detection", {}, "config/xc/app-firewall.json")
add("XC-WAF-04", X, "waap", "bot", "high", "high", ["R1", "C1"],
    "App Firewall bot signatures block malicious bots",
    "Set malicious bot action to Block and suspicious bot action to Block or Report.",
    "Baseline automation control where Bot Defense is not licensed.",
    "xc_waf_bot_setting", {}, "config/xc/app-firewall.json")
add("XC-BOT-01", X, "bot-defense", "bot", "critical", "high", ["R1", "C1", "C3", "P1"],
    "Bot Defense protects authentication and high-value endpoints",
    "Enable Bot Defense with protected endpoints for login, password reset, registration, search and any bulk-lookup API, with mitigation set to Block. A JavaScript or policy-based challenge is a partial substitute.",
    "Signal-based client verification is independent of source IP, User-Agent and request rate, which are the three things the framework varies.",
    "xc_bot_defense", {}, P)
add("XC-MUD-01", X, "waap", "bot", "high", "high", ["R1", "P1", "S1"],
    "Malicious User Detection and mitigation are enabled",
    "Enable Malicious User Detection and a malicious user mitigation challenge policy (JS challenge at low, CAPTCHA at medium, temporary block at high threat level).",
    "Scores the actor on WAF hits, failed logins, forbidden requests and rate behavior, then escalates automatically, which is the response speed this threat requires.",
    "xc_malicious_user", {}, P)
add("XC-RL-01", X, "waap", "cred", "high", "high", ["C1", "A1", "R1"],
    "Rate limiting is configured",
    "Configure rate limiting, and API rate limits on login, recovery and lookup endpoints, sized to human use (single-digit requests per minute per user on auth endpoints). Key on user identifier, not IP alone.",
    "Reported pacing is 2-20 requests per second and about one login attempt per second. A threshold of hundreds per second never triggers.",
    "xc_rate_limit", {}, P)
add("XC-REP-01", X, "waap", "network", "medium", "high", ["P1"],
    "IP Reputation is enabled with proxy and scanner categories",
    "Enable IP Reputation and include Tor Proxy, Proxy, Scanners, Web Attacks and Botnets.",
    "Raises the cost of proxy rotation; does not address residential proxies on its own.",
    "xc_ip_reputation", {"required": ["TOR_PROXY", "PROXY", "SCANNERS"]}, P)
add("XC-REP-02", X, "waap", "network", "medium", "high", ["P1", "S1"],
    "Threat Mesh is enabled",
    "Enable Threat Mesh.", "Shares attacker identification across tenants, useful when one controller is working hundreds of targets at once.",
    "xc_flag", {"on": ["enable_threat_mesh"], "off": ["disable_threat_mesh"]}, P)
add("XC-DDOS-01", X, "waap", "bot", "medium", "heuristic", ["R1"],
    "L7 DDoS auto-mitigation is enabled",
    "Enable L7 DDoS protection with automatic mitigation (block or JS challenge).",
    "Covers aggressive-profile scanning bursts and protects origin capacity during a campaign.",
    "xc_l7_ddos", {}, P)
add("XC-API-01", X, "api-security", "api", "high", "high", ["A1", "R2"],
    "API Discovery is enabled",
    "Enable API Discovery (and code-repository/crawler discovery where licensed) to find shadow and undocumented endpoints.",
    "The agent builds its own inventory of your API from source maps and traffic. You need the same inventory first.",
    "xc_flag", {"on": ["enable_api_discovery"], "off": ["disable_api_discovery"]}, P)
add("XC-API-02", X, "api-security", "api", "high", "high", ["A1"],
    "API definition is attached with validation",
    "Attach an API definition and enable validation (block) for all endpoints, with fall-through set to block or report for undeclared paths.",
    "Positive security for the API: undeclared routes discovered through source maps return an error before reaching the origin.",
    "xc_api_definition", {}, P)
add("XC-API-03", X, "api-security", "api", "high", "high", ["C2", "A1"],
    "API protection rules or JWT validation are configured",
    "Configure JWT validation (signature, issuer, audience, expiry; reject alg=none) and API protection rules that deny unauthenticated access to non-public endpoints.",
    "Unsigned tokens and unauthenticated internal routes are both reported techniques.",
    "xc_api_authz", {}, P)
add("XC-DATA-01", X, "waap", "data", "medium", "high", ["X1"],
    "Data Guard rules are configured",
    "Apply Data Guard to paths that return personal or financial data, and enable sensitive data discovery.",
    "Limits what leaves in responses if an authorization flaw is found.",
    "xc_data_guard", {}, P)
add("XC-SP-01", X, "waap", "recon", "high", "high", ["R2", "C2", "P1"],
    "Service policies are applied",
    "Apply service policies (namespace or custom) that deny known harness User-Agents, canary probe paths, source-map and environment files, and that feed an IP prefix set your SOAR can update.",
    "Cheap tripwires for the current tooling plus the hook for automated blocking.",
    "xc_service_policies", {}, "config/xc/service-policy-agentic-markers.json")
add("XC-TLS-01", X, "waap", "exposure", "medium", "high", ["E1"],
    "HTTPS only, with TLS 1.2 or higher",
    "Use HTTPS with HTTP redirect, and High (default) TLS security. Do not use Low security.",
    "Removes easy scanner findings and downgrade paths.",
    "xc_tls", {}, P)
add("XC-TLS-02", X, "waap", "exposure", "low", "high", ["E1"],
    "HSTS is enabled", "Enable the HSTS header on HTTPS load balancers.", "Baseline transport hardening.",
    "xc_hsts", {}, P)
add("XC-LOG-01", X, "waap", "visibility", "high", "heuristic", ["S1"],
    "A global log receiver streams security events to the SIEM",
    "Configure a Global Log Receiver for request and security event logs to your SIEM, and alert on the behavioral patterns in the guide.",
    "Console-only logs cannot drive automated containment.",
    "xc_log_receiver", {}, "config/xc/global-log-receiver.json")

out = {"schema": 1, "name": "F5 Agentic Adversary Readiness control catalog", "version": "0.1.0",
       "ttps": TTPS, "domains": DOMAINS, "severity_weight": SEVERITY_WEIGHT, "controls": C}
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "catalog.json"), "w") as f:
    json.dump(out, f, indent=1); f.write("\n")
print(len(C), "controls")
