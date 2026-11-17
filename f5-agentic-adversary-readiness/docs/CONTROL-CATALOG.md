# Control catalog

Generated from `controls/catalog.json` (version 0.1.0) with `python -m aar catalog`. Do not edit by hand.

Weights: critical 10, high 6, medium 3, low 1.

## Adversary behaviors referenced

| Tag | Behavior |
|---|---|
| R1 | Low-and-slow recon: directory fuzzing (500+ requests), crawling and vulnerability scanning with wrapped tools (nuclei, httpx, katana, ffuf, dalfox, nmap) paced at 2-20 req/s per host |
| R2 | Client-side intel harvesting: source maps, runtime config (/env.js, /assets/config.json), OpenAPI docs, and a not-found canary path before guessing |
| C1 | Password spray / credential stuffing at a fixed ~1 s rhythm in 20-60 minute bursts, new User-Agent per burst |
| C2 | Token forgery: unsigned (alg=none) JWTs, forged OAuth callbacks, unsigned SAML assertions |
| C3 | Account recovery, sign-up and self-registration abuse |
| E1 | Web exploitation: SQLi, command injection, SSTI, XXE, SSRF, auth bypass, anonymous file upload |
| E2 | Web shell deployment (JSP / PHP / ASPX) |
| A1 | API abuse: unauthenticated internal routes, IDOR, sequential enumeration and bulk record lookups |
| X1 | Exfiltration of structured PII / financial records over HTTPS |
| P1 | Source rotation: residential proxies, Tor, SOCKS relays; blocked IPs replaced within minutes; pivot to another endpoint after a rate limit |
| V1 | Remote access with stolen VPN configurations and leaked credentials |
| M1 | Exposed management and administrative interfaces |
| S1 | Speed: targeting to privileged access in under three hours, many targets in parallel |

## BIG-IP

### BIP-MGT-01: TMOS is on a supported, current release line

- Module: `base` | Domain: Management plane and exposure | Severity: critical | Check confidence: high
- Counters: M1, S1
- Recommendation: Run a release line that still receives security fixes (catalog default: major version >= 17) and apply the latest quarterly security notification fixes. Verify against K5903 before relying on the threshold.
- Why: Agentic frameworks chain public CVEs against edge devices within hours of targeting. An unpatched ADC is the entry point, not the defense.
- Reference config: `config/bigip/01-management-plane.tmsh`
- Tunable parameters: `{'min_major': 17, 'partial_major': 16}`

### BIP-MGT-02: Configuration utility (httpd) is restricted to named management networks

- Module: `base` | Domain: Management plane and exposure | Severity: critical | Check confidence: high
- Counters: M1
- Recommendation: Set `sys httpd allow` to explicit admin subnets or jump hosts. Never `All`.
- Why: The FBI's first mitigation group is restricting device management to trusted networks. A reachable TMUI gives an agent a login page to spray and a CVE surface to probe.
- Reference config: `config/bigip/01-management-plane.tmsh`

### BIP-MGT-03: SSH is restricted to named management networks

- Module: `base` | Domain: Management plane and exposure | Severity: high | Check confidence: high
- Counters: M1
- Recommendation: Set `sys sshd allow` to explicit admin subnets. Never `All`.
- Why: Same reasoning as the configuration utility: no spray surface for management credentials.
- Reference config: `config/bigip/01-management-plane.tmsh`

### BIP-MGT-04: Self IPs use port lockdown (no Allow All, no Allow Default on exposed VLANs)

- Module: `base` | Domain: Management plane and exposure | Severity: critical | Check confidence: high
- Counters: M1
- Recommendation: Set `allow-service none` on data-plane self IPs, or an explicit custom list (for example tcp:4353 and udp:1026 on the HA VLAN only).
- Why: Allow Default exposes TCP 443 and 22 on the self IP, which publishes the management plane on every VLAN the self IP lives on.
- Reference config: `config/bigip/01-management-plane.tmsh`

### BIP-MGT-05: Local account password policy and lockout are enforced

- Module: `base` | Domain: Management plane and exposure | Severity: medium | Check confidence: high
- Counters: M1, C1
- Recommendation: Enable `auth password-policy policy-enforcement`, minimum length >= 14, and `max-login-failures` between 3 and 10. Prefer remote auth (TACACS+/RADIUS with MFA) for administrators.
- Why: A one-attempt-per-second spray is only stopped by lockout or by not being reachable at all.
- Reference config: `config/bigip/01-management-plane.tmsh`
- Tunable parameters: `{'min_length': 14, 'max_failures': 10}`

### BIP-MGT-06: System logs are forwarded off-box

- Module: `base` | Domain: Visibility and response | Severity: high | Check confidence: high
- Counters: S1
- Recommendation: Configure remote syslog (or a log publisher to your SIEM) so audit and security events survive a compromise and can drive automated response.
- Why: With sub-three-hour intrusions, detections that live only on the device are read after the fact.
- Reference config: `config/bigip/01-management-plane.tmsh`

### BIP-MGT-07: Configuration utility idle timeout is 20 minutes or less

- Module: `base` | Domain: Management plane and exposure | Severity: low | Check confidence: high
- Counters: M1
- Recommendation: Set `sys httpd auth-pam-idle-timeout` to 1200 seconds or less.
- Why: Limits the value of a hijacked administrator session.
- Reference config: `config/bigip/01-management-plane.tmsh`
- Tunable parameters: `{'max_seconds': 1200}`

### BIP-TLS-01: Client SSL profiles on virtual servers disable TLS 1.0 and 1.1

- Module: `ltm` | Domain: Management plane and exposure | Severity: medium | Check confidence: high
- Counters: E1
- Recommendation: Add `no-tlsv1` and `no-tlsv1.1` to client SSL profile options (or use a cipher group that excludes them).
- Why: Legacy protocol support is one of the first findings an automated scanner records and builds on.
- Reference config: `config/bigip/02-ltm-baseline.tmsh`

### BIP-LTM-01: Agentic recon marker iRule is attached to HTTP virtual servers

- Module: `ltm` | Domain: Recon and enumeration resistance | Severity: medium | Check confidence: heuristic
- Counters: R2, C2
- Recommendation: Attach the supplied `agentic_recon_markers` iRule (or equivalent LTM policy) to internet-facing HTTP virtual servers. It rejects alg=none JWTs, known harness User-Agents, canary probe paths and source-map requests, and logs each hit.
- Why: These markers are free, high-signal detections of the current tooling. They are trivially changed by an operator, so treat them as an early-warning tripwire, never as the control.
- Reference config: `config/bigip/06-irule-agentic-recon-markers.tcl`
- Tunable parameters: `{'name_pattern': 'agentic'}`

### BIP-WAF-01: Every HTTP virtual server has an Advanced WAF policy

- Module: `asm` | Domain: Exploit prevention | Severity: critical | Check confidence: high
- Counters: E1, E2
- Recommendation: Attach a security policy to every internet-facing HTTP virtual server, including partner portals, mobile backends and legacy apps.
- Why: Reported intrusions started at peripheral applications, not the flagship app. Coverage matters more than tuning depth on one policy.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-02: Security policies are in blocking enforcement mode

- Module: `asm` | Domain: Exploit prevention | Severity: critical | Check confidence: high
- Counters: E1, S1
- Recommendation: Set enforcement mode to Blocking on all policies attached to virtual servers.
- Why: A transparent policy produces a log entry that a human reads after the agent has moved on.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-03: Attack signatures are enforced, not held in staging

- Module: `asm` | Domain: Exploit prevention | Severity: critical | Check confidence: high
- Counters: E1, S1
- Recommendation: Disable signature staging on internet-facing policies (or enforce all signatures whose staging period has elapsed) and do not re-stage on signature update.
- Why: Staged signatures never block. A seven-day staging window is longer than a full agentic campaign.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-04: Signature sets are assigned with Block enabled

- Module: `asm` | Domain: Exploit prevention | Severity: high | Check confidence: high
- Counters: E1
- Recommendation: Assign at minimum the Generic Detection (High/Medium Accuracy) set plus the sets for your server technologies, with Learn/Alarm/Block all enabled.
- Why: SQL injection, command injection, SSTI and XXE are the reported initial-access classes; they are signature-detectable.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-05: Attack signature package is recent

- Module: `asm` | Domain: Exploit prevention | Severity: high | Check confidence: heuristic
- Counters: E1
- Recommendation: Schedule live update for attack signatures, bot signatures and threat campaigns; install within 30 days of release.
- Why: Agents pick up newly published exploit templates automatically; signature age is your exposure window.
- Reference config: `config/bigip/03-awaf-policy.json`
- Tunable parameters: `{'max_age_days': 45}`

### BIP-WAF-06: Brute force protection is configured with defined login pages

- Module: `asm` | Domain: Credential and identity abuse | Severity: critical | Check confidence: high
- Counters: C1, C3
- Recommendation: Define a login page for every authentication, recovery and registration endpoint and enable brute force protection keyed on username and device ID, not source IP alone. Detect distributed attacks and credential stuffing.
- Why: Sprays rotate source address and User-Agent per burst. Per-IP counters see one failure per source; per-username and per-device counters see the campaign.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-07: Session tracking is enabled

- Module: `asm` | Domain: API protection | Severity: high | Check confidence: high
- Counters: A1, P1
- Recommendation: Enable session awareness with username tracking and device ID, and set violation-based thresholds that block the session, user or device after repeated violations.
- Why: Lets the policy act on the actor across requests and source addresses, which is the only stable handle on a rotating agent.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-08: Data Guard is enabled

- Module: `asm` | Domain: Data leakage | Severity: medium | Check confidence: high
- Counters: X1
- Recommendation: Enable Data Guard (mask or block) for card numbers, national identifiers and custom patterns relevant to the application.
- Why: Limits what a successful injection or IDOR can carry out in responses.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-09: IP Intelligence is enabled in the security policy

- Module: `asm` | Domain: Network controls and source reputation | Severity: medium | Check confidence: high
- Counters: P1
- Recommendation: Enable IP Intelligence and block at minimum Anonymous Proxy, Tor Proxies, Scanners, Web Attacks and Botnets.
- Why: Raises the cost of proxy rotation. It does not stop residential proxies, so pair it with device- and behavior-based controls.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-WAF-10: Threat Campaigns violation is set to block

- Module: `asm` | Domain: Exploit prevention | Severity: high | Check confidence: heuristic
- Counters: E1, S1
- Recommendation: License and enable Threat Campaigns; set the Threat Campaign violation to Alarm and Block with no staging.
- Why: Threat campaign signatures are near-zero false positive by design and can be enforced immediately.
- Reference config: `config/bigip/03-awaf-policy.json`
- Tunable parameters: `{'match': ['threat campaign']}`

### BIP-WAF-11: Evasion and HTTP protocol compliance violations are set to block

- Module: `asm` | Domain: Exploit prevention | Severity: medium | Check confidence: heuristic
- Counters: E1
- Recommendation: Block 'Evasion technique detected' and 'HTTP protocol compliance failed'.
- Why: Tool-generated traffic and payload mutation by an LLM trip these checks more often than browsers do.
- Reference config: `config/bigip/03-awaf-policy.json`
- Tunable parameters: `{'match': ['evasion technique', 'http protocol compliance']}`

### BIP-WAF-12: Disallowed file types cover source maps, backups, VCS and environment files

- Module: `asm` | Domain: Recon and enumeration resistance | Severity: high | Check confidence: high
- Counters: R2, E2
- Recommendation: Add `map`, `env`, `git`, `bak`, `old`, `config`, `sql`, `log` to disallowed file types, and remove source maps and runtime config from production.
- Why: Reported activity read source maps and config files, then called internal API routes minutes later.
- Reference config: `config/bigip/03-awaf-policy.json`
- Tunable parameters: `{'required': ['map', 'env', 'bak']}`

### BIP-WAF-13: API traffic is validated against a schema

- Module: `asm` | Domain: API protection | Severity: medium | Check confidence: heuristic
- Counters: A1
- Recommendation: Import the OpenAPI specification for API endpoints (or at minimum define JSON profiles) so undeclared paths, methods and parameters are rejected.
- Why: A positive model blocks the route guessing that follows source-map analysis.
- Reference config: `config/bigip/03-awaf-policy.json`

### BIP-BOT-01: Every HTTP virtual server has a Bot Defense profile

- Module: `asm` | Domain: Automation and bot defense | Severity: critical | Check confidence: high
- Counters: R1, C1, P1
- Recommendation: Attach a Bot Defense profile to every internet-facing HTTP virtual server.
- Why: The framework's workers are curl, python-requests, Go clients and headless tools. Client verification is the control that does not depend on request rate.
- Reference config: `config/bigip/04-bot-defense.tmsh`

### BIP-BOT-02: Bot Defense profiles are in blocking enforcement mode

- Module: `asm` | Domain: Automation and bot defense | Severity: critical | Check confidence: high
- Counters: R1, C1, S1
- Recommendation: Set `enforcement-mode blocking`.
- Why: Transparent mode only classifies.
- Reference config: `config/bigip/04-bot-defense.tmsh`
- Tunable parameters: `{'field': 'enforcementMode', 'good': ['blocking']}`

### BIP-BOT-03: Bot Defense profiles use the balanced or strict template

- Module: `asm` | Domain: Automation and bot defense | Severity: high | Check confidence: high
- Counters: R1, C1
- Recommendation: Use `template strict` on authentication and high-value flows, `balanced` elsewhere. Relaxed does not verify browsers.
- Why: The relaxed template blocks only known malicious signatures, which a per-burst User-Agent change defeats.
- Reference config: `config/bigip/04-bot-defense.tmsh`
- Tunable parameters: `{'field': 'template', 'good': ['strict', 'balanced']}`

### BIP-BOT-04: Device ID is generated for clients

- Module: `asm` | Domain: Automation and bot defense | Severity: high | Check confidence: high
- Counters: P1, C1
- Recommendation: Set `deviceid-mode generate-after-access` (or `generate-before-access` on login flows).
- Why: Device ID follows the client across proxy rotation and feeds brute force protection and session tracking.
- Reference config: `config/bigip/04-bot-defense.tmsh`
- Tunable parameters: `{'field': 'deviceidMode', 'bad': ['none']}`

### BIP-BOT-05: Strict mitigation is applied to API access

- Module: `asm` | Domain: Automation and bot defense | Severity: medium | Check confidence: high
- Counters: A1
- Recommendation: Set `api-access-strict-mitigation enabled` and onboard mobile apps with the Anti-Bot Mobile SDK where browsers cannot be challenged.
- Why: API endpoints cannot run a JavaScript challenge, so they need an explicit mitigation choice instead of a silent pass.
- Reference config: `config/bigip/04-bot-defense.tmsh`
- Tunable parameters: `{'field': 'apiAccessStrictMitigation', 'good': ['enabled']}`

### BIP-DOS-01: A behavioral application DoS profile is attached to HTTP virtual servers

- Module: `asm` | Domain: Automation and bot defense | Severity: high | Check confidence: heuristic
- Counters: R1, S1
- Recommendation: Attach a DoS profile with application security enabled, stress-based detection in blocking mode and Behavioral DoS detection with signatures enabled.
- Why: Behavioral baselining reacts to a change in traffic shape at 2-20 req/s that fixed TPS thresholds will never reach.
- Reference config: `config/bigip/04-bot-defense.tmsh`

### BIP-AFM-01: Network firewall policy is enforced globally or on every virtual server

- Module: `afm` | Domain: Network controls and source reputation | Severity: high | Check confidence: high
- Counters: R1, M1
- Recommendation: Enforce an AFM policy at the global context or per virtual server, default-deny, permitting only the service ports each application needs.
- Why: Removes port-scan findings (the nmap stage) and stops non-application ports from being reachable through a wildcard listener.
- Reference config: `config/bigip/05-afm.tmsh`

### BIP-AFM-02: An IP Intelligence policy is applied globally or per virtual server

- Module: `afm` | Domain: Network controls and source reputation | Severity: high | Check confidence: high
- Counters: P1
- Recommendation: Apply an IP Intelligence policy that drops Tor, anonymous proxies, scanners and botnets, and add a feed list for your own IOC feed so SOAR can push blocks in seconds.
- Why: Published infrastructure indicators rotate quickly. A feed list is the mechanism that lets automated response keep up; a manually edited address list is not.
- Reference config: `config/bigip/05-afm.tmsh`

### BIP-AFM-03: Management port firewall rules are defined

- Module: `afm` | Domain: Management plane and exposure | Severity: high | Check confidence: high
- Counters: M1
- Recommendation: Define management-IP rules that permit only admin subnets to TCP 443/22 and drop everything else.
- Why: Defense in depth behind httpd/sshd allow lists, and the only one of the three that logs the attempts.
- Reference config: `config/bigip/05-afm.tmsh`

### BIP-LOG-01: Security logging profiles are attached to virtual servers

- Module: `asm|afm` | Domain: Visibility and response | Severity: high | Check confidence: high
- Counters: S1
- Recommendation: Attach a security log profile (application security: all requests or illegal requests with responses; bot defense; network firewall; DoS) that publishes to a remote high-speed log destination.
- Why: The behavioral hunts published for ARTEX (canary path, unsigned token, spray rhythm) all run on request logs. No log profile, no hunt.
- Reference config: `config/bigip/05-afm.tmsh`

### BIP-APM-01: Access policies include a strong second factor

- Module: `apm` | Domain: Zero trust access | Severity: critical | Check confidence: heuristic
- Counters: V1, C1
- Recommendation: Require phishing-resistant MFA (client certificate, FIDO2 through SAML/OIDC IdP, or at minimum OTP/RADIUS push) in every access policy that grants network access or portal access.
- Why: Stolen VPN configurations and leaked credentials are a reported initial-access path. A password-only policy converts a leak into a session.
- Reference config: `config/bigip/07-apm.tmsh`
- Tunable parameters: `{'markers': ['otp', 'radius', 'saml', 'oauth', 'cert', 'duo', 'mfa', 'fido', 'securid', 'tacacs']}`

### BIP-APM-02: Access sessions are bound to the client IP and use Secure, HttpOnly cookies

- Module: `apm` | Domain: Zero trust access | Severity: high | Check confidence: high
- Counters: V1
- Recommendation: Enable `restrict-to-single-client-ip`, `secure-cookie` and `httponly-cookie` on access profiles. Where mobile roaming makes IP binding impractical, compensate with device posture and a per-request policy.
- Why: Stops replay of a harvested MRHSession cookie from attacker infrastructure.
- Reference config: `config/bigip/07-apm.tmsh`

### BIP-APM-03: Access session lifetime is bounded

- Module: `apm` | Domain: Zero trust access | Severity: medium | Check confidence: high
- Counters: V1
- Recommendation: Inactivity timeout <= 900 s and maximum session timeout <= 12 hours.
- Why: Bounds how long a stolen session stays useful.
- Reference config: `config/bigip/07-apm.tmsh`
- Tunable parameters: `{'max_inactivity': 900, 'max_session': 43200}`

### BIP-APM-04: In-progress sessions per client IP are limited

- Module: `apm` | Domain: Zero trust access | Severity: medium | Check confidence: high
- Counters: C1
- Recommendation: Set `max-in-progress-sessions` per client IP to a small value (for example 32 or lower) and keep a non-zero logon failure delay.
- Why: Throttles a spray against the logon page before an AAA lockout is reached.
- Reference config: `config/bigip/07-apm.tmsh`
- Tunable parameters: `{'max': 64}`

### BIP-APM-05: Access virtual servers enforce a per-request policy

- Module: `apm` | Domain: Zero trust access | Severity: high | Check confidence: high
- Counters: V1, A1
- Recommendation: Attach a per-request policy that re-evaluates authorization (group, posture, URL category, step-up) on every request rather than once at logon.
- Why: Per-session-only access gives an attacker with one valid session the whole published surface.
- Reference config: `config/bigip/07-apm.tmsh`


## F5 Distributed Cloud

### XC-WAF-01: Every HTTP load balancer has an App Firewall

- Module: `waap` | Domain: Exploit prevention | Severity: critical | Check confidence: high
- Counters: E1, E2
- Recommendation: Attach an App Firewall to every HTTP load balancer.
- Why: Peripheral applications are the reported entry point.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-WAF-02: App Firewalls are in blocking mode

- Module: `waap` | Domain: Exploit prevention | Severity: critical | Check confidence: high
- Counters: E1, S1
- Recommendation: Set enforcement mode to Blocking.
- Why: Monitoring mode logs the intrusion; it does not interrupt it.
- Reference config: `config/xc/app-firewall.json`

### XC-WAF-03: Threat Campaigns are enabled and signature accuracy includes medium

- Module: `waap` | Domain: Exploit prevention | Severity: high | Check confidence: high
- Counters: E1, S1
- Recommendation: Use custom detection settings only where needed; keep Threat Campaigns enabled and select High + Medium accuracy signatures at minimum.
- Why: Threat campaigns block active exploitation patterns with very low false-positive risk.
- Reference config: `config/xc/app-firewall.json`

### XC-WAF-04: App Firewall bot signatures block malicious bots

- Module: `waap` | Domain: Automation and bot defense | Severity: high | Check confidence: high
- Counters: R1, C1
- Recommendation: Set malicious bot action to Block and suspicious bot action to Block or Report.
- Why: Baseline automation control where Bot Defense is not licensed.
- Reference config: `config/xc/app-firewall.json`

### XC-BOT-01: Bot Defense protects authentication and high-value endpoints

- Module: `bot-defense` | Domain: Automation and bot defense | Severity: critical | Check confidence: high
- Counters: R1, C1, C3, P1
- Recommendation: Enable Bot Defense with protected endpoints for login, password reset, registration, search and any bulk-lookup API, with mitigation set to Block. A JavaScript or policy-based challenge is a partial substitute.
- Why: Signal-based client verification is independent of source IP, User-Agent and request rate, which are the three things the framework varies.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-MUD-01: Malicious User Detection and mitigation are enabled

- Module: `waap` | Domain: Automation and bot defense | Severity: high | Check confidence: high
- Counters: R1, P1, S1
- Recommendation: Enable Malicious User Detection and a malicious user mitigation challenge policy (JS challenge at low, CAPTCHA at medium, temporary block at high threat level).
- Why: Scores the actor on WAF hits, failed logins, forbidden requests and rate behavior, then escalates automatically, which is the response speed this threat requires.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-RL-01: Rate limiting is configured

- Module: `waap` | Domain: Credential and identity abuse | Severity: high | Check confidence: high
- Counters: C1, A1, R1
- Recommendation: Configure rate limiting, and API rate limits on login, recovery and lookup endpoints, sized to human use (single-digit requests per minute per user on auth endpoints). Key on user identifier, not IP alone.
- Why: Reported pacing is 2-20 requests per second and about one login attempt per second. A threshold of hundreds per second never triggers.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-REP-01: IP Reputation is enabled with proxy and scanner categories

- Module: `waap` | Domain: Network controls and source reputation | Severity: medium | Check confidence: high
- Counters: P1
- Recommendation: Enable IP Reputation and include Tor Proxy, Proxy, Scanners, Web Attacks and Botnets.
- Why: Raises the cost of proxy rotation; does not address residential proxies on its own.
- Reference config: `config/xc/http-loadbalancer-security.json`
- Tunable parameters: `{'required': ['TOR_PROXY', 'PROXY', 'SCANNERS']}`

### XC-REP-02: Threat Mesh is enabled

- Module: `waap` | Domain: Network controls and source reputation | Severity: medium | Check confidence: high
- Counters: P1, S1
- Recommendation: Enable Threat Mesh.
- Why: Shares attacker identification across tenants, useful when one controller is working hundreds of targets at once.
- Reference config: `config/xc/http-loadbalancer-security.json`
- Tunable parameters: `{'on': ['enable_threat_mesh'], 'off': ['disable_threat_mesh']}`

### XC-DDOS-01: L7 DDoS auto-mitigation is enabled

- Module: `waap` | Domain: Automation and bot defense | Severity: medium | Check confidence: heuristic
- Counters: R1
- Recommendation: Enable L7 DDoS protection with automatic mitigation (block or JS challenge).
- Why: Covers aggressive-profile scanning bursts and protects origin capacity during a campaign.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-API-01: API Discovery is enabled

- Module: `api-security` | Domain: API protection | Severity: high | Check confidence: high
- Counters: A1, R2
- Recommendation: Enable API Discovery (and code-repository/crawler discovery where licensed) to find shadow and undocumented endpoints.
- Why: The agent builds its own inventory of your API from source maps and traffic. You need the same inventory first.
- Reference config: `config/xc/http-loadbalancer-security.json`
- Tunable parameters: `{'on': ['enable_api_discovery'], 'off': ['disable_api_discovery']}`

### XC-API-02: API definition is attached with validation

- Module: `api-security` | Domain: API protection | Severity: high | Check confidence: high
- Counters: A1
- Recommendation: Attach an API definition and enable validation (block) for all endpoints, with fall-through set to block or report for undeclared paths.
- Why: Positive security for the API: undeclared routes discovered through source maps return an error before reaching the origin.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-API-03: API protection rules or JWT validation are configured

- Module: `api-security` | Domain: API protection | Severity: high | Check confidence: high
- Counters: C2, A1
- Recommendation: Configure JWT validation (signature, issuer, audience, expiry; reject alg=none) and API protection rules that deny unauthenticated access to non-public endpoints.
- Why: Unsigned tokens and unauthenticated internal routes are both reported techniques.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-DATA-01: Data Guard rules are configured

- Module: `waap` | Domain: Data leakage | Severity: medium | Check confidence: high
- Counters: X1
- Recommendation: Apply Data Guard to paths that return personal or financial data, and enable sensitive data discovery.
- Why: Limits what leaves in responses if an authorization flaw is found.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-SP-01: Service policies are applied

- Module: `waap` | Domain: Recon and enumeration resistance | Severity: high | Check confidence: high
- Counters: R2, C2, P1
- Recommendation: Apply service policies (namespace or custom) that deny known harness User-Agents, canary probe paths, source-map and environment files, and that feed an IP prefix set your SOAR can update.
- Why: Cheap tripwires for the current tooling plus the hook for automated blocking.
- Reference config: `config/xc/service-policy-agentic-markers.json`

### XC-TLS-01: HTTPS only, with TLS 1.2 or higher

- Module: `waap` | Domain: Management plane and exposure | Severity: medium | Check confidence: high
- Counters: E1
- Recommendation: Use HTTPS with HTTP redirect, and High (default) TLS security. Do not use Low security.
- Why: Removes easy scanner findings and downgrade paths.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-TLS-02: HSTS is enabled

- Module: `waap` | Domain: Management plane and exposure | Severity: low | Check confidence: high
- Counters: E1
- Recommendation: Enable the HSTS header on HTTPS load balancers.
- Why: Baseline transport hardening.
- Reference config: `config/xc/http-loadbalancer-security.json`

### XC-LOG-01: A global log receiver streams security events to the SIEM

- Module: `waap` | Domain: Visibility and response | Severity: high | Check confidence: heuristic
- Counters: S1
- Recommendation: Configure a Global Log Receiver for request and security event logs to your SIEM, and alert on the behavioral patterns in the guide.
- Why: Console-only logs cannot drive automated containment.
- Reference config: `config/xc/global-log-receiver.json`

