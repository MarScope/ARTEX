# Agentic Adversary Best Practices for F5 BIG-IP and Distributed Cloud

Version 0.1 (17 November 2026). Field guidance, not an official F5 publication.

## 1. What this guide is for

ARTEX and the frameworks like it (CyberStrikeAI, PentAGI, CAIRN, HexStrike) put a planner LLM in front of ordinary offensive tools and let it run the loop: recon, pick a path, exploit, record what worked, try the next thing. The FBI's FLASH of 13 November 2026 reports intrusions that went from first targeting to privileged access in under three hours, and CrowdStrike attributes a campaign against more than 200 organizations in 11 days to a single controller.

None of the techniques are new. What changed is three properties of the adversary, and each one breaks a habit that many F5 deployments still rely on:

| Property of the agentic adversary | The habit it breaks |
|---|---|
| **Speed and parallelism.** Hours end to end, hundreds of targets at once. | Running WAF and bot policies in transparent mode or with signatures staged, on the assumption a human will review logs in time. |
| **Patience at low rates.** The framework's own pacing profiles are 2, 5 and 20 requests per second per host, and reported password sprays run at about one attempt per second for up to an hour. | Volumetric thresholds sized for floods. A limit of 200 requests per second never fires. |
| **Cheap adaptation.** A new User-Agent per burst, a new source address within minutes of a block, a switch to another endpoint on the same host after a rate limit. | Blocking by IP address or User-Agent and treating the block as containment. |
| **Breadth.** It enumerates everything exposed and starts with the weakest thing. Reported entry points were partner portals, inquiry sites and mobile backends, not the flagship application. | Tuning one policy deeply on the main application and leaving peripheral virtual servers with nothing. |

The guide maps those properties to concrete BIG-IP and Distributed Cloud (XC) settings. Every recommendation has an ID that matches `controls/catalog.json`, a reference configuration under `config/`, and an automated check in the validator.

### What it does not cover

F5 sits in front of applications, APIs and remote access. Much of the reported ARTEX activity never touches that position: OAuth application abuse in Microsoft 365, Graph and Key Vault enumeration, AWS key use, Active Directory lateral movement, supplier trust. A perfect score from this tool says the application edge is ready. It says nothing about the identity provider or the cloud control plane. Use the FBI FLASH and the Google/Mandiant guidance in the references for those.

## 2. Observed behaviors and where F5 can act

Tags are used throughout the catalog.

| Tag | Reported behavior | Primary F5 countermeasure |
|---|---|---|
| R1 | Directory fuzzing (500+ requests), crawling and vulnerability scanning with nuclei, httpx, katana, ffuf, dalfox, nmap, paced at 2 to 20 req/s | Bot Defense client verification; behavioral DoS; XC Malicious User Detection; AFM default-deny |
| R2 | Source maps, `/env.js`, `/assets/config.json`, OpenAPI docs harvested; a not-found canary such as `/zzz-nonexistent-xyz123` requested before route guessing | Disallowed file types; marker iRule or service policy; API schema enforcement |
| C1 | Password spray at a fixed rhythm of about one second for 20 to 60 minutes, new User-Agent per burst | Brute force protection keyed on username and device ID; XC Bot Defense on login; rate limits sized for humans |
| C2 | Unsigned JWTs (`alg: none`) sent to dozens of SSO routes; forged OAuth callbacks; unsigned SAML | JWT validation (XC); marker iRule (BIG-IP); APM as the SAML SP with signature validation |
| C3 | Recovery, sign-up and self-registration abuse | Treat these as login pages: Bot Defense protected endpoints, brute force protection, rate limits |
| E1 | SQL injection, command injection, SSTI, XXE, SSRF, authentication bypass, anonymous upload | WAF in blocking with signatures enforced, threat campaigns on |
| E2 | JSP, PHP and ASPX web shells | Disallowed file types on upload paths; WAF response checks; server technology signature sets |
| A1 | Unauthenticated internal API routes, IDOR, sequential enumeration, bulk lookups | API discovery and schema validation; session tracking; per-user rate limits |
| X1 | Structured personal and financial data leaving over HTTPS | Data Guard; XC sensitive data discovery |
| P1 | Residential proxies, Tor, SOCKS relays; blocked addresses replaced within minutes | Device ID and user-keyed controls; IP Intelligence and Threat Mesh as cost-raisers; SOAR-fed feed lists |
| V1 | Stolen VPN configurations and leaked credentials | APM MFA, session binding, per-request policy |
| M1 | Exposed management interfaces | httpd/sshd allow lists, port lockdown, AFM management rules |
| S1 | Under three hours to privileged access | Enforcement instead of observation; off-box logging; automated response |

## 3. Seven principles

1. **Cover the periphery first.** One unprotected legacy virtual server outweighs a finely tuned policy on the main site. Coverage controls (BIP-WAF-01, BIP-BOT-01, XC-WAF-01) are critical severity for this reason.
2. **Enforce, don't observe.** Transparent mode and signature staging are tuning states, not operating states. If a policy cannot be put into blocking, that is a finding to fix, not a steady state to accept.
3. **Identify the actor, not the address.** Device ID, username, session and XC user identifier survive proxy rotation. IP reputation raises the adversary's cost and is worth having, but it is not containment.
4. **Size thresholds for humans.** Nobody types five passwords a minute. Limits on authentication, recovery and lookup endpoints should sit just above real human use, per user and per device.
5. **Positive security for APIs.** After the agent reads your source maps it knows your internal routes. A schema that rejects undeclared paths, methods and parameters turns that knowledge into 4xx responses.
6. **Shrink the management plane.** The ADC must not be an entry point. Allow lists, port lockdown and current software come before any application control.
7. **Automate the response.** Published observations describe new source addresses appearing within minutes of a block. A response that needs a change ticket will lose. Wire logs to the SIEM and give SOAR a feed list or prefix set it can write to.

One caution on indicators. The marker iRule and service policy in this repository match published harness User-Agents, canary paths and unsigned tokens. They are cheap and currently high-signal, and an operator defeats each with one line of configuration. Deploy them as tripwires and hunt sources. Do not count them as protection.

## 4. BIG-IP

### 4.1 Management plane (base system)

| Control | Setting | Recommended value |
|---|---|---|
| BIP-MGT-01 | TMOS release | A line still receiving security fixes, with the latest quarterly security notification applied |
| BIP-MGT-02 | `sys httpd allow` | Explicit admin subnets; never `All` |
| BIP-MGT-03 | `sys sshd allow` | Explicit admin subnets; never `All` |
| BIP-MGT-04 | `net self ... allow-service` | `none` on data-plane self IPs; explicit list on the HA self IP |
| BIP-MGT-05 | `auth password-policy` | Enforcement on, minimum length 14, lockout after 3 to 10 failures; remote auth with MFA preferred |
| BIP-MGT-06 | `sys syslog remote-servers` | At least one off-box destination |
| BIP-MGT-07 | `sys httpd auth-pam-idle-timeout` | 1200 seconds or less |

Config: `config/bigip/01-management-plane.tmsh`.

### 4.2 Advanced WAF

| Control | Setting | Recommended value |
|---|---|---|
| BIP-WAF-01 | Policy coverage | Every internet-facing HTTP virtual server |
| BIP-WAF-02 | Enforcement mode | Blocking |
| BIP-WAF-03 | Signature staging | Off; do not re-stage on update |
| BIP-WAF-04 | Signature sets | Generic Detection (High/Medium) plus server-technology sets, Block on |
| BIP-WAF-05 | Live update | Attack signatures, bot signatures and threat campaigns on a schedule; under 30 days old |
| BIP-WAF-06 | Brute force protection | Login pages defined for login, recovery and registration; per-username and per-device thresholds of 5; distributed and credential-stuffing detection on |
| BIP-WAF-07 | Session tracking | Session awareness on, device ID tracking on, block after 5 violations per user/device/session in 15 minutes |
| BIP-WAF-08 | Data Guard | On, masking |
| BIP-WAF-09 | IP Intelligence | Anonymous Proxy, Tor Proxies, Scanners, Web Attacks, BotNets blocked |
| BIP-WAF-10 | Threat Campaigns | Violation set to block, no staging |
| BIP-WAF-11 | Evasion and HTTP compliance | Block |
| BIP-WAF-12 | Disallowed file types | `map`, `env`, `git`, `bak`, `old`, `config`, `sql`, `log` |
| BIP-WAF-13 | API schema | OpenAPI file imported for API endpoints |

Config: `config/bigip/03-awaf-policy.json` (declarative policy fragment).

The two settings that matter most against this threat are BIP-WAF-03 and BIP-WAF-06. Staging is the default for new and updated signatures and silently removes blocking. Brute force protection without defined login pages does nothing, and with only the per-IP threshold enabled it sees one failure per source during a distributed spray.

### 4.3 Bot Defense and behavioral DoS

| Control | Setting | Recommended value |
|---|---|---|
| BIP-BOT-01 | Profile coverage | Every internet-facing HTTP virtual server |
| BIP-BOT-02 | `enforcement-mode` | `blocking` |
| BIP-BOT-03 | `template` | `strict` on authentication and high-value flows, `balanced` elsewhere; not `relaxed` |
| BIP-BOT-04 | `deviceid-mode` | `generate-after-access` (or `generate-before-access` on login flows) |
| BIP-BOT-05 | `api-access-strict-mitigation` | `enabled`; Anti-Bot Mobile SDK for native apps |
| BIP-DOS-01 | DoS profile | Stress-based blocking with Behavioral DoS detection and signatures on |

Config: `config/bigip/04-bot-defense.tmsh`.

Bot Defense is the control whose effectiveness does not depend on request rate, source address or User-Agent, which are the three things the framework varies. The workers are command-line HTTP clients and Go programs; they do not execute a JavaScript challenge unless the operator moves to a real browser, which costs them speed and scale.

### 4.4 AFM

| Control | Setting | Recommended value |
|---|---|---|
| BIP-AFM-01 | Enforced firewall policy | Global or per virtual server, default deny |
| BIP-AFM-02 | IP Intelligence policy | Global; drop proxy, Tor, scanner, botnet categories; a feed list for SOAR-pushed blocks polled every 60 seconds |
| BIP-AFM-03 | Management-IP rules | Admin subnets to 443/22, drop the rest, logged |
| BIP-LOG-01 | Security log profile | Attached to every HTTP virtual server, publishing remotely (available with ASM or AFM) |

Config: `config/bigip/05-afm.tmsh`.

### 4.5 APM

| Control | Setting | Recommended value |
|---|---|---|
| BIP-APM-01 | Second factor in the per-session policy | Certificate or FIDO2 through the IdP preferred; OTP/RADIUS push at minimum |
| BIP-APM-02 | Session binding | `restrict-to-single-client-ip`, `secure-cookie`, `httponly-cookie` on |
| BIP-APM-03 | Session lifetime | Inactivity 900 s, maximum 12 hours |
| BIP-APM-04 | `max-in-progress-sessions` per client IP | 32 or lower |
| BIP-APM-05 | Per-request policy | Attached to every access virtual server |

Config: `config/bigip/07-apm.tmsh`.

IP binding breaks roaming mobile clients. Where that is a real constraint, keep it off for that profile and compensate with posture checks and the per-request policy; the validator will show a partial result and that is the correct reading.

## 5. Distributed Cloud

| Control | Setting | Recommended value |
|---|---|---|
| XC-WAF-01 | App Firewall on every HTTP load balancer | Attached |
| XC-WAF-02 | Enforcement mode | Blocking |
| XC-WAF-03 | Detection settings | Threat Campaigns on; High and Medium accuracy signatures |
| XC-WAF-04 | Bot protection setting | Malicious: Block. Suspicious: Block or Report |
| XC-BOT-01 | Bot Defense | Protected endpoints for login, reset, registration, search and bulk lookups; mitigation Block |
| XC-MUD-01 | Malicious User Detection | On, with the mitigation challenge enabled (JS challenge, CAPTCHA, temporary block by threat level) |
| XC-RL-01 | Rate limiting | On; API rate limits on authentication and lookup endpoints sized for human use |
| XC-REP-01 | IP Reputation | On with Tor Proxy, Proxy, Scanners at minimum |
| XC-REP-02 | Threat Mesh | On |
| XC-DDOS-01 | L7 DDoS auto-mitigation | Block or JS challenge |
| XC-API-01 | API Discovery | On |
| XC-API-02 | API definition | Attached, validation active, undeclared paths blocked |
| XC-API-03 | JWT validation or API protection rules | Signature, issuer, audience and expiry validated; unauthenticated access to non-public endpoints denied |
| XC-DATA-01 | Data Guard | Rules on paths returning personal or financial data |
| XC-SP-01 | Service policies | Active custom policy list including the marker policy and a SOAR-managed prefix set |
| XC-TLS-01 | TLS | HTTPS with redirect; Default (high) security; never Low |
| XC-TLS-02 | HSTS | On |
| XC-LOG-01 | Global Log Receiver | Security events streamed to the SIEM |

Config: `config/xc/`.

Malicious User Detection deserves emphasis. It builds a per-user threat level from WAF events, failed logins, forbidden responses and rate behavior, then escalates mitigation without a human. That is the closest built-in match to an adversary that works slowly across many small probes. It only acts if the challenge policy is enabled alongside detection; detection alone produces a score that nothing uses, which the validator reports as partial.

Two XC items the validator cannot check from the API and you should confirm by hand: that origins accept traffic only from XC (otherwise the agent goes around the load balancer once it finds the origin address), and that the user identifier policy is something better than client IP where a session cookie or token is available.

## 6. Detection on F5 logs

These are behavioral, so they survive a change of indicators. They assume request logs reach a SIEM (BIP-LOG-01, XC-LOG-01).

| Signal | What to look for |
|---|---|
| Spray rhythm | One source or one device ID producing 200 or more authentication failures across 20 or more usernames in an hour with a median gap of two seconds or less |
| Spray then success | A successful login from a source or device that failed against 20 or more other usernames |
| Recon marker cluster | Two or more of: source map request, runtime config request, not-found canary, unsigned token, forged OAuth callback, from one source within ten minutes. The marker iRule logs these with the prefix `AAR marker=` |
| Internal route discovery | Requests to API paths not present in the published schema within minutes of a source map download |
| Sequential enumeration | Monotonic or dictionary-ordered identifiers in a lookup endpoint from one session |
| Rate-limit pivot | A 429 or challenge on one endpoint followed within seconds by the same client fingerprint on a different endpoint of the same host |
| Rotation after block | A blocked device ID or TLS fingerprint reappearing from a new address |

## 7. Automating the response

- **BIG-IP:** an AFM IP Intelligence feed list polled every 60 seconds, written by SOAR from the detections above. Session tracking and brute force protection act on device ID and username without outside help.
- **XC:** a shared IP prefix set referenced by the marker service policy, updated through the API; Malicious User Detection with mitigation handles the per-user escalation.
- **Both:** preserve logs before blocking shared cloud addresses, as the FBI advises, and vet published indicators against your own telemetry. Addresses rotate and are reassigned.

## 8. How the readiness score works

- Each control has a severity weight: critical 10, high 6, medium 3, low 1.
- A check returns 1 (pass), 0 (fail), or a fraction, normally the share of virtual servers, policies or load balancers that comply.
- **Readiness** = sum(weight x result) / sum(weight) across all controls for the platform, on a 0 to 100 scale. Controls that need a module that is not provisioned score zero.
- **Configuration score** is the same calculation over provisioned capabilities only. **Capability coverage** is the share of catalog weight those capabilities represent. The gap between readiness and configuration score is what licensing or provisioning would buy.
- Controls the tool could not read are reported as Unknown and left out of the arithmetic.
- Tiers: 85 and above Ready; 70 to 84 Mostly ready; 50 to 69 Exposed; below 50 Unprepared. If any critical control is below half, the tier cannot rise above Exposed whatever the number says.

The weights are a judgment, set out in `controls/build_catalog.py` so they can be argued with and changed. The number is useful for comparing a device to itself over time and for ranking a fleet. It is not a probability of compromise.

## 9. References

- FBI, FLASH-20261113-001, *Threat Overview of ARTEX Autonomous Penetration Testing Framework*, 13 November 2026: https://www.ic3.gov/CSA/2026/261113.pdf
- Google Threat Intelligence Group and Mandiant, *ARTEX and Friends: Enter Agentic Offensive Frameworks*: https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- Zscaler ThreatLabz, *Threat Actor Abuses Agentic AI Pentesting Framework to Target South Korean Financial Institutions*: https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean
- ThreatDefence, *ARTEX Agentic Attack Framework: Detection and Hunting*, 16 November 2026: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Elastic Security Labs, *Inside the loop: Five AI attack frameworks that never ask permission*: https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex
- Censys, *ARTEX: Agentic Asbestos*: https://censys.com/blog/artex-agentic-asbestos/
- Cloud Security Alliance, *ARTEX and Its Forks: Agentic Pentest Frameworks as Attack Infrastructure*: https://labs.cloudsecurityalliance.org/research/csa-research-note-artex-agentic-pentest-frameworks-in-the-wi/
- Pacing profiles (2, 5, 20 requests per second) are read from `egress/egress.go` in this repository.
