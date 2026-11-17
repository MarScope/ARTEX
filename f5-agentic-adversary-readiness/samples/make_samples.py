#!/usr/bin/env python3
"""Generates the synthetic demo snapshots. No real device data. Run after changing collectors or checks."""
import json, os
H = os.path.dirname(os.path.abspath(__file__))
V = "/mgmt/tm/ltm/virtual?expandSubcollections=true"

def prof(*names):
    return {"items": [{"name": n.split("/")[-1], "fullPath": n} for n in names]}

P1, P2 = "aB3xPortalPolicy0001", "cD4yLegacyPolicy0002"
b = {
 "/mgmt/tm/sys/version": {"entries": {"https://localhost/mgmt/tm/sys/version/0": {"nestedStats": {"entries": {"Version": {"description": "17.1.2"}}}}}},
 "/mgmt/tm/sys/provision": {"items": [{"name": "ltm", "level": "nominal"}, {"name": "asm", "level": "nominal"},
                                      {"name": "apm", "level": "nominal"}, {"name": "afm", "level": "none"}]},
 "/mgmt/tm/sys/httpd": {"allow": ["10.20.0.0/24"], "authPamIdleTimeout": 1200},
 "/mgmt/tm/sys/sshd": {"allow": ["ALL"]},
 "/mgmt/tm/sys/syslog": {"remoteServers": [{"name": "siem", "host": "10.20.0.50", "remotePort": 6514}]},
 "/mgmt/tm/auth/password-policy": {"policyEnforcement": "enabled", "minimumLength": 8, "maxLoginFailures": 0},
 "/mgmt/tm/net/self": {"items": [{"fullPath": "/Common/external_self", "allowService": ["default"]},
                                 {"fullPath": "/Common/internal_self", "allowService": "none"},
                                 {"fullPath": "/Common/ha_self", "allowService": ["tcp:4353", "udp:1026"]}]},
 "/mgmt/tm/ltm/profile/http": {"items": [{"fullPath": "/Common/http"}, {"fullPath": "/Common/http_xff"}]},
 "/mgmt/tm/ltm/profile/client-ssl": {"items": [
     {"fullPath": "/Common/cssl_modern", "tmOptions": ["dont-insert-empty-fragments", "no-tlsv1", "no-tlsv1.1"], "ciphers": "none", "cipherGroup": "/Common/f5-secure"},
     {"fullPath": "/Common/cssl_legacy", "tmOptions": ["dont-insert-empty-fragments"], "ciphers": "DEFAULT", "cipherGroup": "none"}]},
 V: {"items": [
     {"fullPath": "/Common/vs_customer_portal", "profilesReference": prof("/Common/http_xff", "/Common/cssl_modern", "/Common/websecurity", "/Common/bot_strict", "/Common/dos_portal"),
      "securityLogProfiles": ["/Common/log_all_remote"], "rules": ["/Common/agentic_recon_markers"]},
     {"fullPath": "/Common/vs_partner_api", "profilesReference": prof("/Common/http", "/Common/cssl_modern", "/Common/websecurity", "/Common/bot_relaxed"),
      "securityLogProfiles": ["/Common/log_all_remote"]},
     {"fullPath": "/Common/vs_legacy_hr", "profilesReference": prof("/Common/http", "/Common/cssl_legacy")},
     {"fullPath": "/Common/vs_vpn", "profilesReference": prof("/Common/http", "/Common/cssl_modern", "/Common/ap_vpn")},
     {"fullPath": "/Common/vs_old_disabled", "disabled": True, "profilesReference": prof("/Common/http")}]},
 "/mgmt/tm/security/bot-defense/profile": {"items": [
     {"fullPath": "/Common/bot_strict", "enforcementMode": "blocking", "template": "strict", "deviceidMode": "generate-after-access", "apiAccessStrictMitigation": "enabled"},
     {"fullPath": "/Common/bot_relaxed", "enforcementMode": "transparent", "template": "relaxed", "deviceidMode": "none", "apiAccessStrictMitigation": "disabled"}]},
 "/mgmt/tm/security/dos/profile?expandSubcollections=true": {"items": [
     {"fullPath": "/Common/dos_portal", "applicationReference": {"items": [{"stressBased": {"mode": "blocking", "behavioral": {"dosDetection": "enabled", "signatures": "enabled"}}}]}}]},
 "/mgmt/tm/security/log/profile": {"items": [{"fullPath": "/Common/log_all_remote"}]},
 "/mgmt/tm/asm/policies": {"items": [
     {"id": P1, "name": "portal_policy", "fullPath": "/Common/portal_policy", "enforcementMode": "blocking", "virtualServers": ["/Common/vs_customer_portal"]},
     {"id": P2, "name": "partner_api_policy", "fullPath": "/Common/partner_api_policy", "enforcementMode": "transparent", "virtualServers": ["/Common/vs_partner_api"]}]},
 "/mgmt/tm/live-update/asm-attack-signatures/installations": {"items": [{"status": "install-complete", "addDateTime": "2026-10-28T03:10:00Z"}]},
 "/mgmt/tm/apm/profile/access": {"items": [
     {"fullPath": "/Common/access"},
     {"fullPath": "/Common/ap_vpn", "restrictToSingleClientIp": "false", "secureCookie": "true", "httponlyCookie": "false",
      "inactivityTimeout": 900, "maxSessionTimeout": 604800, "maxInProgressSessions": 128}]},
 "/mgmt/tm/apm/policy/policy-item": {"items": [{"fullPath": "/Common/ap_vpn_act_logon_page"}, {"fullPath": "/Common/ap_vpn_act_active_directory_auth"},
                                                {"fullPath": "/Common/ap_vpn_act_full_resource_assign"}]},
}
def asm(pid, staging, lp, bf, sess, dg, ipi, tc_block, ft, oa):
    base = "/mgmt/tm/asm/policies/%s/" % pid
    b[base + "signature-settings"] = {"signatureStaging": staging}
    b[base + "login-pages"] = {"items": lp}
    b[base + "brute-force-attack-preventions"] = {"items": bf}
    b[base + "session-tracking"] = {"sessionTrackingConfiguration": {"enableSessionAwareness": sess}}
    b[base + "data-guard"] = {"enabled": dg}
    b[base + "ip-intelligence"] = {"enabled": ipi}
    b[base + "blocking-settings/violations"] = {"items": [
        {"description": "Threat Campaign detected", "block": tc_block, "alarm": True},
        {"description": "Evasion technique detected", "block": True, "alarm": True},
        {"description": "HTTP protocol compliance failed", "block": tc_block, "alarm": True}]}
    b[base + "signature-sets"] = {"items": [{"block": True, "alarm": True, "learn": True}]}
    b[base + "filetypes"] = {"items": [{"name": "*", "allowed": True}] + [{"name": n, "allowed": False} for n in ft]}
    b[base + "open-api-files"] = {"items": oa}
    b[base + "json-profiles"] = {"items": [{"name": "Default"}]}
asm(P1, False, [{"id": "1"}], [{"id": "1"}], True, True, True, True, ["map", "env", "bak", "git", "sql"], [])
asm(P2, True, [], [], False, False, False, False, ["bak"], [{"id": "1"}])
json.dump({"platform": "bigip", "target": "demo-bigip.example.com (synthetic)", "collected_at": "2026-11-17T18:00:00Z", "data": b},
          open(os.path.join(H, "bigip-demo-snapshot.json"), "w"), indent=1)

x = {"namespaces": ["retail", "partners"], "http_loadbalancers": {
  "retail/www": {"spec": {"https_auto_cert": {"http_redirect": True, "add_hsts": True, "tls_config": {"default_security": {}}},
      "app_firewall": {"namespace": "shared", "name": "waf-blocking"}, "bot_defense": {"policy": {}}, "enable_malicious_user_detection": {},
      "enable_challenge": {}, "rate_limit": {}, "enable_ip_reputation": {"ip_threat_categories": ["TOR_PROXY", "PROXY", "SCANNERS", "BOTNETS", "WEB_ATTACKS"]},
      "enable_threat_mesh": {}, "l7_ddos_action_default": {}, "enable_api_discovery": {}, "disable_api_definition": {},
      "data_guard_rules": [{"metadata": {"name": "all"}}], "active_service_policies": {"policies": [{"name": "agentic-markers"}]}}},
  "retail/api": {"spec": {"https": {"http_redirect": True, "add_hsts": False, "tls_cert_params": {"tls_config": {"default_security": {}}}},
      "app_firewall": {"namespace": "shared", "name": "waf-blocking"}, "js_challenge": {}, "enable_malicious_user_detection": {},
      "api_rate_limit": {}, "enable_ip_reputation": {"ip_threat_categories": ["BOTNETS"]}, "disable_threat_mesh": {}, "l7_ddos_action_default": {},
      "enable_api_discovery": {}, "api_specification": {"api_definition": {"name": "retail-v2"}, "validation_disabled": {}},
      "service_policies_from_namespace": {}}},
  "partners/supplier-portal": {"spec": {"https": {"http_redirect": False, "tls_parameters": {"tls_config": {"low_security": {}}}},
      "app_firewall": {"namespace": "partners", "name": "waf-monitor"}, "no_challenge": {}, "disable_malicious_user_detection": {},
      "disable_rate_limit": {}, "disable_ip_reputation": {}, "disable_threat_mesh": {}, "l7_ddos_action_none": {},
      "disable_api_discovery": {}, "disable_api_definition": {}, "no_service_policies": {}}}},
 "app_firewalls": {"shared/waf-blocking": {"spec": {"blocking": {}, "default_detection_settings": {}, "default_bot_setting": {}}},
                   "partners/waf-monitor": {"spec": {"monitoring": {}, "detection_settings": {"disable_threat_campaigns": {},
                        "signature_selection_setting": {"only_high_accuracy_signatures": {}}},
                        "bot_protection_setting": {"malicious_bot_action": "REPORT", "suspicious_bot_action": "IGNORE"}}}},
 "global_log_receivers": {"shared": {"items": []}, "system": {"_error": "HTTP 403"}}}
json.dump({"platform": "xc", "target": "demo-tenant.console.ves.volterra.io (synthetic)", "collected_at": "2026-11-17T18:00:00Z", "data": x},
          open(os.path.join(H, "xc-demo-snapshot.json"), "w"), indent=1)
print("samples written")
