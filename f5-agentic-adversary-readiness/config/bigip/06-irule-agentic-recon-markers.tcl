# agentic_recon_markers  (control BIP-LTM-01)
#
# Tripwire for markers reported in ARTEX-driven recon as of November 2026:
#   - harness User-Agent strings (artex-*, ARTeX, ScopeWeaver, ReconProbe, azure-toolkit)
#   - the not-found canary path requested before route guessing
#   - source map and runtime config harvesting
#   - unsigned (alg=none) JWTs
#
# An operator changes every one of these with one config line. This rule is an early-warning
# signal and a log source for hunts. It is not the control: Bot Defense, brute force protection
# and WAF enforcement are. Review the config-probe list against your own application first;
# some single-page apps legitimately serve /env.js.
#
# Reference template. Validate in a lab. Attach to internet-facing HTTP virtual servers.

when RULE_INIT {
    set static::aar_block 1
    set static::aar_ua_markers { "artex" "scopeweaver" "reconprobe/" "azure-toolkit/" "authorized-pentest" }
}

when HTTP_REQUEST {
    set aar_hit ""
    set aar_ua [string tolower [HTTP::header value "User-Agent"]]
    foreach m $static::aar_ua_markers {
        if { $aar_ua contains $m } { set aar_hit "ua:$m"; break }
    }

    if { $aar_hit eq "" } {
        set aar_path [string tolower [HTTP::path]]
        if { ($aar_path starts_with "/zzz-nonexistent") or ($aar_path contains "nonexistent-xyz") } {
            set aar_hit "canary-path"
        } elseif { ($aar_path ends_with ".js.map") or ($aar_path ends_with ".css.map") } {
            set aar_hit "source-map"
        } elseif { ($aar_path eq "/env.js") or ($aar_path eq "/.env") or ($aar_path starts_with "/.git/") or ($aar_path eq "/assets/config.json") } {
            set aar_hit "config-probe"
        }
    }

    if { $aar_hit eq "" } {
        set aar_auth [HTTP::header value "Authorization"]
        if { [string tolower [string range $aar_auth 0 6]] eq "bearer " } {
            # Decode the JWT header segment (base64url) and look for alg=none in any letter case.
            set aar_seg [lindex [split [string range $aar_auth 7 end] "."] 0]
            set aar_seg [string map { "-" "+" "_" "/" } $aar_seg]
            append aar_seg [string repeat "=" [expr { (4 - [string length $aar_seg] % 4) % 4 }]]
            if { ![catch { b64decode $aar_seg } aar_dec] } {
                if { [string tolower $aar_dec] matches_regex {"alg"\s*:\s*"none"} } { set aar_hit "jwt-alg-none" }
            }
        }
    }

    if { $aar_hit ne "" } {
        log local0.warning "AAR marker=$aar_hit client=[IP::client_addr] vs=[virtual name] host=[HTTP::host] uri=[HTTP::uri] ua=\"[HTTP::header value User-Agent]\""
        if { $static::aar_block } {
            HTTP::respond 404 content "" noserver Connection close
            return
        }
    }
}
