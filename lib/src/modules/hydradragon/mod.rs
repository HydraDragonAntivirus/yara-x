//! `hydradragon` — HIPS (Host Intrusion Prevention System) module for Android.
//!
//! Inspired by the Koodous `androguard` YARA module, but completely rewritten
//! from the ground up: very different and far more capable, combining dynamic
//! behavioral analysis with the static APK signals Koodous exposed.
//!
//! Provides both network-level and behavioral-level signals for YARA-X rules:
//!
//! **Network** (MITM-free DNS-only Web-Shield + VpnService full-tunnel):
//!   * `hydradragon.network.dns_lookup(regex)` — DNS domains the app resolved
//!   * `hydradragon.network.host(regex)` — destination IPs from DNS resolution
//!   * `hydradragon.network.payload_hex(hex)` — byte pattern in captured packets
//!   * `hydradragon.network.http_request(regex)` — HTTP request URI (any method, cleartext only)
//!   * `hydradragon.network.http_get(regex)` — HTTP GET request URI
//!   * `hydradragon.network.http_post(regex)` — HTTP POST request URI
//!   * `hydradragon.network.http_user_agent(regex)` — HTTP User-Agent header
//!   * `hydradragon.network.tcp(regex)` — TCP connection dst_ip/dst_port match
//!   * `hydradragon.network.udp(regex)` — UDP connection dst_ip/dst_port match
//!   * `hydradragon.url(regex)` / `hydradragon.url(string)` — full URLs contacted
//!   * `hydradragon.screen_text(regex)` — OCR-captured on-screen text
//!
//! **Behavioral HIPS** (accessibility service, file system, system state):
//!   * `hydradragon.ui_spam(package_re)` — UI click/window spam detection
//!   * `hydradragon.notification_spam(package_re)` — notification spam detection
//!   * `hydradragon.clickjack(package_re)` — clickjacking detection
//!   * `hydradragon.ransomware_behavior(package_re)` — ransomware rename burst
//!   * `hydradragon.canary_triggered(package_re)` — decoy file trap hit
//!   * `hydradragon.strandhogg(package_re)` — StrandHogg protection
//!   * `hydradragon.rooted()` — device rooted check
//!   * `hydradragon.debug_mode()` — USB/debug mode check
//!   * `hydradragon.behavior_flagged(package_re)` — behavioral flag count
//!   * `hydradragon.foreground_package(regex)` — foreground app match
//!   * `hydradragon.observed_packages(regex)` — observed apps count
//!   * `hydradragon.network_connections(package_re)` — network connections
//!   * `hydradragon.removal_resistance(package_re)` — removal resistance kick count
//!   * `hydradragon.launcher_change(package_re)` — default launcher change attempt score
//!
//! **Per-package HIPS metadata** (runtime checks, passed via JSON):
//!   * `hydradragon.device_admin(package_re)` — 1 if the package is an active Device Administrator
//!   * `hydradragon.hidden_app(package_re)` — 1 if the package has no launcher icon (hidden app)
//!
//! **Crypto-miner detection** (runtime CPU + memory profiling):
//!   * `hydradragon.miner_count(package_re)` — count of miner events for matching packages
//!   * `hydradragon.miner_cpu(package_re)` — max sustained CPU usage % (0-100)
//!   * `hydradragon.miner_memory(package_re)` — max resident memory (MB) at detection
//!   * `hydradragon.miner_known_name(name_re)` — 1 if any known miner process name matches
//!
//! **Static DEX analysis** (project's own dex-parser-analyzer engine):
//!   * `hydradragon.dex_finding(regex)` — static findings whose message matches
//!   * `hydradragon.dex_severe_finding_count()` — High/Critical finding count
//!
//! **Static APK analysis** (external report, Koodous-style but reimplemented):
//!   * `hydradragon.certificate.issuer(regex|string)` — certificate issuer DN
//!   * `hydradragon.certificate.subject(regex|string)` — certificate subject DN
//!   * `hydradragon.certificate.sha1("hex")` — certificate SHA-1
//!   * `hydradragon.app_name(regex|string)`, `hydradragon.package_name(regex|string)`
//!   * `hydradragon.permission(regex|string)` — declared permission
//!   * `hydradragon.activity / main_activity / service / receiver(regex|string)`
//!   * `hydradragon.min_sdk / max_sdk / target_sdk` — integers
//!   * `hydradragon.permissions_number` — number of declared permissions
//!   * `hydradragon.rootkit_behavior()` — hidden launcher + suspicious perms
//!   * `hydradragon.device_admin_permission()` — BIND_DEVICE_ADMIN declared
//!   * `hydradragon.metadata(regex|string)` — manifest `<meta-data>` name

use crate::compiler::RegexId;
use crate::mods::prelude::*;
use crate::modules::protos::hydradragon::*;

use base64::Engine;

mod schema;

use std::cell::RefCell;
use std::rc::Rc;
thread_local! {
    static LOCAL_DATA: RefCell<Option<Rc<schema::HydradragonJson>>> = const { RefCell::new(None) };
    /// Hash of the metadata bytes last parsed into LOCAL_DATA. Phase 3 rescans
    /// the same hydradragon JSON against many buffers; without this every
    /// scan() call re-ran serde_json::from_slice over the (potentially large)
    /// report. Caching by content hash makes it parse once per distinct report.
    static LOCAL_DATA_HASH: RefCell<u64> = const { RefCell::new(0) };
}

fn get_local() -> Option<Rc<schema::HydradragonJson>> {
    LOCAL_DATA.with(|data| data.borrow().clone())
}

fn set_local(value: schema::HydradragonJson) {
    LOCAL_DATA.with(|data| {
        *data.borrow_mut() = Some(Rc::new(value));
    });
}

/// FNV-1a hash of the raw metadata bytes — cheap, no allocation.
fn meta_hash(meta: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in meta {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build the protobuf output from an already-parsed report (cheap: a few
/// integer field copies), used both on a fresh parse and a cache hit.
fn build_output(report: &schema::HydradragonJson) -> Hydradragon {
    let mut out = Hydradragon::new();
    if let Some(v) = report.min_sdk_version {
        out.set_min_sdk(v);
    }
    if let Some(v) = report.max_sdk_version {
        out.set_max_sdk(v);
    }
    if let Some(v) = report.target_sdk_version {
        out.set_target_sdk(v);
    }
    out.set_permissions_number(
        report.permissions.as_ref().map(|p| p.len() as i64).unwrap_or(0),
    );
    out
}

fn main(
    _ctx: &mut ModuleContext,
    _data: &[u8],
) -> Result<Hydradragon, ModuleError> {
    let meta = match _ctx
        .get_module_metadata("hydradragon")
        .or_else(|| _ctx.get_module_metadata("androguard"))
    {
        None | Some([]) => {
            set_local(schema::HydradragonJson::default());
            LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = 0);
            return Ok(Hydradragon::new());
        }
        Some(meta) => meta,
    };

    // Skip re-parsing if this exact metadata was already parsed on this thread
    // (Phase 3 scans the same report against many buffers).
    let hash = meta_hash(meta);
    let already = LOCAL_DATA_HASH.with(|h| *h.borrow()) == hash
        && get_local().is_some();
    if already {
        if let Some(cached) = get_local() {
            return Ok(build_output(&cached));
        }
    }

    match serde_json::from_slice::<schema::HydradragonJson>(meta) {
        Ok(parsed) => {
            let out = build_output(&parsed);
            set_local(parsed);
            LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = hash);
            Ok(out)
        }
        Err(e) => {
            set_local(schema::HydradragonJson::default());
            LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = 0);
            return Err(ModuleError::MetadataError { err: e.to_string() });
        }
    }
}

// ── Network functions ────────────────────────────────────────────────────────

// ── Cuckoo-compatible HTTP functions (parse from raw packet captures) ─────

/// Helper: parse HTTP request info from a base64-decoded packet payload.
/// Returns (method, uri, user_agent) if it looks like an HTTP request.
fn parse_http_from_payload(payload: &[u8]) -> Option<(String, String, Option<String>)> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.lines();

    let request_line = lines.next()?;
    // Request line: "GET /path HTTP/1.1" or "POST /path?query HTTP/1.0"
    let (method, uri) = {
        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return None;
        }
        let m = parts[0].to_uppercase();
        if !matches!(m.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT") {
            return None;
        }
        (m, parts[1].to_string())
    };

    // Scan headers for User-Agent
    let mut user_agent: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(val) = line.strip_prefix("User-Agent:")
            .or_else(|| line.strip_prefix("user-agent:"))
            .or_else(|| line.strip_prefix("USER-AGENT:"))
        {
            user_agent = Some(val.trim().to_string());
            // don't break — keep scanning but UA is what we want
        }
    }

    Some((method, uri, user_agent))
}

#[module_export(name = "network.http_request")]
fn network_http_request_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("TCP") {
            continue;
        }
        let payload = match pkt.payload_b64.as_ref()
            .and_then(|b64| engine.decode(b64).ok())
        {
            Some(p) => p,
            None => continue,
        };
        if let Some((_method, uri, _ua)) = parse_http_from_payload(&payload) {
            if ctx.regexp_matches(re, uri.as_bytes()) {
                count += 1;
            }
        }
    }
    count
}

#[module_export(name = "network.http_get")]
fn network_http_get_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("TCP") {
            continue;
        }
        let payload = match pkt.payload_b64.as_ref()
            .and_then(|b64| engine.decode(b64).ok())
        {
            Some(p) => p,
            None => continue,
        };
        if let Some((method, uri, _ua)) = parse_http_from_payload(&payload) {
            if method == "GET" && ctx.regexp_matches(re, uri.as_bytes()) {
                count += 1;
            }
        }
    }
    count
}

#[module_export(name = "network.http_post")]
fn network_http_post_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("TCP") {
            continue;
        }
        let payload = match pkt.payload_b64.as_ref()
            .and_then(|b64| engine.decode(b64).ok())
        {
            Some(p) => p,
            None => continue,
        };
        if let Some((method, uri, _ua)) = parse_http_from_payload(&payload) {
            if method == "POST" && ctx.regexp_matches(re, uri.as_bytes()) {
                count += 1;
            }
        }
    }
    count
}

#[module_export(name = "network.http_user_agent")]
fn network_http_user_agent_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("TCP") {
            continue;
        }
        let payload = match pkt.payload_b64.as_ref()
            .and_then(|b64| engine.decode(b64).ok())
        {
            Some(p) => p,
            None => continue,
        };
        if let Some((_method, _uri, ua)) = parse_http_from_payload(&payload) {
            if let Some(ua_str) = ua {
                if ctx.regexp_matches(re, ua_str.as_bytes()) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Match TCP packets where dst_ip or dst_port match the regex.
/// Counts matching packets.
#[module_export(name = "network.tcp")]
fn network_tcp_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("TCP") {
            continue;
        }
        let mut matched = false;
        if let Some(ref dst) = pkt.dst_ip {
            if ctx.regexp_matches(re, dst.as_bytes()) {
                matched = true;
            }
        }
        if !matched {
            if let Some(port) = pkt.dst_port {
                let port_str = port.to_string();
                if ctx.regexp_matches(re, port_str.as_bytes()) {
                    matched = true;
                }
            }
        }
        if matched {
            count += 1;
        }
    }
    count
}

/// Match UDP packets where dst_ip or dst_port match the regex.
/// Counts matching packets.
#[module_export(name = "network.udp")]
fn network_udp_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let packets = match local.as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    {
        Some(p) => p,
        None => return 0,
    };
    let mut count: i64 = 0;
    for pkt in packets {
        if pkt.protocol.as_deref() != Some("UDP") {
            continue;
        }
        let mut matched = false;
        if let Some(ref dst) = pkt.dst_ip {
            if ctx.regexp_matches(re, dst.as_bytes()) {
                matched = true;
            }
        }
        if !matched {
            if let Some(port) = pkt.dst_port {
                let port_str = port.to_string();
                if ctx.regexp_matches(re, port_str.as_bytes()) {
                    matched = true;
                }
            }
        }
        if matched {
            count += 1;
        }
    }
    count
}

#[module_export(name = "network.dns_lookup")]
fn network_dns_lookup_r(ctx: &ScanContext, regexp_id: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|local| local.network.as_ref())
        .and_then(|network| network.domains.as_ref())
        .map(|domains| {
            domains
                .iter()
                .filter(|domain| {
                    matches!(&domain.domain, Some(domain_domain) if ctx.regexp_matches(regexp_id, domain_domain.as_bytes()))
                })
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "network.host")]
fn network_host_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|local| local.network.as_ref())
        .and_then(|network| network.hosts.as_ref())
        .map(|hosts| {
            hosts
                .iter()
                .filter(|host| ctx.regexp_matches(re, host.as_bytes()))
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "url")]
fn url_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .and_then(|l| l.urls.clone())
        .map(|urls| {
            urls.iter()
                .filter(|u| ctx.regexp_matches(re, u.as_bytes()))
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "url")]
fn url_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    get_local()
        .and_then(|l| l.urls.clone())
        .map(|urls| urls.iter().filter(|u| u.eq_ignore_ascii_case(needle)).count() as i64)
        .unwrap_or(0)
}

/// Search for a hex-encoded byte pattern in captured packet payloads
/// (VpnService full-tunnel mode). Returns the number of packets whose
/// decoded payload contains the pattern.
///
/// Usage: `hydradragon.network.payload_hex("54636C5368656C6C") >= 1`
#[module_export(name = "network.payload_hex")]
fn network_payload_hex(ctx: &ScanContext, needle_hex: RuntimeString) -> i64 {
    let Ok(hex) = needle_hex.to_str(ctx) else { return 0 };
    let needle: Vec<u8> = match (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
    {
        Ok(b) => b,
        Err(_) => return 0,
    };
    if needle.is_empty() {
        return 0;
    }
    let local = get_local();
    let Some(packets) = local
        .as_ref()
        .and_then(|l| l.network.as_ref())
        .and_then(|n| n.packets.as_ref())
    else {
        return 0;
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut count: i64 = 0;
    for pkt in packets {
        let payload_match = pkt.payload_b64.as_ref().and_then(|b64| {
            engine.decode(b64).ok().map(|decoded| {
                decoded.windows(needle.len()).any(|w| w == needle.as_slice())
            })
        }).unwrap_or(false);

        let meta_match = pkt.src_ip.as_ref()
            .or(pkt.dst_ip.as_ref())
            .or(pkt.protocol.as_ref())
            .map(|s| s.as_bytes().windows(needle.len()).any(|w| w == needle.as_slice()))
            .unwrap_or(false)
            || pkt.src_port.map(|p| {
                let ps = p.to_string();
                ps.as_bytes().windows(needle.len()).any(|w| w == needle.as_slice())
            }).unwrap_or(false)
            || pkt.dst_port.map(|p| {
                let ps = p.to_string();
                ps.as_bytes().windows(needle.len()).any(|w| w == needle.as_slice())
            }).unwrap_or(false);

        if payload_match || meta_match {
            count += 1;
        }
    }
    count
}

#[module_export(name = "screen_text")]
fn screen_text_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|local| local.screen_text.as_ref())
        .map(|text| i64::from(ctx.regexp_matches(re, text.as_bytes())))
        .unwrap_or(0)
}

// ── HIPS behavioral functions ────────────────────────────────────────────────

#[module_export(name = "ui_spam")]
fn ui_spam_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.ui_spam_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.click_count.unwrap_or(1);
            score += e.window_count.unwrap_or(0);
            if let Some(tw) = e.time_window_seconds {
                if tw > 0 && tw < 60 {
                    score = score.saturating_mul(2);
                }
            }
            if e.is_malicious.unwrap_or(false) {
                score = score.saturating_mul(2);
            }
            score
        })
        .sum()
}

#[module_export(name = "notification_spam")]
fn notification_spam_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.notification_spam_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.notification_count.unwrap_or(0);
            if let Some(tw) = e.time_window_seconds {
                if tw > 0 && tw < 60 {
                    score = score.saturating_mul(2);
                }
            }
            if e.is_malicious.unwrap_or(false) {
                score = score.saturating_add(10);
            }
            score
        })
        .sum()
}

#[module_export(name = "clickjack")]
fn clickjack_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.clickjack_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.rapid_clicks.unwrap_or(0);
            if e.is_malicious.unwrap_or(false) {
                score += 5;
            }
            if let Some(tw) = e.time_window_seconds {
                if tw > 0 && tw < 60 {
                    score = score.saturating_mul(2);
                }
            }
            if e.target_package.is_some() {
                score += 2;
            }
            score
        })
        .sum()
}

#[module_export(name = "ransomware_behavior")]
fn ransomware_behavior_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.ransomware_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.rename_count.unwrap_or(0);
            if e.access_granted.unwrap_or(false) && e.is_all_files.unwrap_or(false) {
                score += 5;
            }
            if let Some(suffix) = &e.appended_suffix {
                if !suffix.is_empty() {
                    score += 3;
                }
            }
            if let Some(tw) = e.time_window_seconds {
                if tw > 0 && tw < 60 {
                    score = score.saturating_mul(2);
                }
            }
            if e.is_malicious.unwrap_or(false) {
                score = score.saturating_mul(2);
            }
            score
        })
        .sum()
}

#[module_export(name = "canary_triggered")]
fn canary_triggered_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.canary_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    for e in events {
        if e.canary_triggered.unwrap_or(false) {
            if let Some(pkg) = &e.package_name {
                if ctx.regexp_matches(package_re, pkg.as_bytes()) {
                    return 1;
                }
            }
        }
    }
    0
}

#[module_export(name = "strandhogg")]
fn strandhogg_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.strandhogg_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
                && e.is_suspicious.unwrap_or(false)
        })
        .map(|e| 1 + e.activity_count.unwrap_or(0))
        .sum()
}

#[module_export(name = "rooted")]
fn rooted(_ctx: &ScanContext) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.system.as_ref())
        .map(|s| {
            let mut score = 0i64;
            if s.is_rooted.unwrap_or(false) { score += 1; }
            if s.is_self_protection_triggered.unwrap_or(false) { score += 1; }
            score
        })
        .unwrap_or(0)
}

#[module_export(name = "debug_mode")]
fn debug_mode(_ctx: &ScanContext) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.system.as_ref())
        .map(|s| {
            let _ = &s.package_name;
            i64::from(s.is_debug_mode.unwrap_or(false))
        })
        .unwrap_or(0)
}

#[module_export(name = "system_package")]
fn system_package_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.system.as_ref())
        .and_then(|s| s.package_name.as_ref())
        .map(|p| i64::from(ctx.regexp_matches(package_re, p.as_bytes())))
        .unwrap_or(0)
}

#[module_export(name = "behavior_flagged")]
fn behavior_flagged_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let flags = match local.as_ref().and_then(|l| l.behavior_flags.as_ref()) {
        Some(f) => f,
        None => return 0,
    };
    let mut count: i64 = 0;
    for f in flags {
        if let Some(pkg) = &f.package_name {
            if ctx.regexp_matches(package_re, pkg.as_bytes()) {
                count += f.flags.as_ref().map(|fl| fl.len() as i64).unwrap_or(0);
            }
        }
    }
    count
}

#[module_export(name = "foreground_package")]
fn foreground_package_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.behavior_state.as_ref())
        .and_then(|s| s.foreground_package.as_ref())
        .map(|pkg| i64::from(ctx.regexp_matches(package_re, pkg.as_bytes())))
        .unwrap_or(0)
}

#[module_export(name = "observed_packages")]
fn observed_packages_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.behavior_state.as_ref())
        .and_then(|s| s.observed_packages.as_ref())
        .map(|pkgs| {
            pkgs.iter()
                .filter(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "network_connections")]
fn network_connections_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.network_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.connection_count.unwrap_or(0);
            score += e.unique_hosts.unwrap_or(0);
            score += e.dns_queries.unwrap_or(0);
            score
        })
        .sum()
}

#[module_export(name = "removal_resistance")]
fn removal_resistance_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.removal_resistance_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = e.kick_count.unwrap_or(0);
            if let Some(tw) = e.time_window_seconds {
                if tw > 0 && tw < 60 {
                    score = score.saturating_mul(2);
                }
            }
            if e.is_malicious.unwrap_or(false) {
                score = score.saturating_mul(2);
            }
            score
        })
        .sum()
}

#[module_export(name = "launcher_change")]
fn launcher_change_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.launcher_change_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .map(|e| {
            let mut score = 1i64;
            if e.changed.unwrap_or(false) {
                score += 3;
            }
            if e.is_suspicious.unwrap_or(false) {
                score = score.saturating_mul(2);
            }
            score
        })
        .sum()
}

// ── Per-package metadata functions (HIPS JSON) ─────────────────────────────

#[module_export(name = "device_admin")]
fn device_admin_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let entries = match local.as_ref().and_then(|l| l.device_admin_packages.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    for e in entries {
        if let Some(pkg) = &e.package_name {
            if ctx.regexp_matches(package_re, pkg.as_bytes()) {
                if e.value.unwrap_or(false) {
                    return 1;
                }
            }
        }
    }
    0
}

#[module_export(name = "hidden_app")]
fn hidden_app_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let entries = match local.as_ref().and_then(|l| l.hidden_app_packages.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    for e in entries {
        if let Some(pkg) = &e.package_name {
            if ctx.regexp_matches(package_re, pkg.as_bytes()) {
                if e.value.unwrap_or(false) {
                    return 1;
                }
            }
        }
    }
    0
}

// ── Static DEX-analysis functions (dex-parser-analyzer engine) ──────────────

#[module_export(name = "dex_finding")]
fn dex_finding_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.dex_findings.as_ref())
        .map(|findings| {
            findings
                .iter()
                .filter(|f| {
                    f.message
                        .as_ref()
                        .map(|m| ctx.regexp_matches(re, m.as_bytes()))
                        .unwrap_or(false)
                })
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "dex_severe_finding_count")]
fn dex_severe_finding_count(_ctx: &ScanContext) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.dex_findings.as_ref())
        .map(|findings| {
            findings
                .iter()
                .filter(|f| matches!(f.severity.as_deref(), Some("High") | Some("Critical")))
                .count() as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "api_call")]
fn api_call_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.api_calls.as_ref())
        .map(|calls| {
            calls
                .iter()
                .filter_map(|c| {
                    if ctx.regexp_matches(re, c.as_bytes()) {
                        // Each entry is "sig\tcount"
                        c.rsplit('\t').next().and_then(|s| s.parse::<i64>().ok())
                    } else {
                        None
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

// ── Crypto-miner detection (runtime CPU + memory profiling) ─────────────────

/// Returns the number of miner events for packages matching the regex.
/// Each event represents a sustained high-CPU + high-memory window.
#[module_export(name = "miner_count")]
fn miner_count_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.miner_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
        })
        .count() as i64
}

/// Returns the maximum CPU usage % for packages matching the regex.
/// Example: `hydradragon.miner_cpu(/com\.example/) >= 85`
#[module_export(name = "miner_cpu")]
fn miner_cpu_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.miner_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
                && e.is_malicious.unwrap_or(false)
        })
        .filter_map(|e| e.cpu_usage.map(|c| (c * 100.0) as i64))
        .max()
        .unwrap_or(0)
}

/// Returns the maximum memory usage in MB for packages matching the regex.
/// Example: `hydradragon.miner_memory(/com\.example/) >= 64`
#[module_export(name = "miner_memory")]
fn miner_memory_r(ctx: &ScanContext, package_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.miner_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    events
        .iter()
        .filter(|e| {
            e.package_name
                .as_ref()
                .map(|p| ctx.regexp_matches(package_re, p.as_bytes()))
                .unwrap_or(false)
                && e.is_malicious.unwrap_or(false)
        })
        .filter_map(|e| e.memory_mb)
        .max()
        .unwrap_or(0)
}

/// Returns 1 if any miner event has a known miner name matching the regex.
/// Example: `hydradragon.miner_known_name(/xmrig/i) >= 1`
#[module_export(name = "miner_known_name")]
fn miner_known_name_r(ctx: &ScanContext, name_re: RegexId) -> i64 {
    let local = get_local();
    let events = match local.as_ref().and_then(|l| l.miner_events.as_ref()) {
        Some(e) => e,
        None => return 0,
    };
    for e in events {
        if e.known_name.unwrap_or(false) {
            if let Some(pkg) = &e.package_name {
                if ctx.regexp_matches(name_re, pkg.as_bytes()) {
                    return 1;
                }
            }
        }
    }
    0
}

// ── Static APK analysis functions (external report) ─────────────────────────

/// 1 if any element of `list` matches the regex, else 0.
#[inline]
fn any_regex(ctx: &ScanContext, regexp_id: RegexId, list: Option<&Vec<String>>) -> i64 {
    match list {
        Some(items) => items
            .iter()
            .any(|s| ctx.regexp_matches(regexp_id, s.as_bytes())) as i64,
        None => 0,
    }
}

/// 1 if any element of `list` equals `needle` (case-insensitive), else 0.
#[inline]
fn any_eqic(list: Option<&Vec<String>>, needle: &str) -> i64 {
    match list {
        Some(items) => items.iter().any(|s| s.eq_ignore_ascii_case(needle)) as i64,
        None => 0,
    }
}

#[inline]
fn one_regex(ctx: &ScanContext, regexp_id: RegexId, value: Option<&String>) -> i64 {
    matches!(value, Some(v) if ctx.regexp_matches(regexp_id, v.as_bytes())) as i64
}

#[inline]
fn one_eqic(value: Option<&String>, needle: &str) -> i64 {
    matches!(value, Some(v) if v.eq_ignore_ascii_case(needle)) as i64
}

#[module_export(name = "certificate.issuer")]
fn certificate_issuer_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.issuer_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.issuer")]
fn certificate_issuer_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.issuer_dn.clone()))
            .as_ref(),
        needle,
    )
}

#[module_export(name = "certificate.subject")]
fn certificate_subject_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.subject_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.subject")]
fn certificate_subject_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.subject_dn.clone()))
            .as_ref(),
        needle,
    )
}

#[module_export(name = "certificate.sha1")]
fn certificate_sha1(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.sha1.clone()))
            .as_ref(),
        needle,
    )
}

// ── app_name ───────────────────────────────────────────────────────────────

#[module_export(name = "app_name")]
fn app_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(ctx, re, get_local().and_then(|l| l.app_name.clone()).as_ref())
}

#[module_export(name = "app_name")]
fn app_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.app_name.clone()).as_ref(), needle)
}

// ── permission (permissions + new_permissions) ─────────────────────────────

#[module_export(name = "permission")]
fn permission_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let a = any_regex(ctx, re, local.as_ref().and_then(|l| l.permissions.as_ref()));
    if a != 0 {
        return 1;
    }
    any_regex(ctx, re, local.as_ref().and_then(|l| l.new_permissions.as_ref()))
}

#[module_export(name = "permission")]
fn permission_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    let local = get_local();
    let a = any_eqic(local.as_ref().and_then(|l| l.permissions.as_ref()), needle);
    if a != 0 {
        return 1;
    }
    any_eqic(local.as_ref().and_then(|l| l.new_permissions.as_ref()), needle)
}

// ── activity / main_activity ───────────────────────────────────────────────

#[module_export(name = "activity")]
fn activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.activities.clone()).as_ref())
}

#[module_export(name = "activity")]
fn activity_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.activities.clone()).as_ref(), needle)
}

#[module_export(name = "receiver")]
fn receiver_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.receivers.clone()).as_ref())
}

#[module_export(name = "receiver")]
fn receiver_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.receivers.clone()).as_ref(), needle)
}

#[module_export(name = "main_activity")]
fn main_activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.main_activity.clone()).as_ref(),
    )
}

#[module_export(name = "main_activity")]
fn main_activity_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.main_activity.clone()).as_ref(), needle)
}

// ── service ────────────────────────────────────────────────────────────────

#[module_export(name = "service")]
fn service_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.services.clone()).as_ref())
}

#[module_export(name = "service")]
fn service_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.services.clone()).as_ref(), needle)
}

// ── package_name ───────────────────────────────────────────────────────────

#[module_export(name = "package_name")]
fn package_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.package_name.clone()).as_ref(),
    )
}

#[module_export(name = "package_name")]
fn package_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.package_name.clone()).as_ref(), needle)
}

// ── rootkit_behavior ─────────────────────────────────────────────────────
//
// Stealth-rootkit pattern: no launchable (MAIN/LAUNCHER) activity declared —
// i.e. the app can't be opened from the home screen/app drawer at all — AND
// at least one high-privilege or persistence permission. Neither signal is
// proof on its own (some legitimate apps have no launcher activity, and
// device-admin/accessibility/overlay/boot-completed each have legitimate
// uses individually); together they're the classic "install silently, hide
// the icon, persist via one of these" combination.

/// Same high-privilege/persistence permission set the host app's own Java
/// heuristic uses (ScanEngine.ROOTKIT_SUSPICIOUS_PERMS) — device-admin and
/// accessibility grant near-total device control, SYSTEM_ALERT_WINDOW
/// enables overlay attacks, and boot-completed plus any of the others gives
/// silent persistence across reboots with no icon ever needed to relaunch.
const ROOTKIT_SUSPICIOUS_PERMS: &[&str] = &[
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
];

#[module_export(name = "rootkit_behavior")]
fn rootkit_behavior(_ctx: &ScanContext) -> i64 {
    let local = get_local();
    let Some(local) = local.as_ref() else { return 0 };

    // "Hidden": the report has no main_activity at all, or an explicitly
    // empty one — both mean the host found no enabled MAIN/LAUNCHER
    // activity while parsing the manifest.
    let hidden = match &local.main_activity {
        None => true,
        Some(s) => s.is_empty(),
    };
    if !hidden {
        return 0;
    }

    let has_suspicious_perm = |perms: &Option<Vec<String>>| -> bool {
        perms
            .as_ref()
            .map(|list| {
                list.iter()
                    .any(|p| ROOTKIT_SUSPICIOUS_PERMS.iter().any(|s| p.eq_ignore_ascii_case(s)))
            })
            .unwrap_or(false)
    };
    i64::from(
        has_suspicious_perm(&local.permissions) || has_suspicious_perm(&local.new_permissions),
    )
}

// ── device_admin_permission ──────────────────────────────────────────────
//
// Standalone check for `android.permission.BIND_DEVICE_ADMIN` in the
// manifest's permission declarations. Unlike rootkit_behavior() which
// combines this with the hidden-launcher heuristic, this function returns
// 1 whenever the APK merely *declares* the device-admin permission,
// regardless of whether it also hides its icon.

#[module_export(name = "device_admin_permission")]
fn device_admin_permission(_ctx: &ScanContext) -> i64 {
    let local = get_local();
    let Some(local) = local.as_ref() else { return 0 };
    let has_it = |perms: &Option<Vec<String>>| -> bool {
        perms
            .as_ref()
            .map(|list| {
                list.iter()
                    .any(|p| p.eq_ignore_ascii_case("android.permission.BIND_DEVICE_ADMIN"))
            })
            .unwrap_or(false)
    };
    i64::from(has_it(&local.permissions) || has_it(&local.new_permissions))
}

// ── Manifest <meta-data> support ─────────────────────────────────────────────

#[module_export(name = "metadata")]
fn metadata_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    get_local()
        .as_ref()
        .and_then(|l| l.meta_data.as_ref())
        .map(|list| {
            list.iter()
                .any(|m| m.name.as_deref() == Some(needle)) as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "metadata")]
fn metadata_r(ctx: &ScanContext, regex: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.meta_data.as_ref())
        .map(|list| {
            list.iter()
                .any(|m| {
                    m.name.as_ref()
                        .map(|n| ctx.regexp_matches(regex, n.as_bytes()))
                        .unwrap_or(false)
                }) as i64
        })
        .unwrap_or(0)
}

register_module!("hydradragon", Hydradragon, main);
