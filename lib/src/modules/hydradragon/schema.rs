use std::fmt;

use serde::de::Error;
use serde::{de::Visitor, Deserialize, Deserializer};

#[derive(serde::Deserialize, Debug)]
pub(super) struct DomainJson {
    pub domain: Option<String>,
}

/// A raw captured packet (VpnService full-tunnel mode), for Suricata-style
/// payload matching via `hydradragon.network.payload_hex`.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct CapturedPacketJson {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    /// Base64-encoded payload bytes (first 2048 bytes max).
    pub payload_b64: Option<String>,
}

/// The network metadata a MITM-free, DNS-only Web-Shield can attribute per app:
/// the domains it resolved and the destination IPs those resolved to. HTTP
/// fields are approximated from the VpnService's raw packet capture payloads
/// (cleartext TCP port 80/8080 only).
#[derive(/* serde::Deserialize, - custom */ Debug, Default)]
pub(super) struct NetworkJson {
    pub domains: Option<Vec<DomainJson>>,
    pub hosts: Option<Vec<String>>,
    /// Raw captured packets (VpnService full-tunnel mode) for Suricata-style
    /// payload matching. Max ~50 recent packets, payloads base64-encoded.
    pub packets: Option<Vec<CapturedPacketJson>>,
}

// ── HIPS behavioral event types ──────────────────────────────────────────────

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct UISpamEventJson {
    pub package_name: Option<String>,
    pub click_count: Option<i64>,
    pub window_count: Option<i64>,
    pub time_window_seconds: Option<i64>,
    pub is_malicious: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct NotificationSpamEventJson {
    pub package_name: Option<String>,
    pub notification_count: Option<i64>,
    pub time_window_seconds: Option<i64>,
    pub is_malicious: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct ClickjackEventJson {
    pub package_name: Option<String>,
    pub rapid_clicks: Option<i64>,
    pub target_package: Option<String>,
    pub time_window_seconds: Option<i64>,
    pub is_malicious: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct RansomwareEventJson {
    pub package_name: Option<String>,
    pub rename_count: Option<i64>,
    pub appended_suffix: Option<String>,
    pub access_granted: Option<bool>,
    pub is_all_files: Option<bool>,
    pub time_window_seconds: Option<i64>,
    pub is_malicious: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct CanaryEventJson {
    pub package_name: Option<String>,
    pub canary_triggered: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct NetworkEventJson {
    pub package_name: Option<String>,
    pub connection_count: Option<i64>,
    pub unique_hosts: Option<i64>,
    pub dns_queries: Option<i64>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct StrandHoggEventJson {
    pub package_name: Option<String>,
    pub activity_count: Option<i64>,
    pub is_suspicious: Option<bool>,
}

/// Malware repeatedly kicking the user off its own uninstall confirmation
/// or device-admin deactivation screen (RemovalResistanceGuard).
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct RemovalResistanceEventJson {
    pub package_name: Option<String>,
    pub kick_count: Option<i64>,
    pub screen_kind: Option<String>,
    pub time_window_seconds: Option<i64>,
    pub is_malicious: Option<bool>,
}

/// An app has attempted to become or has become the default home/launcher app.
/// Emitted by HipsMonitor when PackageManager.clearPackagePreferredActivities,
/// addPreferredActivity, or RoleManager.ROLE_HOME is invoked.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct LauncherChangeEventJson {
    pub package_name: Option<String>,
    /// True if the launcher was actually changed (not just an attempt).
    pub changed: Option<bool>,
    /// Method used: "clearPackagePreferredActivities", "addPreferredActivity",
    /// "role_manager" (Android 10+), or "category_home_registration".
    pub method: Option<String>,
    pub is_suspicious: Option<bool>,
}

/// Media-volume spike observed while a (suspected) app was in the foreground —
/// scareware/ransomware attention tactic. See `hydradragon.audio_spike`.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct AudioSpikeEventJson {
    pub package_name: Option<String>,
    pub volume_from: Option<i64>,
    pub volume_to: Option<i64>,
    pub max_volume: Option<i64>,
    pub is_malicious: Option<bool>,
}

/// Package playing audio with a high-priority usage (alarm/emergency/ringtone) —
/// scareware audio-abuse. See `hydradragon.audio_abuse`.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct AudioAbuseEventJson {
    pub package_name: Option<String>,
    pub usage: Option<i64>,
    pub usage_name: Option<String>,
    pub content_type: Option<i64>,
    pub is_malicious: Option<bool>,
}

/// Sensitive clipboard content (crypto address, token, seed phrase) observed
/// on the clipboard while a different app took the foreground — info-stealer
/// pattern. See `hydradragon.clipboard_read`.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct ClipboardReadEventJson {
    pub package_name: Option<String>,
    pub timestamp: Option<i64>,
    pub sensitive: Option<bool>,
    pub hint: Option<String>,
    pub is_malicious: Option<bool>,
}

/// Wallpaper replaced while an app was in the foreground — ransomware/scareware
/// signature. See `hydradragon.wallpaper_change`.
#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct WallpaperChangeEventJson {
    pub package_name: Option<String>,
    pub wallpaper_id: Option<i64>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct SystemEventJson {
    pub is_rooted: Option<bool>,
    pub is_debug_mode: Option<bool>,
    pub is_self_protection_triggered: Option<bool>,
    pub package_name: Option<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct BehaviorFlagsJson {
    pub package_name: Option<String>,
    pub flags: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct BehaviorStateJson {
    pub foreground_package: Option<String>,
    pub observed_packages: Option<Vec<String>>,
}

// ── Static DEX-analysis finding (dex-parser-analyzer engine) ─────────────────

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct DexFindingJson {
    pub severity: Option<String>,
    pub kind: Option<String>,
    pub class_descriptor: Option<String>,
    pub message: Option<String>,
}

// ── Per-package metadata ─────────────────────────────────────────────────────

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct PackageFlagJson {
    pub package_name: Option<String>,
    /// 1 if the flag is active (e.g. is device admin, is hidden app).
    pub value: Option<bool>,
}

// ── Crypto-miner detection (runtime CPU + memory profiling) ──────────────────

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct MinerEventJson {
    pub package_name: Option<String>,
    /// Sustained CPU usage fraction (0.0–1.0), e.g. 0.85 for 85%.
    pub cpu_usage: Option<f64>,
    /// Resident memory in MB at time of detection.
    pub memory_mb: Option<i64>,
    /// Whether the process name matches known miner names (xmrig, etc.).
    pub known_name: Option<bool>,
    /// Whether this event is confirmed malicious (CPU + mem above threshold
    /// for sustained period).
    pub is_malicious: Option<bool>,
}

// ── Static APK analysis (external report, inspired by Koodous' androguard) ──
//
// The host may feed an external static-analysis report (the androguard-style
// APK analysis, or the Koodous module's equivalent) as module metadata. The
// fields below mirror what the original Koodous C module read with jansson:
// `package_name`, `app_name`, `main_activity`, `activities`, `services`,
// `urls`, `permissions`, `new_permissions`, `min/max/target_sdk_version`
// (strings, atoi'd) and the `certificate` object (`subjectDN`, `IssuerDN`,
// `sha1`).

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct CertificateJson {
    #[serde(rename = "subjectDN")]
    pub subject_dn: Option<String>,
    #[serde(rename = "IssuerDN")]
    pub issuer_dn: Option<String>,
    pub sha1: Option<String>,
    /// ISO-8601 "YYYY-MM-DD HH:MM:SS" (UTC) certificate not-before.
    #[serde(rename = "notBefore")]
    pub not_before: Option<String>,
    /// ISO-8601 "YYYY-MM-DD HH:MM:SS" (UTC) certificate not-after.
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
    /// 1 if the certificate is expired or not-yet-valid at scan time, else 0.
    pub expired: Option<i64>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct MetaDataEntry {
    pub name: Option<String>,
    pub value: Option<String>,
}

/// Deserialize an optional integer that may be encoded as a JSON string
/// ("19"), a JSON number (19), or be absent/null — matching the C module's
/// lenient `atoi(json_string_value(...))`.
fn de_opt_int_str<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum IntOrStr {
        Int(i64),
        Str(String),
        Null,
    }
    Ok(match Option::<IntOrStr>::deserialize(d)? {
        None | Some(IntOrStr::Null) => None,
        Some(IntOrStr::Int(i)) => Some(i),
        // atoi semantics: parse the leading integer, 0 on failure.
        Some(IntOrStr::Str(s)) => Some(s.trim().parse::<i64>().unwrap_or(0)),
    })
}

// ── Root JSON schema (extended hydradragon) ──────────────────────────────────

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct HydradragonJson {
    pub network: Option<NetworkJson>,
    /// Full URLs observed live (host + path), for `hydradragon.url`.
    pub urls: Option<Vec<String>>,
    /// On-screen text recognized by the OCR screen-capture pipeline (recent
    /// text for the scanned app, concatenated), for `hydradragon.screen_text`.
    pub screen_text: Option<String>,
    // ── HIPS behavioral fields ──
    pub ui_spam_events: Option<Vec<UISpamEventJson>>,
    pub notification_spam_events: Option<Vec<NotificationSpamEventJson>>,
    pub clickjack_events: Option<Vec<ClickjackEventJson>>,
    pub ransomware_events: Option<Vec<RansomwareEventJson>>,
    pub canary_events: Option<Vec<CanaryEventJson>>,
    pub network_events: Option<Vec<NetworkEventJson>>,
    pub strandhogg_events: Option<Vec<StrandHoggEventJson>>,
    /// Uninstall/device-admin "kick" events (RemovalResistanceGuard), for
    /// `hydradragon.removal_resistance`.
    pub removal_resistance_events: Option<Vec<RemovalResistanceEventJson>>,
    /// Launcher-change attempts (default home app hijacking), for
    /// `hydradragon.launcher_change`.
    pub launcher_change_events: Option<Vec<LauncherChangeEventJson>>,
    /// Media-volume spikes (scareware attention tactic), for
    /// `hydradragon.audio_spike`.
    pub audio_spike_events: Option<Vec<AudioSpikeEventJson>>,
    /// Alarm/emergency-usage audio playback (scareware), for
    /// `hydradragon.audio_abuse`.
    pub audio_abuse_events: Option<Vec<AudioAbuseEventJson>>,
    /// Sensitive-clipboard reads (info-stealer), for `hydradragon.clipboard_read`.
    pub clipboard_read_events: Option<Vec<ClipboardReadEventJson>>,
    /// Wallpaper changes attributed to the foreground app, for
    /// `hydradragon.wallpaper_change`.
    pub wallpaper_events: Option<Vec<WallpaperChangeEventJson>>,
    pub system: Option<SystemEventJson>,
    pub behavior_flags: Option<Vec<BehaviorFlagsJson>>,
    pub behavior_state: Option<BehaviorStateJson>,
    /// Static DEX-analysis findings (dex-parser-analyzer engine), any
    /// severity, for `hydradragon.dex_finding` / `dex_severe_finding_count`.
    pub dex_findings: Option<Vec<DexFindingJson>>,
    /// Unique API calls (method invocations) extracted from all DEX buffers,
    /// in `Lpkg/Cls;->method(params)return` format. Deduplicated across the
    /// entire scan, for `hydradragon.api_call(regex)`.
    pub api_calls: Option<Vec<String>>,
    /// Packages that are currently active Device Administrators at runtime,
    /// for `hydradragon.device_admin`. Populated by Java's
    /// DevicePolicyManager.getActiveAdmins() at HIPS report time.
    pub device_admin_packages: Option<Vec<PackageFlagJson>>,
    /// Packages that have no launcher icon (hidden from the app drawer) and
    /// request suspicious permissions — the stealth-rootkit pattern — for
    /// `hydradragon.hidden_app`. Populated by Java's ScanEngine rootkit check.
    pub hidden_app_packages: Option<Vec<PackageFlagJson>>,
    /// Runtime crypto-miner detection events (MinerDetector), for
    /// `hydradragon.miner_count` / `miner_cpu` / `miner_memory` / `miner_known_name`.
    pub miner_events: Option<Vec<MinerEventJson>>,
    // ── Static APK analysis fields (external report) ──
    pub package_name: Option<String>,
    pub app_name: Option<String>,
    pub main_activity: Option<String>,
    pub activities: Option<Vec<String>>,
    pub services: Option<Vec<String>>,
    pub receivers: Option<Vec<String>>,
    pub permissions: Option<Vec<String>>,
    pub new_permissions: Option<Vec<String>>,
    pub certificate: Option<CertificateJson>,
    // The original module stored these as strings and ran atoi() over them, so
    // accept a string (and tolerate a bare number too).
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub min_sdk_version: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub max_sdk_version: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub target_sdk_version: Option<i64>,
    /// `<meta-data>` entries from AndroidManifest.xml
    pub meta_data: Option<Vec<MetaDataEntry>>,
}

impl<'de> Deserialize<'de> for NetworkJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MyVisitor;

        impl<'de> Visitor<'de> for MyVisitor {
            type Value = NetworkJson;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("string or object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut old_domains = None::<serde_json::Value>;
                let mut domains = None::<serde_json::Value>;
                let mut hosts = None::<Vec<String>>;
                let mut packets = None::<Vec<CapturedPacketJson>>;

                while let Some((key, val)) =
                    map.next_entry::<String, serde_json::Value>()?
                {
                    match key.as_str() {
                        "domains" => {
                            domains = Some(val);
                        }
                        "dns" => {
                            if domains.is_some() {
                                continue;
                            }
                            old_domains = Some(val);
                        }
                        "hosts" if !val.is_null() => {
                            hosts = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        "packets" if !val.is_null() => {
                            packets = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        _ => {}
                    }
                }

                #[derive(serde::Deserialize, Debug)]
                struct OldDomainJson {
                    pub hostname: Option<String>,
                }

                let domains: Option<Vec<DomainJson>> =
                    match (domains, old_domains) {
                        (Some(domains), _) if !domains.is_null() => {
                            Deserialize::deserialize(domains)
                                .map_err(Error::custom)?
                        }
                        (None, Some(old_domains))
                            if !old_domains.is_null() =>
                        {
                            let old_domains: Vec<OldDomainJson> =
                                Deserialize::deserialize(old_domains)
                                    .map_err(Error::custom)?;

                            Some(
                                old_domains
                                    .into_iter()
                                    .map(|old| DomainJson {
                                        domain: old.hostname,
                                    })
                                    .collect(),
                            )
                        }
                        _ => None,
                    };

                Ok(NetworkJson { domains, hosts, packets })
            }
        }

        deserializer.deserialize_any(MyVisitor)
    }
}
