//! `clavenarctl doctor` — probe every clavenar service's `/health` endpoint
//! and surface up/down + latency + any version info the service
//! returns.
//!
//! Designed for the partner-day-1 reality where the operator just
//! ran `docker compose up -d` and is asking "is everything actually
//! up?" Bare minimum: GET /health on the standard ports; surface a
//! one-line-per-service status. Exit code 0 if every probed service
//! responded 200, 5 if any failed — so a CI smoke can `clavenarctl
//! doctor` without further parsing.

use std::time::{Duration, Instant};

use clap::Args;

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Override the identity URL (default config / env / built-in).
    #[arg(long)]
    pub identity_url: Option<String>,
    /// Override the ledger URL.
    #[arg(long)]
    pub ledger_url: Option<String>,
    /// Override the HIL URL.
    #[arg(long)]
    pub hil_url: Option<String>,
    /// Override the console URL.
    #[arg(long)]
    pub console_url: Option<String>,
    /// Override the brain URL.
    #[arg(long)]
    pub brain_url: Option<String>,
    /// Override the policy-engine URL.
    #[arg(long)]
    pub policy_engine_url: Option<String>,
    /// Override the proxy URL (probed but mTLS — the result reports
    /// "reachable" but not auth status).
    #[arg(long)]
    pub proxy_url: Option<String>,
    /// Per-service request timeout in seconds. Doctor must finish
    /// quickly even when half the stack is down.
    #[arg(long, default_value_t = 3)]
    pub timeout_secs: u64,
    /// Skip services whose URL resolves to the built-in default —
    /// useful when running doctor against a deployed stack where only
    /// some endpoints are exposed.
    #[arg(long)]
    pub only_configured: bool,
    /// JSON output instead of the human-readable table. CI smoke tests
    /// parse this; the human format is for the terminal.
    #[arg(long)]
    pub json: bool,
}

/// One service probe result. Lives at this level (not pinned to
/// `serde_json::Value`) because the doctor surface is part of the
/// CLI's wire contract — partners script against this shape.
#[derive(Debug, serde::Serialize)]
struct ServiceCheck {
    service: &'static str,
    url: String,
    /// `up` / `down` / `skipped`. `up` only when the service returned
    /// HTTP 2xx; everything else (network, 4xx, 5xx) is `down`.
    status: &'static str,
    /// HTTP status code on a transport-level success, `null` on a
    /// network failure.
    http_status: Option<u16>,
    /// Round-trip latency in milliseconds, `null` when the request
    /// never completed.
    latency_ms: Option<u64>,
    /// Whatever the service returned as a body, trimmed to 256 bytes.
    /// Many clavenar services emit a short status string or JSON shape.
    body_excerpt: Option<String>,
    /// One-line operator-actionable error for failures, `null` on
    /// success.
    error: Option<String>,
}

const BUILTIN_DEFAULTS: &[(&str, &str)] = &[
    ("identity", "http://localhost:8086/health"),
    ("ledger", "http://localhost:8083/health"),
    ("hil", "http://localhost:8084/health"),
    ("console", "http://localhost:8085/health"),
    ("brain", "http://localhost:8081/health"),
    ("policy-engine", "http://localhost:8082/health"),
    ("proxy", "https://localhost:8443/health"),
];

fn defaults_lookup(service: &str) -> &'static str {
    BUILTIN_DEFAULTS
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, u)| *u)
        .expect("service has a builtin default")
}

fn pick_url(service: &'static str, flag: Option<String>, env_key: &str) -> (String, bool) {
    if let Some(v) = flag {
        return (v, true);
    }
    if let Ok(v) = std::env::var(env_key)
        && !v.is_empty()
    {
        return (v, true);
    }
    (defaults_lookup(service).to_string(), false)
}

pub(crate) async fn run(args: DoctorArgs) -> ExitCode {
    let timeout = Duration::from_secs(args.timeout_secs);
    // Permissive TLS verifier: the proxy ships with self-signed dev
    // certs by default. Production operators who care can pass
    // `--proxy-url` pointed at their real cert and the probe still
    // works (we already accept any cert).
    let http = match reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to build HTTP client: {}", e);
            return ExitCode::Server;
        }
    };

    let probes: Vec<(&'static str, String, bool)> = vec![
        {
            let (u, ovr) = pick_url("identity", args.identity_url, "CLAVENAR_IDENTITY_URL");
            ("identity", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url("ledger", args.ledger_url, "CLAVENAR_LEDGER_URL");
            ("ledger", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url("hil", args.hil_url, "CLAVENAR_HIL_URL");
            ("hil", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url("console", args.console_url, "CLAVENAR_CONSOLE_URL");
            ("console", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url("brain", args.brain_url, "CLAVENAR_BRAIN_URL");
            ("brain", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url(
                "policy-engine",
                args.policy_engine_url,
                "CLAVENAR_POLICY_URL",
            );
            ("policy-engine", health_url(&u), ovr)
        },
        {
            let (u, ovr) = pick_url("proxy", args.proxy_url, "CLAVENAR_PROXY_URL");
            ("proxy", health_url(&u), ovr)
        },
    ];

    let mut results: Vec<ServiceCheck> = Vec::new();
    for (service, url, configured) in probes {
        if args.only_configured && !configured {
            results.push(ServiceCheck {
                service,
                url,
                status: "skipped",
                http_status: None,
                latency_ms: None,
                body_excerpt: None,
                error: None,
            });
            continue;
        }
        // The proxy speaks mTLS by default, so probing it without a
        // client cert returns a handshake failure that's
        // indistinguishable from "service down." Skip when the URL
        // resolves to the built-in default — operators with a
        // non-mTLS proxy override via `--proxy-url`.
        if service == "proxy" && !configured {
            results.push(ServiceCheck {
                service,
                url,
                status: "skipped",
                http_status: None,
                latency_ms: None,
                body_excerpt: None,
                error: Some(
                    "proxy probe is opt-in (mTLS) — pass --proxy-url or set CLAVENAR_PROXY_URL"
                        .to_string(),
                ),
            });
            continue;
        }
        results.push(probe(&http, service, &url).await);
    }

    let any_down = results.iter().any(|r| r.status == "down");

    if args.json {
        match serde_json::to_string_pretty(&results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error: serialize results: {}", e);
                return ExitCode::Server;
            }
        }
    } else {
        print_table(&results);
    }
    if any_down {
        ExitCode::Server
    } else {
        ExitCode::Ok
    }
}

/// Normalize a base URL into a /health probe URL. Tolerates either
/// `http://host:port` or `http://host:port/health` — operators
/// shouldn't have to remember which to write.
fn health_url(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/health") || trimmed.ends_with("/readyz") {
        trimmed.to_string()
    } else {
        format!("{}/health", trimmed)
    }
}

async fn probe(http: &reqwest::Client, service: &'static str, url: &str) -> ServiceCheck {
    let start = Instant::now();
    match http.get(url).send().await {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            let latency = start.elapsed().as_millis() as u64;
            let body = resp.text().await.ok();
            let excerpt = body.as_ref().map(|s| {
                let s = s.trim();
                if s.len() > 256 {
                    format!("{}…", &s[..256])
                } else {
                    s.to_string()
                }
            });
            if (200..300).contains(&http_status) {
                ServiceCheck {
                    service,
                    url: url.to_string(),
                    status: "up",
                    http_status: Some(http_status),
                    latency_ms: Some(latency),
                    body_excerpt: excerpt,
                    error: None,
                }
            } else {
                ServiceCheck {
                    service,
                    url: url.to_string(),
                    status: "down",
                    http_status: Some(http_status),
                    latency_ms: Some(latency),
                    body_excerpt: excerpt,
                    error: Some(format!("non-2xx HTTP status {}", http_status)),
                }
            }
        }
        Err(e) => ServiceCheck {
            service,
            url: url.to_string(),
            status: "down",
            http_status: None,
            latency_ms: None,
            body_excerpt: None,
            error: Some(format!("{}", e)),
        },
    }
}

fn print_table(results: &[ServiceCheck]) {
    println!(
        "{:<16} {:<48} {:<8} {:>8}  detail",
        "SERVICE", "URL", "STATUS", "LATENCY"
    );
    for r in results {
        let latency = r
            .latency_ms
            .map(|m| format!("{}ms", m))
            .unwrap_or_else(|| "-".to_string());
        let detail = match (r.http_status, r.error.as_deref(), r.body_excerpt.as_deref()) {
            (_, Some(e), _) => e.to_string(),
            (Some(s), None, Some(b)) if !b.is_empty() => format!("HTTP {} — {}", s, b),
            (Some(s), None, _) => format!("HTTP {}", s),
            (None, None, _) => "-".to_string(),
        };
        println!(
            "{:<16} {:<48} {:<8} {:>8}  {}",
            r.service, r.url, r.status, latency, detail
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_url_idempotent() {
        assert_eq!(
            health_url("http://localhost:8086"),
            "http://localhost:8086/health"
        );
        assert_eq!(
            health_url("http://localhost:8086/"),
            "http://localhost:8086/health"
        );
        assert_eq!(
            health_url("http://localhost:8086/health"),
            "http://localhost:8086/health"
        );
        // Operators who hand-typed /readyz keep that suffix.
        assert_eq!(
            health_url("http://localhost:8086/readyz"),
            "http://localhost:8086/readyz"
        );
    }

    #[test]
    fn pick_url_prefers_flag_over_env() {
        // SAFETY: this test sets/removes a process-wide env var; the
        // CARGO_TARGET_TMPDIR-style isolation isn't available, so we
        // unset on teardown.
        let key = "CLAVENAR_DOCTOR_TEST_URL";
        unsafe { std::env::set_var(key, "http://from-env") };
        let (u, ovr) = pick_url("identity", Some("http://from-flag".into()), key);
        assert_eq!(u, "http://from-flag");
        assert!(ovr);
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn pick_url_falls_through_to_default() {
        let key = "CLAVENAR_DOCTOR_TEST_UNSET";
        unsafe { std::env::remove_var(key) };
        let (u, ovr) = pick_url("identity", None, key);
        assert!(u.contains("localhost:8086"), "got {}", u);
        assert!(!ovr);
    }

    #[tokio::test]
    async fn probe_marks_down_on_unreachable_host() {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        // 127.0.0.1:1 is the discard port — TCP connect refused by
        // the kernel, doesn't depend on whether anything binds. The
        // probe must surface this as `down`, not panic.
        let r = probe(&http, "identity", "http://127.0.0.1:1/health").await;
        assert_eq!(r.status, "down");
        assert!(r.error.is_some());
        assert!(r.http_status.is_none());
    }
}
