//! Real-provider RFC 8628 acceptance.
//!
//! The companion runner starts an exact pinned Keycloak image and imports the
//! test-only realm. This ignored test drives the shipped CLI process, completes
//! the browser ceremony, and verifies restrictive credential persistence.

use reqwest::{Client, Response, StatusCode, Url};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::time::Duration;

const REALM: &str = "clavenar-device";
const USERNAME: &str = "device-operator";
const PASSWORD: &str = "device-test-password";

fn browser() -> Client {
    Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("browser client")
}

fn extract_tag_attribute(
    html: &str,
    tag: &str,
    identifying_attribute: &str,
    identifying_value: &str,
    desired_attribute: &str,
) -> Option<String> {
    let marker = format!(r#"{identifying_attribute}="{identifying_value}""#);
    let marker_at = html.find(&marker)?;
    let tag_start = html[..marker_at].rfind(&format!("<{tag}"))?;
    let tag_end = html[marker_at..].find('>')? + marker_at;
    extract_attribute(&html[tag_start..=tag_end], desired_attribute)
}

fn extract_attribute(tag: &str, attribute: &str) -> Option<String> {
    let marker = format!(r#"{attribute}=""#);
    let start = tag.find(&marker)? + marker.len();
    let end = tag[start..].find('"')? + start;
    Some(decode_html_entities(&tag[start..end]))
}

fn decode_html_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#x2F;", "/")
        .replace("&#x2f;", "/")
        .replace("&#x2B;", "+")
        .replace("&#x2b;", "+")
        .replace("&#43;", "+")
        .replace("&#x3D;", "=")
        .replace("&#x3d;", "=")
        .replace("&#61;", "=")
}

async fn submit_login(client: &Client, start_url: Url) -> Response {
    let login_page = follow_redirects(
        client,
        client
            .get(start_url)
            .send()
            .await
            .expect("open device login"),
    )
    .await;
    assert_eq!(login_page.status(), StatusCode::OK);
    let login_html = login_page.text().await.expect("login page body");
    let action = extract_tag_attribute(&login_html, "form", "id", "kc-form-login", "action")
        .expect("Keycloak login form action");
    follow_redirects(
        client,
        client
            .post(action)
            .form(&[
                ("username", USERNAME),
                ("password", PASSWORD),
                ("credentialId", ""),
            ])
            .send()
            .await
            .expect("submit Keycloak login"),
    )
    .await
}

async fn follow_redirects(client: &Client, mut response: Response) -> Response {
    for _ in 0..8 {
        if !response.status().is_redirection() {
            return response;
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .expect("redirect Location")
            .to_str()
            .expect("ASCII redirect Location");
        let next = response
            .url()
            .join(location)
            .expect("valid redirect Location");
        response = client.get(next).send().await.expect("follow redirect");
    }
    panic!("too many browser redirects");
}

async fn confirm_device(client: &Client, response: Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let response_url = response.url().clone();
    let html = response.text().await.expect("device confirmation body");
    if html.contains("Device Login Successful") {
        return;
    }
    let action = extract_tag_attribute(&html, "form", "id", "kc-device-verify", "action")
        .or_else(|| extract_tag_attribute(&html, "form", "id", "kc-form-login", "action"))
        .or_else(|| {
            let accept_at = html.find(r#"name="accept""#)?;
            let form_start = html[..accept_at].rfind("<form")?;
            let form_end = html[form_start..].find('>')? + form_start;
            extract_attribute(&html[form_start..=form_end], "action")
        })
        .unwrap_or_else(|| panic!("Keycloak device confirmation form missing: {html}"));
    let action = response_url.join(&action).expect("device form action URL");
    let code = extract_tag_attribute(&html, "input", "name", "code", "value");
    let mut form = vec![("submitAction", "confirm")];
    if let Some(code) = code.as_deref() {
        form = vec![("code", code), ("accept", "Yes")];
    }
    let response = follow_redirects(
        client,
        client
            .post(action)
            .form(&form)
            .send()
            .await
            .expect("confirm device"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.expect("device success body");
    assert!(
        html.contains("Device Login Successful") || html.contains("successfully connected"),
        "unexpected Keycloak device result: {html}"
    );
}

#[tokio::test]
#[ignore = "started by scripts/run-keycloak-device-authorization.sh"]
async fn pinned_keycloak_completes_bounded_operator_device_flow() {
    let keycloak =
        std::env::var("CLAVENAR_KEYCLOAK_URL").unwrap_or_else(|_| "http://127.0.0.1:18081".into());
    let issuer = format!("{keycloak}/realms/{REALM}");
    let directory = tempfile::tempdir().expect("credential tempdir");
    let credentials = directory.path().join("credentials.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_clavenarctl"))
        .args(["auth", "login", "--tenant", "acme", "--issuer", &issuer])
        .env("CLAVENAR_CREDENTIALS_PATH", &credentials)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clavenarctl");
    let stdout = child.stdout.take().expect("CLI stdout");
    let mut lines = BufReader::new(stdout).lines();
    let prompt = lines
        .next()
        .expect("device prompt line")
        .expect("read device prompt");
    assert!(prompt.starts_with("Open "));
    let user_code = prompt
        .split_ascii_whitespace()
        .next_back()
        .expect("user code")
        .to_string();
    let complete = lines
        .next()
        .expect("complete verification line")
        .expect("read complete verification URL");
    let complete = complete
        .strip_prefix("Verification URL: ")
        .expect("complete URL prefix")
        .parse::<Url>()
        .expect("complete verification URL");

    let browser_client = browser();
    let login = submit_login(&browser_client, complete).await;
    confirm_device(&browser_client, login).await;

    let status = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll CLI") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("CLI completed before timeout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("CLI stderr")
        .read_to_string(&mut stderr)
        .expect("read CLI stderr");
    assert!(status.success(), "clavenarctl failed: {stderr}");

    let metadata = std::fs::metadata(&credentials).expect("credential metadata");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    let credential_bytes = std::fs::read(&credentials).expect("credential bytes");
    assert!(
        !String::from_utf8_lossy(&credential_bytes).contains(&user_code),
        "user code must not persist with credentials"
    );
    let document: Value = serde_json::from_slice(&credential_bytes).expect("credential JSON");
    let entry = &document["tenants"]["acme"];
    assert!(
        entry["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert_eq!(
        entry["issuer"].as_str(),
        Some(format!("{keycloak}/realms/{REALM}").as_str())
    );
    assert!(entry["sub"].as_str().is_some_and(|value| !value.is_empty()));

    let mut wrong_tenant = Command::new(env!("CARGO_BIN_EXE_clavenarctl"))
        .args(["auth", "login", "--tenant", "globex", "--issuer", &issuer])
        .env("CLAVENAR_CREDENTIALS_PATH", &credentials)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cross-tenant clavenarctl");
    let stdout = wrong_tenant.stdout.take().expect("cross-tenant stdout");
    let mut lines = BufReader::new(stdout).lines();
    assert!(
        lines
            .next()
            .expect("cross-tenant prompt")
            .expect("read cross-tenant prompt")
            .starts_with("Open ")
    );
    let complete = lines
        .next()
        .expect("cross-tenant complete URL")
        .expect("read cross-tenant complete URL")
        .strip_prefix("Verification URL: ")
        .expect("cross-tenant URL prefix")
        .parse::<Url>()
        .expect("cross-tenant verification URL");
    let browser_client = browser();
    let login = submit_login(&browser_client, complete).await;
    confirm_device(&browser_client, login).await;
    let status = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(status) = wrong_tenant.try_wait().expect("poll cross-tenant CLI") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("cross-tenant CLI completed before timeout");
    assert_eq!(status.code(), Some(3));
    let document: Value =
        serde_json::from_slice(&std::fs::read(&credentials).expect("credential bytes"))
            .expect("credential JSON");
    assert!(
        document["tenants"].get("globex").is_none(),
        "cross-tenant token must not be persisted"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_keycloak_form_action() {
        let html = r#"<form id="kc-device-verify" action="http://idp.test/a?x=1&amp;y=2">"#;
        assert_eq!(
            extract_tag_attribute(html, "form", "id", "kc-device-verify", "action").as_deref(),
            Some("http://idp.test/a?x=1&y=2")
        );
    }
}
