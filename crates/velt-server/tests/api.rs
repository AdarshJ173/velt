//! End-to-end relay test against a real embedded PostgreSQL instance.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use futures_util::StreamExt;
use postgresql_embedded::blocking::PostgreSQL;
use postgresql_embedded::Settings;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use velt_core::sync::{seal_team_key, TeamIdentity, TeamPayload};
use velt_core::vault::now_unix;
use velt_core::Entry;
use velt_server::config::Config;
use velt_server::events::{self, EventBus};
use velt_server::{build_app, connect_database, run_migrations, AppState, AUTH_NAMESPACE};

fn ssh_key() -> (PrivateKey, String) {
    let key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    (key, public)
}

fn entries() -> BTreeMap<String, Entry> {
    let mut entries = BTreeMap::new();
    entries.insert(
        "DATABASE_URL".to_owned(),
        Entry {
            value: "postgres://localhost/app".into(),
            updated_at: now_unix(),
            expires_at: None,
        },
    );
    entries.insert(
        "STRIPE_KEY".to_owned(),
        Entry {
            value: "sk_live_test_value".into(),
            updated_at: now_unix(),
            expires_at: None,
        },
    );
    entries
}

async fn call(
    client: &Client,
    method: Method,
    url: String,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = client.request(method, url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("http request");
    let status = response.status();
    let text = response.text().await.expect("response body");
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, value)
}

async fn register(
    client: &Client,
    base: &str,
    username: &str,
    ssh: &PrivateKey,
    identity: &TeamIdentity,
) -> Value {
    let (status, body) = call(
        client,
        Method::POST,
        format!("{base}/v1/auth/register"),
        None,
        Some(json!({
            "username": username,
            "ssh_public_key": ssh.public_key().to_openssh().unwrap(),
            "encryption_public_key": identity.public_base64(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");
    body
}

async fn login(client: &Client, base: &str, username: &str, ssh: &PrivateKey) -> String {
    let (status, challenge) = call(
        client,
        Method::POST,
        format!("{base}/v1/auth/challenge"),
        None,
        Some(json!({"username": username})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge failed: {challenge}");
    let challenge_id = challenge["challenge_id"].as_str().unwrap().to_owned();
    let bytes = STANDARD_NO_PAD
        .decode(challenge["challenge"].as_str().unwrap())
        .unwrap();
    let signature = ssh.sign(AUTH_NAMESPACE, HashAlg::Sha512, &bytes).unwrap();
    let pem = signature.to_pem(LineEnding::LF).unwrap();
    let (status, response) = call(
        client,
        Method::POST,
        format!("{base}/v1/auth/verify"),
        None,
        Some(json!({"challenge_id": challenge_id, "signature": pem})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify failed: {response}");
    response["token"].as_str().unwrap().to_owned()
}

#[allow(clippy::too_many_arguments)]
async fn push(
    client: &Client,
    base: &str,
    token: &str,
    team_id: Uuid,
    team_key: &[u8; 32],
    entries: &BTreeMap<String, Entry>,
    base_version: Option<i64>,
    force: bool,
) -> (StatusCode, Value) {
    let mut payload = TeamPayload::new(team_id.to_string(), "production", entries.clone());
    let encrypted = payload.encrypt(team_key).unwrap();
    call(
        client,
        Method::PUT,
        format!("{base}/v1/teams/{team_id}/environments/production"),
        Some(token),
        Some(json!({
            "base_version": base_version,
            "force": force,
            "nonce": encrypted.nonce_base64(),
            "ciphertext": encrypted.ciphertext_base64(),
            "checksum": encrypted.checksum_base64(),
        })),
    )
    .await
}

async fn pull(
    client: &Client,
    base: &str,
    token: &str,
    team_id: Uuid,
    team_key: &[u8; 32],
) -> Value {
    let (status, body) = call(
        client,
        Method::GET,
        format!("{base}/v1/teams/{team_id}/environments/production"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "pull failed: {body}");
    assert_eq!(body["not_modified"], false);
    let nonce_bytes = STANDARD_NO_PAD
        .decode(body["nonce"].as_str().unwrap())
        .unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    let ciphertext = STANDARD_NO_PAD
        .decode(body["ciphertext"].as_str().unwrap())
        .unwrap();
    let payload = TeamPayload::decrypt(
        team_key,
        &team_id.to_string(),
        "production",
        &nonce,
        &ciphertext,
    )
    .unwrap();
    json!({
        "version": body["version"].clone(),
        "entries": payload.entries,
    })
}

#[test]
fn relay_end_to_end() {
    let data = TempDir::new().unwrap();
    let mut settings = Settings::new();
    settings.data_dir = data.path().join("data");
    std::fs::create_dir_all(&settings.data_dir).unwrap();
    settings.port = 0;
    settings.timeout = Some(Duration::from_secs(30));
    let mut postgres = PostgreSQL::new(settings);
    postgres.setup().expect("postgres setup");
    postgres.start().expect("postgres start");
    let database_url = postgres.settings().url("postgres");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let pool = connect_database(&database_url).await.unwrap();
        run_migrations(&pool).await.unwrap();
        let bus = EventBus::new(1024);
        events::spawn_listener(&database_url, bus.clone())
            .await
            .unwrap();

        let config = Config {
            database_url: database_url.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            session_ttl_seconds: 3600,
            challenge_ttl_seconds: 300,
            max_blob_bytes: 4 * 1024 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            max_envelopes: 64,
            public_url: None,
        };
        let listener = TcpListener::bind(config.bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = AppState {
            db: pool.clone(),
            config: Arc::new(config),
            events: bus,
        };
        let server = tokio::spawn(async move {
            axum::serve(listener, build_app(state)).await.unwrap();
        });
        let base = format!("http://{address}");
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        // Health and readiness.
        assert_eq!(
            call(&client, Method::GET, format!("{base}/healthz"), None, None)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(&client, Method::GET, format!("{base}/readyz"), None, None)
                .await
                .0,
            StatusCode::OK
        );

        // Register and authenticate two developers.
        let (alice_ssh, _) = ssh_key();
        let alice_identity = TeamIdentity::generate().unwrap();
        let alice = register(&client, &base, "alice", &alice_ssh, &alice_identity).await;
        let alice_id: Uuid = serde_json::from_value(alice["id"].clone()).unwrap();
        let alice_token = login(&client, &base, "alice", &alice_ssh).await;

        let (bob_ssh, _) = ssh_key();
        let bob_identity = TeamIdentity::generate().unwrap();
        let bob = register(&client, &base, "bob", &bob_ssh, &bob_identity).await;
        let bob_id: Uuid = serde_json::from_value(bob["id"].clone()).unwrap();
        let bob_token = login(&client, &base, "bob", &bob_ssh).await;

        let (status, me) = call(
            &client,
            Method::GET,
            format!("{base}/v1/me"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["user"]["username"], "alice");
        assert_eq!(
            call(&client, Method::GET, format!("{base}/v1/me"), None, None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        // Create a team with a self envelope, then push and pull encrypted data.
        let team_id = Uuid::new_v4();
        let team_key = *velt_core::crypto::random_key().unwrap();
        let self_envelope = seal_team_key(
            alice_identity.public(),
            &team_id.to_string(),
            1,
            "alice",
            &team_key,
        )
        .unwrap();
        let (status, team) = call(
            &client,
            Method::POST,
            format!("{base}/v1/teams"),
            Some(&alice_token),
            Some(json!({"team_id": team_id, "name": "acme", "envelope": self_envelope})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create team failed: {team}");
        assert_eq!(team["key_epoch"], 1);

        let (status, pushed) = push(
            &client,
            &base,
            &alice_token,
            team_id,
            &team_key,
            &entries(),
            None,
            false,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "push failed: {pushed}");
        assert_eq!(pushed["version"], 1);

        let pulled = pull(&client, &base, &alice_token, team_id, &team_key).await;
        assert_eq!(pulled["version"], 1);
        assert_eq!(
            pulled["entries"]["STRIPE_KEY"]["value"],
            "sk_live_test_value"
        );

        let (status, conflict) = push(
            &client,
            &base,
            &alice_token,
            team_id,
            &team_key,
            &entries(),
            None,
            false,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "stale push must fail: {conflict}"
        );

        // Bob discovers Alice's team by invitation and receives the sealed team key.
        let (status, bob_lookup) = call(
            &client,
            Method::GET,
            format!("{base}/v1/users/bob"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            bob_lookup["encryption_public_key"],
            bob_identity.public_base64()
        );

        let bob_envelope = seal_team_key(
            bob_identity.public(),
            &team_id.to_string(),
            1,
            "bob",
            &team_key,
        )
        .unwrap();
        let (status, invited) = call(
            &client,
            Method::POST,
            format!("{base}/v1/teams/{team_id}/members"),
            Some(&alice_token),
            Some(json!({
                "username": "bob",
                "role": "developer",
                "env_grants": ["production"],
                "envelope": bob_envelope,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "invite failed: {invited}");

        let (status, envelopes) = call(
            &client,
            Method::GET,
            format!("{base}/v1/teams/{team_id}/envelopes"),
            Some(&bob_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "envelopes failed: {envelopes}");
        let envelope = &envelopes["envelopes"][0];
        let sealed = velt_core::sync::SealedTeamKey {
            recipient: "bob".to_owned(),
            epoch: envelope["epoch"].as_u64().unwrap() as u32,
            ephemeral_public: envelope["ephemeral_public_key"]
                .as_str()
                .unwrap()
                .to_owned(),
            nonce: envelope["nonce"].as_str().unwrap().to_owned(),
            ciphertext: envelope["ciphertext"].as_str().unwrap().to_owned(),
        };
        let bob_team_key =
            velt_core::sync::open_team_key(bob_identity.secret(), &team_id.to_string(), &sealed)
                .unwrap();
        assert_eq!(&bob_team_key[..], &team_key);

        // Bob can read and push; he cannot manage membership or read audit logs.
        let bob_pull = pull(&client, &base, &bob_token, team_id, &team_key).await;
        assert_eq!(
            bob_pull["entries"]["DATABASE_URL"]["value"],
            "postgres://localhost/app"
        );
        assert_eq!(
            call(
                &client,
                Method::GET,
                format!("{base}/v1/teams/{team_id}/audit"),
                Some(&bob_token),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &client,
                Method::POST,
                format!("{base}/v1/teams/{team_id}/members"),
                Some(&bob_token),
                Some(json!({
                    "username": "alice",
                    "role": "developer",
                    "env_grants": [],
                    "envelope": bob_envelope,
                }))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        let (status, bob_push) = push(
            &client,
            &base,
            &bob_token,
            team_id,
            &team_key,
            &entries(),
            Some(1),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "developer push failed: {bob_push}");
        assert_eq!(bob_push["version"], 2);

        // WebSocket notifications arrive after a commit.
        let ws_url = format!("ws://{address}/v1/teams/{team_id}/events?token={alice_token}");
        let (mut socket, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
        let ready = socket.next().await.unwrap().unwrap();
        match ready {
            Message::Text(text) => assert!(text.contains("ready")),
            other => panic!("unexpected ready message: {other:?}"),
        }
        let (status, _) = push(
            &client,
            &base,
            &alice_token,
            team_id,
            &team_key,
            &entries(),
            Some(2),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let event = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("websocket event timeout")
            .expect("websocket closed")
            .expect("websocket error");
        match event {
            Message::Text(text) => {
                assert!(text.contains("vault_updated"), "unexpected event: {text}");
                assert!(text.contains("\"version\":3"), "unexpected event: {text}");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Revoke Bob, rotate the team key, and re-encrypt the environment.
        let (status, removed) = call(
            &client,
            Method::DELETE,
            format!("{base}/v1/teams/{team_id}/members/{bob_id}"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(removed["key_rotation_required"], true);
        assert_eq!(
            call(
                &client,
                Method::GET,
                format!("{base}/v1/teams/{team_id}/environments/production"),
                Some(&bob_token),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );

        let current = call(
            &client,
            Method::GET,
            format!("{base}/v1/teams/{team_id}/environments/production"),
            Some(&alice_token),
            None,
        )
        .await
        .1;
        assert_eq!(current["version"], 3);
        let mut old_nonce = [0u8; 12];
        old_nonce.copy_from_slice(
            &STANDARD_NO_PAD
                .decode(current["nonce"].as_str().unwrap())
                .unwrap(),
        );
        let old_ciphertext = STANDARD_NO_PAD
            .decode(current["ciphertext"].as_str().unwrap())
            .unwrap();
        let old_payload = TeamPayload::decrypt(
            &team_key,
            &team_id.to_string(),
            "production",
            &old_nonce,
            &old_ciphertext,
        )
        .unwrap();

        let new_team_key = *velt_core::crypto::random_key().unwrap();
        let mut rotated_payload = TeamPayload::new(
            team_id.to_string(),
            "production",
            old_payload.entries.clone(),
        );
        let rotated_blob = rotated_payload.encrypt(&new_team_key).unwrap();
        let new_envelope = seal_team_key(
            alice_identity.public(),
            &team_id.to_string(),
            2,
            "alice",
            &new_team_key,
        )
        .unwrap();
        let (status, rotated) = call(
            &client,
            Method::POST,
            format!("{base}/v1/teams/{team_id}/key-epoch"),
            Some(&alice_token),
            Some(json!({
                "epoch": 2,
                "envelopes": [{
                    "user_id": alice_id,
                    "epoch": 2,
                    "ephemeral_public_key": new_envelope.ephemeral_public,
                    "nonce": new_envelope.nonce,
                    "ciphertext": new_envelope.ciphertext,
                }],
                "blobs": [{
                    "environment": "production",
                    "base_version": 3,
                    "nonce": rotated_blob.nonce_base64(),
                    "ciphertext": rotated_blob.ciphertext_base64(),
                    "checksum": rotated_blob.checksum_base64(),
                }],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "rotation failed: {rotated}");
        assert_eq!(rotated["key_epoch"], 2);

        let rotated_pull = pull(&client, &base, &alice_token, team_id, &new_team_key).await;
        assert_eq!(rotated_pull["version"], 4);
        assert_eq!(
            rotated_pull["entries"]["DATABASE_URL"]["value"],
            "postgres://localhost/app"
        );

        // Dashboard: one-time login link, cookie session, rendered team and CSV.
        let (status, link) = call(
            &client,
            Method::POST,
            format!("{base}/v1/dashboard/session"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "dashboard link failed: {link}");
        let login_path = link["path"].as_str().unwrap();
        let no_redirect = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let confirm = no_redirect
            .get(format!("{base}{login_path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(confirm.status(), StatusCode::OK);
        let confirm_html = confirm.text().await.unwrap();
        assert!(confirm_html.contains("Continue to dashboard"));
        let token = login_path.split_once("token=").unwrap().1;

        let login = no_redirect
            .post(format!("{base}/dashboard/login"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(format!("token={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(cookie.starts_with("velt_dashboard="));

        // A one-time link cannot be replayed.
        let replay = no_redirect
            .post(format!("{base}/dashboard/login"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(format!("token={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        let dashboard = no_redirect
            .get(format!("{base}/dashboard"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(dashboard.status(), StatusCode::OK);
        let html = dashboard.text().await.unwrap();
        assert!(html.contains("acme"), "dashboard did not render team");
        assert!(html.contains("Zero-knowledge"));

        let team_page = no_redirect
            .get(format!("{base}/dashboard/teams/{team_id}"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(team_page.status(), StatusCode::OK);
        let html = team_page.text().await.unwrap();
        assert!(html.contains("Members"));
        assert!(html.contains("Audit trail"));
        assert!(html.contains("Revocation requires key rotation"));

        let csv = no_redirect
            .get(format!("{base}/dashboard/teams/{team_id}/audit.csv"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(csv.status(), StatusCode::OK);
        assert!(csv.headers()[reqwest::header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv"));
        let csv_body = csv.text().await.unwrap();
        assert!(csv_body.contains("key_rotated"));

        // Logout revokes the dashboard session, not just the browser cookie.
        let logout = no_redirect
            .post(format!("{base}/dashboard/logout"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::SEE_OTHER);
        let after_logout = no_redirect
            .get(format!("{base}/dashboard"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(after_logout.status(), StatusCode::SEE_OTHER);

        // The owner can read the audit trail and delete the team.
        let (status, audit) = call(
            &client,
            Method::GET,
            format!("{base}/v1/teams/{team_id}/audit"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let actions: Vec<&str> = audit["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["action"].as_str())
            .collect();
        for expected in [
            "team_created",
            "member_added",
            "vault_pushed",
            "member_removed",
            "key_rotated",
        ] {
            assert!(
                actions.contains(&expected),
                "missing audit action {expected}"
            );
        }

        let (status, _) = call(
            &client,
            Method::DELETE,
            format!("{base}/v1/teams/{team_id}"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        socket.close(None).await.ok();
        server.abort();
    });

    postgres.stop().expect("stop postgres");
}
