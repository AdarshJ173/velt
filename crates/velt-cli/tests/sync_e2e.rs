//! Full CLI-to-relay test with a real embedded PostgreSQL and two OS users'
//! worth of isolated configuration, keys and vaults.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use postgresql_embedded::blocking::PostgreSQL;
use postgresql_embedded::Settings;
use serde_json::Value;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;
use tokio::net::TcpListener;
use velt_server::config::Config;
use velt_server::events::{self, EventBus};
use velt_server::{build_app, connect_database, run_migrations, AppState};

fn velt(config_dir: &Path) -> AssertCommand {
    let mut command = AssertCommand::cargo_bin("velt").expect("velt binary");
    command
        .env("VELT_CONFIG_DIR", config_dir)
        .env("NO_COLOR", "1")
        .env_remove("VELT_VAULT")
        .env_remove("VELT_SERVER_URL");
    command
}

fn run(command: &mut AssertCommand) -> Output {
    command.output().expect("run velt")
}

fn run_json(command: &mut AssertCommand) -> Value {
    let output = run(command);
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid JSON output: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn make_ssh_key(directory: &Path, name: &str) -> PathBuf {
    let key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519).unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    let path = directory.join(format!("{name}_ed25519"));
    fs::write(&path, pem.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn start_relay(database_url: String) -> String {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            let pool = connect_database(&database_url).await.expect("connect db");
            run_migrations(&pool).await.expect("migrations");
            let bus = EventBus::new(1024);
            events::spawn_listener(&database_url, bus.clone())
                .await
                .expect("event listener");
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().unwrap();
            let config = Config {
                database_url,
                bind: address,
                session_ttl_seconds: 3600,
                challenge_ttl_seconds: 300,
                max_blob_bytes: 4 * 1024 * 1024,
                max_envelopes: 64,
                public_url: None,
            };
            let state = AppState {
                db: pool,
                config: Arc::new(config),
                events: bus,
            };
            sender.send(address.to_string()).expect("send address");
            axum::serve(listener, build_app(state)).await.unwrap();
        });
    });
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("relay startup")
}

#[test]
fn cli_sync_end_to_end() {
    let postgres_data = TempDir::new().unwrap();
    let mut settings = Settings::new();
    settings.data_dir = postgres_data.path().join("data");
    std::fs::create_dir_all(&settings.data_dir).unwrap();
    settings.port = 0;
    settings.timeout = Some(Duration::from_secs(30));
    let mut postgres = PostgreSQL::new(settings);
    postgres.setup().expect("postgres setup");
    postgres.start().expect("postgres start");
    let database_url = postgres.settings().url("postgres");
    let base = format!("http://{}", start_relay(database_url));

    let root = TempDir::new().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    let alice_config = root.path().join("config-alice");
    let bob_config = root.path().join("config-bob");
    fs::create_dir_all(&alice_dir).unwrap();
    fs::create_dir_all(&bob_dir).unwrap();
    fs::create_dir_all(&alice_config).unwrap();
    fs::create_dir_all(&bob_config).unwrap();
    let alice_ssh = make_ssh_key(root.path(), "alice");
    let bob_ssh = make_ssh_key(root.path(), "bob");

    // Register and authenticate both users.
    let mut alice = velt(&alice_config);
    alice.args([
        "--json",
        "auth",
        "register",
        "--server",
        &base,
        "--username",
        "alice",
        "--ssh-key",
        alice_ssh.to_str().unwrap(),
    ]);
    let value = run_json(&mut alice);
    assert_eq!(value["username"], "alice");
    assert_eq!(value["authenticated"], true);

    let mut bob = velt(&bob_config);
    bob.args([
        "--json",
        "auth",
        "register",
        "--server",
        &base,
        "--username",
        "bob",
        "--ssh-key",
        bob_ssh.to_str().unwrap(),
    ]);
    let value = run_json(&mut bob);
    assert_eq!(value["username"], "bob");

    // Alice creates a team and a vault, then binds and pushes.
    let mut alice = velt(&alice_config);
    alice.args(["--json", "team", "create", "acme"]);
    let created = run_json(&mut alice);
    let team_id = created["team"]["id"].as_str().unwrap().to_owned();

    let mut alice = velt(&alice_config);
    alice
        .current_dir(&alice_dir)
        .args(["--json", "init", "--no-agent-files"]);
    run_json(&mut alice);

    let mut alice = velt(&alice_config);
    alice
        .current_dir(&alice_dir)
        .args(["--json", "set", "API_KEY", "--stdin"])
        .write_stdin("alice-secret-123456");
    run_json(&mut alice);

    let mut alice = velt(&alice_config);
    alice.current_dir(&alice_dir).args([
        "--json",
        "sync",
        "init",
        "--team",
        &team_id,
        "--env",
        "production",
    ]);
    let bound = run_json(&mut alice);
    assert_eq!(bound["environment"], "production");

    let mut alice = velt(&alice_config);
    alice
        .current_dir(&alice_dir)
        .args(["--json", "sync", "push"]);
    let pushed = run_json(&mut alice);
    assert_eq!(pushed["version"], 1);

    // Bob joins, binds, pulls and decrypts.
    let mut alice = velt(&alice_config);
    alice.args([
        "--json",
        "team",
        "invite",
        "bob",
        "--team",
        &team_id,
        "--env",
        "production",
    ]);
    let invited = run_json(&mut alice);
    assert_eq!(invited["member"]["username"], "bob");

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir)
        .args(["--json", "init", "--no-agent-files"]);
    run_json(&mut bob);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir).args([
        "--json",
        "sync",
        "init",
        "--team",
        &team_id,
        "--env",
        "production",
    ]);
    run_json(&mut bob);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir).args(["--json", "sync", "pull"]);
    let pulled = run_json(&mut bob);
    assert_eq!(pulled["version"], 1);
    assert_eq!(pulled["added"], 1);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir)
        .args(["get", "API_KEY", "--no-newline"]);
    let output = run(&mut bob);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "alice-secret-123456"
    );

    // Rotate the key after a member has enrolled; Bob must receive epoch 2.
    let mut alice = velt(&alice_config);
    alice
        .current_dir(&alice_dir)
        .args(["--json", "team", "rotate-key", "--team", &team_id]);
    let rotated = run_json(&mut alice);
    assert_eq!(rotated["key_epoch"], 2);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir)
        .args(["--json", "sync", "pull", "--force"]);
    let pulled = run_json(&mut bob);
    assert_eq!(pulled["version"], 2);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir)
        .args(["get", "API_KEY", "--no-newline"]);
    let output = run(&mut bob);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "alice-secret-123456"
    );

    // Revoke Bob; he must no longer be able to pull.
    let mut alice = velt(&alice_config);
    alice.args([
        "--json", "team", "remove", "bob", "--team", &team_id, "--yes",
    ]);
    let removed = run_json(&mut alice);
    assert_eq!(removed["key_rotation_required"], true);

    let mut bob = velt(&bob_config);
    bob.current_dir(&bob_dir)
        .args(["--json", "sync", "pull", "--force"]);
    let output = run(&mut bob);
    assert!(
        !output.status.success(),
        "revoked member must not be able to pull: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // The owner can read the audit trail.
    let mut alice = velt(&alice_config);
    alice.args(["--json", "team", "audit", "--team", &team_id]);
    let audit = run_json(&mut alice);
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["action"].as_str())
        .collect();
    for expected in [
        "member_added",
        "vault_pushed",
        "key_rotated",
        "member_removed",
    ] {
        assert!(
            actions.contains(&expected),
            "missing audit action {expected}"
        );
    }

    postgres.stop().expect("stop postgres");
}
