//! Process injection and output redaction for `velt run` and the MCP runner.

use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use velt_core::lease;
use velt_core::vault::now_unix;
use velt_core::Vault;
use zeroize::Zeroizing;

use crate::cli::{Cli, RedactMode, RunArgs};
use crate::context;
use crate::error::{CliError, Result};
use crate::redact::{self, SecretPatterns};

const CAPTURE_LIMIT: usize = 1024 * 1024;

pub struct Prepared {
    pub pairs: Vec<(String, Zeroizing<String>)>,
    pub all_names: Vec<String>,
}

/// Resolve the environment that will be injected, applying a lease if present.
pub fn prepare(vault: &Vault, lease_token: Option<&str>) -> Result<Prepared> {
    let all_pairs = vault.env_pairs();
    let all_names: Vec<String> = all_pairs.iter().map(|(name, _)| name.clone()).collect();
    let pairs = match lease_token.filter(|token| !token.trim().is_empty()) {
        None => all_pairs,
        Some(token) => {
            let secret = context::lease_secret(&vault.header.vault_id, false)?;
            let vault_id = vault.vault_id_hex();
            let verified = lease::verify(&secret, token, &vault_id, now_unix())?;
            all_pairs
                .into_iter()
                .filter(|(name, _)| verified.allows(name))
                .collect()
        }
    };
    Ok(Prepared { pairs, all_names })
}

fn inject(command: &mut Command, prepared: &Prepared) {
    // Parent environment entries for vault-managed names are removed unless the
    // lease actually grants them. This prevents inherited secrets from leaking
    // around a restricted lease.
    let allowed: std::collections::BTreeSet<&str> = prepared
        .pairs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for name in &prepared.all_names {
        if !allowed.contains(name.as_str()) {
            command.env_remove(name);
        }
    }
    for (name, value) in &prepared.pairs {
        command.env(name, value.as_str());
    }
}

fn should_redact(mode: RedactMode) -> bool {
    match mode {
        RedactMode::Always => true,
        RedactMode::Never => false,
        RedactMode::Auto => !(io::stdout().is_terminal() && io::stderr().is_terminal()),
    }
}

pub fn execute(_cli: &Cli, args: &RunArgs) -> Result<i32> {
    if args.command.is_empty() {
        return Err(CliError::msg(
            "no command provided; use `velt run -- <command>`",
        ));
    }
    let vault_path = context::discover_vault(_cli.vault.clone())?;
    let (vault, _key) = context::open_vault(&vault_path)?;
    let prepared = prepare(&vault, args.lease.as_deref())?;

    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    inject(&mut command, &prepared);

    let redact_output = should_redact(args.redact);
    if redact_output {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    } else {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }

    let program = args.command[0].to_string_lossy().into_owned();
    let mut child = command.spawn().map_err(|err| spawn_error(&program, err))?;
    let signals = SignalForwarder::install(child.id());

    let (stdout_thread, stderr_thread) = if redact_output {
        let patterns = SecretPatterns::from_pairs(&prepared.pairs);
        if patterns.skipped > 0 {
            eprintln!(
                "warning: {} secret(s) exceed the 64 KiB redaction limit and were not redacted",
                patterns.skipped
            );
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdout_patterns = patterns.clone();
        let stderr_patterns = patterns.clone();
        let stdout_thread = stdout.map(|reader| {
            thread::Builder::new()
                .name("velt-stdout".to_owned())
                .spawn(move || redact::stream_scrubbed(reader, io::stdout(), &stdout_patterns))
        });
        let stderr_thread = stderr.map(|reader| {
            thread::Builder::new()
                .name("velt-stderr".to_owned())
                .spawn(move || redact::stream_scrubbed(reader, io::stderr(), &stderr_patterns))
        });
        (stdout_thread, stderr_thread)
    } else {
        (None, None)
    };

    let status = wait_with_signals(&mut child, signals)?;
    join_stream(stdout_thread, "stdout")?;
    join_stream(stderr_thread, "stderr")?;
    Ok(exit_code(status))
}

fn join_stream(
    handle: Option<Result<thread::JoinHandle<io::Result<()>>, io::Error>>,
    name: &str,
) -> Result<()> {
    let Some(handle) = handle else {
        return Ok(());
    };
    let handle =
        handle.map_err(|err| CliError::msg(format!("could not start {name} reader: {err}")))?;
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Ok(Err(err)) => Err(CliError::msg(format!("{name} reader failed: {err}"))),
        Err(_) => Err(CliError::msg(format!("{name} reader panicked"))),
    }
}

#[derive(Debug, Default)]
pub struct CapturedRun {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub redaction_skipped: usize,
}

/// Execute a command with injected secrets and fully captured, redacted output.
/// Used by the MCP server, where stdout belongs to the JSON-RPC transport.
pub fn capture(
    vault: &Vault,
    command: &[String],
    cwd: Option<&Path>,
    lease_token: Option<&str>,
    timeout: Duration,
) -> Result<CapturedRun> {
    if command.is_empty() {
        return Err(CliError::msg("command array is empty"));
    }
    if let Some(cwd) = cwd {
        if !cwd.is_dir() {
            return Err(CliError::msg(format!(
                "working directory does not exist: {}",
                cwd.display()
            )));
        }
    }
    let prepared = prepare(vault, lease_token)?;
    let mut process = Command::new(&command[0]);
    process.args(&command[1..]);
    process
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        process.current_dir(cwd);
    }
    inject(&mut process, &prepared);

    let program = command[0].clone();
    let mut child = process.spawn().map_err(|err| spawn_error(&program, err))?;
    let mut signals = SignalForwarder::install(child.id());
    let patterns = SecretPatterns::from_pairs(&prepared.pairs);
    let redaction_skipped = patterns.skipped;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_patterns = patterns.clone();
    let stderr_patterns = patterns.clone();
    let stdout_thread = stdout.map(|reader| {
        thread::Builder::new()
            .name("velt-capture-stdout".to_owned())
            .spawn(move || redact::capture_scrubbed(reader, &stdout_patterns, CAPTURE_LIMIT))
    });
    let stderr_thread = stderr.map(|reader| {
        thread::Builder::new()
            .name("velt-capture-stderr".to_owned())
            .spawn(move || redact::capture_scrubbed(reader, &stderr_patterns, CAPTURE_LIMIT))
    });

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| CliError::io(&program, err))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            timed_out = true;
            break child.wait().map_err(|err| CliError::io(&program, err))?;
        }
        thread::sleep(Duration::from_millis(25));
    };
    signals.finish();

    let stdout = join_capture(stdout_thread, "stdout")?;
    let stderr = join_capture(stderr_thread, "stderr")?;
    Ok(CapturedRun {
        status: exit_code(status),
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        timed_out,
        redaction_skipped,
    })
}

fn join_capture(
    handle: Option<Result<thread::JoinHandle<io::Result<redact::CapturedOutput>>, io::Error>>,
    name: &str,
) -> Result<redact::CapturedOutput> {
    let Some(handle) = handle else {
        return Ok(redact::CapturedOutput::default());
    };
    let handle =
        handle.map_err(|err| CliError::msg(format!("could not start {name} reader: {err}")))?;
    match handle.join() {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(CliError::msg(format!("{name} reader failed: {err}"))),
        Err(_) => Err(CliError::msg(format!("{name} reader panicked"))),
    }
}

fn spawn_error(program: &str, err: io::Error) -> CliError {
    if err.kind() == io::ErrorKind::NotFound {
        CliError::msg(format!("command not found: {program}"))
    } else {
        CliError::io(program, err)
    }
}

fn wait_with_signals(child: &mut Child, mut signals: SignalForwarder) -> Result<ExitStatus> {
    let status = child.wait().map_err(|err| CliError::io("<child>", err))?;
    signals.finish();
    Ok(status)
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(unix)]
struct SignalForwarder {
    handle: Option<signal_hook::iterator::Handle>,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl SignalForwarder {
    fn install(pid: u32) -> Self {
        let signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGQUIT,
        ]);
        let Ok(mut signals) = signals else {
            return Self {
                handle: None,
                thread: None,
            };
        };
        let handle = signals.handle();
        let thread = thread::Builder::new()
            .name("velt-signals".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    // SAFETY: this is a direct `kill(2)` system call. `pid` is
                    // the positive PID returned by `Command::spawn`; `signal`
                    // comes from signal-hook's fixed constant set. The call has
                    // no Rust memory-safety preconditions, and ESRCH after child
                    // exit is intentionally ignored.
                    unsafe {
                        libc::kill(pid as i32, signal);
                    }
                }
            })
            .ok();
        Self {
            handle: Some(handle),
            thread,
        }
    }

    fn finish(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.close();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(not(unix))]
struct SignalForwarder;

#[cfg(not(unix))]
impl SignalForwarder {
    fn install(_pid: u32) -> Self {
        Self
    }

    fn finish(&mut self) {}
}
