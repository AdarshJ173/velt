//! Interactive terminal editor built with ratatui.
//!
//! The editor holds the write lock for its lifetime so two editors cannot lose
//! updates. Changes are saved explicitly (`s`); quitting with unsaved changes
//! requires a confirmation. Values are masked until revealed; the edit popup
//! necessarily displays the value being typed.

use std::io::{self, IsTerminal};
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::{Frame, Terminal};
use velt_core::audit::{classify, SecretStatus};
use velt_core::vault::{validate_name, Vault, VaultLock};
use velt_core::{MasterKey, SecretValue};
use zeroize::Zeroizing;

use crate::cli::Cli;
use crate::error::{CliError, Result};
use crate::util;

const AMBER: Color = Color::Rgb(255, 159, 28);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    KeyInput,
    ValueInput,
    ConfirmDelete,
    ConfirmQuit,
    Help,
}

pub fn execute(cli: &Cli) -> Result<i32> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(CliError::msg(
            "`velt edit` requires an interactive terminal; use `velt set` or `velt tui` from a TTY",
        ));
    }
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let context = crate::context::WriteContext::open(&path)?;
    let (vault, key, lock) = context.into_parts();
    let mut app = App::new(vault, key, Some(lock));
    run_terminal(&mut app, &path)?;
    Ok(0)
}

struct App {
    vault: Vault,
    key: MasterKey,
    _lock: Option<VaultLock>,
    selected: usize,
    reveal: bool,
    mode: Mode,
    key_input: String,
    value_input: Zeroizing<String>,
    editing_key: Option<String>,
    message: Option<(bool, String)>,
    dirty: bool,
}

impl App {
    fn new(vault: Vault, key: MasterKey, lock: Option<VaultLock>) -> Self {
        Self {
            vault,
            key,
            _lock: lock,
            selected: 0,
            reveal: false,
            mode: Mode::Normal,
            key_input: String::new(),
            value_input: Zeroizing::new(String::new()),
            editing_key: None,
            message: None,
            dirty: false,
        }
    }

    fn names(&self) -> Vec<String> {
        self.vault.entries().keys().cloned().collect()
    }

    fn selected_name(&self) -> Option<String> {
        self.names().get(self.selected).cloned()
    }

    fn clamp_selection(&mut self) {
        let count = self.vault.entries().len();
        if count == 0 {
            self.selected = 0;
        } else if self.selected >= count {
            self.selected = count - 1;
        }
    }

    fn message(&mut self, error: bool, text: impl Into<String>) {
        self.message = Some((error, text.into()));
    }

    fn save(&mut self) -> bool {
        match self.vault.save(&self.key) {
            Ok(()) => {
                self.dirty = false;
                self.message(false, "Saved.");
                true
            }
            Err(error) => {
                self.message(true, format!("Save failed: {error}"));
                false
            }
        }
    }

    fn start_new(&mut self) {
        self.mode = Mode::KeyInput;
        self.key_input.clear();
        self.value_input = Zeroizing::new(String::new());
        self.editing_key = None;
        self.message = None;
    }

    fn start_edit(&mut self) {
        let Some(name) = self.selected_name() else {
            self.message(true, "No entry selected.");
            return;
        };
        if let Some(entry) = self.vault.get(&name) {
            self.value_input = Zeroizing::new(entry.value.expose().to_owned());
            self.editing_key = Some(name);
            self.mode = Mode::ValueInput;
            self.message = None;
        }
    }

    fn delete_selected(&mut self) {
        let Some(name) = self.selected_name() else {
            return;
        };
        if self.vault.remove(&name) {
            self.dirty = true;
            self.clamp_selection();
            self.message(false, format!("Removed {name}."));
        }
    }

    /// Returns true when the application should exit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.dirty {
                self.mode = Mode::ConfirmQuit;
                return false;
            }
            return true;
        }
        match self.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::KeyInput => self.handle_key_input(key),
            Mode::ValueInput => self.handle_value_input(key),
            Mode::ConfirmDelete => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        self.delete_selected();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.mode = Mode::Normal;
                    }
                    _ => {}
                }
                false
            }
            Mode::ConfirmQuit => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if self.save() {
                            return true;
                        }
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') => return true,
                    KeyCode::Esc => self.mode = Mode::Normal,
                    _ => {}
                }
                false
            }
            Mode::Help => {
                self.mode = Mode::Normal;
                false
            }
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.vault.entries().len() {
                    self.selected += 1;
                }
            }
            KeyCode::Char('g') | KeyCode::Home => self.selected = 0,
            KeyCode::Char('G') | KeyCode::End => {
                self.selected = self.vault.entries().len().saturating_sub(1);
            }
            KeyCode::Char('a') | KeyCode::Char('n') => self.start_new(),
            KeyCode::Char('e') | KeyCode::Enter => self.start_edit(),
            KeyCode::Char('d') if !self.vault.entries().is_empty() => {
                self.mode = Mode::ConfirmDelete;
            }
            KeyCode::Char('r') => self.reveal = !self.reveal,
            KeyCode::Char('s') => {
                self.save();
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.dirty {
                    self.mode = Mode::ConfirmQuit;
                } else {
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    fn handle_key_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.message = None;
            }
            KeyCode::Enter => {
                let name = self.key_input.trim().to_owned();
                match validate_name(&name) {
                    Ok(()) => {
                        if let Some(existing) = self.vault.get(&name) {
                            self.value_input = Zeroizing::new(existing.value.expose().to_owned());
                        } else {
                            self.value_input = Zeroizing::new(String::new());
                        }
                        self.editing_key = Some(name);
                        self.mode = Mode::ValueInput;
                        self.message = None;
                    }
                    Err(error) => self.message(true, error.to_string()),
                }
            }
            KeyCode::Backspace => {
                self.key_input.pop();
            }
            KeyCode::Char(character) if !character.is_control() => {
                self.key_input.push(character);
            }
            _ => {}
        }
        false
    }

    fn handle_value_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.value_input = Zeroizing::new(String::new());
                self.editing_key = None;
                self.message = None;
            }
            KeyCode::Enter => {
                let Some(name) = self.editing_key.clone() else {
                    self.mode = Mode::Normal;
                    return false;
                };
                let expires_at = self.vault.get(&name).and_then(|entry| entry.expires_at);
                let value = self.value_input.as_str().to_owned();
                match self.vault.set(&name, SecretValue::new(value), expires_at) {
                    Ok(()) => {
                        self.dirty = true;
                        self.message(false, format!("Updated {name}. Press s to save."));
                        self.mode = Mode::Normal;
                        self.value_input = Zeroizing::new(String::new());
                        self.editing_key = None;
                    }
                    Err(error) => self.message(true, error.to_string()),
                }
            }
            KeyCode::Backspace => {
                self.value_input.pop();
            }
            KeyCode::Char(character) if !character.is_control() => {
                self.value_input.push(character);
            }
            _ => {}
        }
        false
    }
}

fn run_terminal(app: &mut App, path: &Path) -> Result<()> {
    enable_raw_mode().map_err(|err| CliError::Terminal(err.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|err| CliError::Terminal(err.to_string()))?;
    let guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|err| CliError::Terminal(err.to_string()))?;
    let result = loop {
        if let Err(error) = terminal.draw(|frame| draw(frame, app, path)) {
            break Err(CliError::Terminal(error.to_string()));
        }
        match event::read() {
            Ok(Event::Key(key)) => {
                if app.handle_key(key) {
                    break Ok(());
                }
            }
            Ok(_) => {}
            Err(error) => break Err(CliError::Terminal(error.to_string())),
        }
    };
    drop(terminal);
    drop(guard);
    result
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn draw(frame: &mut Frame, app: &mut App, path: &Path) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .split(area);

    let binding = app
        .vault
        .binding()
        .map(|binding| format!("  team {} / {}", binding.team_id, binding.environment))
        .unwrap_or_default();
    let title = Line::from(vec![
        Span::styled(
            " VELT ",
            Style::default()
                .fg(Color::Black)
                .bg(AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(path.display().to_string(), Style::default().fg(Color::Gray)),
        Span::styled(
            format!(
                "  rev {}{}{}",
                app.vault.revision(),
                binding,
                if app.dirty { "  [unsaved]" } else { "" }
            ),
            Style::default().fg(if app.dirty { AMBER } else { Color::DarkGray }),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let now = util::now_unix();
    let names = app.names();
    let rows: Vec<Row> = names
        .iter()
        .map(|name| {
            let entry = app.vault.get(name);
            let (value, status) = match entry {
                Some(entry) => {
                    let value = if app.reveal {
                        entry.value.expose().to_owned()
                    } else {
                        "••••••••".to_owned()
                    };
                    let status = classify(entry.value.expose(), entry.expires_at, now);
                    (value, status)
                }
                None => ("?".to_owned(), SecretStatus::Empty),
            };
            let (status_text, status_color) = status_label(status);
            Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(truncate(&value, 46)),
                Cell::from(status_text).style(Style::default().fg(status_color)),
                Cell::from(
                    entry
                        .and_then(|entry| entry.expires_at)
                        .map(util::format_timestamp)
                        .unwrap_or_else(|| "never".to_owned()),
                ),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Min(20),
            Constraint::Length(14),
            Constraint::Length(22),
        ],
    )
    .header(
        Row::new(vec!["KEY", "VALUE", "STATUS", "EXPIRES"])
            .style(Style::default().fg(AMBER).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" Secrets "))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = TableState::default().with_selected(if names.is_empty() {
        None
    } else {
        Some(app.selected)
    });
    frame.render_stateful_widget(table, chunks[1], &mut state);

    let (message, color) = match &app.message {
        Some((true, text)) => (text.clone(), Color::Red),
        Some((false, text)) => (text.clone(), Color::Green),
        None => (
            if app.dirty {
                "Unsaved changes: s to save, q to quit".to_owned()
            } else {
                "[a] new  [e] edit  [d] delete  [r] reveal  [s] save  [q] quit  [?] help".to_owned()
            },
            Color::DarkGray,
        ),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            message,
            Style::default().fg(color),
        )))
        .block(Block::default().borders(Borders::TOP)),
        chunks[2],
    );

    match app.mode {
        Mode::Normal => {}
        Mode::KeyInput => draw_input(
            frame,
            "New key",
            &app.key_input,
            "Enter: continue  Esc: cancel",
        ),
        Mode::ValueInput => draw_input(
            frame,
            app.editing_key.as_deref().unwrap_or("Value"),
            app.value_input.as_str(),
            "Enter: apply  Esc: cancel (value is visible while editing)",
        ),
        Mode::ConfirmDelete => draw_prompt(
            frame,
            &format!(
                "Delete {}? This cannot be undone until you save.",
                app.selected_name().unwrap_or_default()
            ),
            "y: delete  n/Esc: cancel",
        ),
        Mode::ConfirmQuit => draw_prompt(
            frame,
            "You have unsaved changes.",
            "y: save & quit  n: discard & quit  Esc: cancel",
        ),
        Mode::Help => draw_help(frame),
    }
}

fn draw_input(frame: &mut Frame, title: &str, value: &str, hint: &str) {
    let area = centered_rect(70, 20, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .border_style(Style::default().fg(AMBER));
    let lines = vec![
        Line::from(vec![
            Span::styled(value, Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(AMBER)),
        ]),
        Line::from(""),
        Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_prompt(frame: &mut Frame, title: &str, hint: &str) {
    let area = centered_rect(60, 18, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .border_style(Style::default().fg(Color::Red));
    let lines = vec![
        Line::from(title),
        Line::from(""),
        Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_help(frame: &mut Frame) {
    let area = centered_rect(76, 60, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Velt editor ")
        .border_style(Style::default().fg(AMBER));
    let text = vec![
        Line::from(Span::styled("Navigation", Style::default().fg(AMBER))),
        Line::from("↑/k, ↓/j, g, G    move selection"),
        Line::from(""),
        Line::from(Span::styled("Editing", Style::default().fg(AMBER))),
        Line::from("a / n             new secret"),
        Line::from("e / Enter         edit selected value"),
        Line::from("d                 delete selected secret"),
        Line::from("r                 reveal / mask values"),
        Line::from("s                 save the vault"),
        Line::from(""),
        Line::from(Span::styled("Exit", Style::default().fg(AMBER))),
        Line::from("q / Esc           quit (confirms if dirty)"),
        Line::from("Ctrl-C            quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Values are masked until revealed. The edit popup shows the value being typed.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn status_label(status: SecretStatus) -> (&'static str, Color) {
    match status {
        SecretStatus::Valid => ("valid", Color::Green),
        SecretStatus::Expiring => ("expiring", Color::Yellow),
        SecretStatus::Expired => ("expired", Color::Red),
        SecretStatus::Placeholder => ("placeholder", Color::Red),
        SecretStatus::Empty => ("empty", Color::Red),
    }
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let mut truncated: String = value.chars().take(limit.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use tempfile::TempDir;

    fn key_event(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn test_app() -> (TempDir, App, [u8; 32]) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".velt.vault");
        let key = MasterKey::generate().unwrap();
        let key_bytes = *key.expose();
        let mut vault = Vault::new(&path, None).unwrap();
        vault
            .set("DATABASE_URL", "postgres://localhost/app", None)
            .unwrap();
        vault.set("API_TOKEN", "super-secret-token", None).unwrap();
        vault.save(&key).unwrap();
        (directory, App::new(vault, key, None), key_bytes)
    }

    fn render(app: &mut App) -> String {
        let backend = TestBackend::new(110, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        let path = Path::new("/tmp/.velt.vault");
        terminal
            .draw(|frame| super::draw(frame, app, path))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn renders_keys_without_values() {
        let (_directory, mut app, _key) = test_app();
        let screen = render(&mut app);
        assert!(screen.contains("DATABASE_URL"));
        assert!(screen.contains("valid"));
        assert!(!screen.contains("super-secret-token"));
        app.reveal = true;
        let screen = render(&mut app);
        assert!(screen.contains("super-secret-token"));
    }

    #[test]
    fn add_save_and_reload() {
        let (directory, mut app, key_bytes) = test_app();
        app.handle_key(key_event(KeyCode::Char('a')));
        for character in "NEW_KEY".chars() {
            app.handle_key(key_event(KeyCode::Char(character)));
        }
        app.handle_key(key_event(KeyCode::Enter));
        for character in "new-secret-value".chars() {
            app.handle_key(key_event(KeyCode::Char(character)));
        }
        app.handle_key(key_event(KeyCode::Enter));
        assert!(app.dirty);
        app.handle_key(key_event(KeyCode::Char('s')));
        assert!(!app.dirty);

        let key = MasterKey::from_slice(&key_bytes).unwrap();
        let reloaded = Vault::load(directory.path().join(".velt.vault"), &key).unwrap();
        assert_eq!(
            reloaded.get("NEW_KEY").unwrap().value.expose(),
            "new-secret-value"
        );
    }

    #[test]
    fn delete_requires_confirmation() {
        let (_directory, mut app, _key) = test_app();
        app.selected = 0;
        let first = app.names()[0].clone();
        app.handle_key(key_event(KeyCode::Char('d')));
        app.handle_key(key_event(KeyCode::Char('n')));
        assert!(app.vault.get(&first).is_some());
        app.handle_key(key_event(KeyCode::Char('d')));
        app.handle_key(key_event(KeyCode::Char('y')));
        assert!(app.vault.get(&first).is_none());
        assert!(app.dirty);
    }

    #[test]
    fn quit_with_dirty_prompts() {
        let (_directory, mut app, _key) = test_app();
        app.dirty = true;
        assert!(!app.handle_key(key_event(KeyCode::Char('q'))));
        assert_eq!(app.mode, Mode::ConfirmQuit);
        assert!(app.handle_key(key_event(KeyCode::Char('n'))));
    }
}
