//! `kvendra dashboard` — global TUI overview (REQ-KVD-002 AC-TUI-1).
//!
//! Refresh cadence: 1 s. Layout:
//!   ┌ Header                                  ┐
//!   │ Locked panel  │  Recent audit (10 rows) │
//!   └ Footer keybindings                       ┘

use crate::audit::reader::{list_all, open_readonly};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "tui")]
use {
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    ratatui::Terminal,
    ratatui::backend::CrosstermBackend,
    ratatui::layout::{Constraint, Direction, Layout},
    ratatui::style::{Color, Modifier, Style},
    ratatui::text::{Line, Span},
    ratatui::widgets::{Block, Borders, List, ListItem, Paragraph},
};

#[cfg(feature = "tui")]
struct TerminalGuard;

#[cfg(feature = "tui")]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    }
}

#[cfg(feature = "tui")]
pub async fn run(home: PathBuf) -> KvendraResult<()> {
    enable_raw_mode().map_err(|e| KvendraError::Tui(e.to_string()))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| KvendraError::Tui(e.to_string()))?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| KvendraError::Tui(e.to_string()))?;

    let res = tokio::select! {
        out = render_loop(&mut terminal, home.clone()) => out,
        _ = tokio::signal::ctrl_c() => Ok(()),
    };
    res
}

#[cfg(feature = "tui")]
async fn render_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    home: PathBuf,
) -> KvendraResult<()> {
    let vault = Vault::new(home.clone());
    let db = home.join("audit.db");
    let refresh = Duration::from_secs(1);
    loop {
        let unlocked = vault.is_unlocked();
        let profiles = vault.list_profiles().unwrap_or_default();
        let recent = if db.exists() {
            open_readonly(&db)
                .ok()
                .and_then(|c| list_all(&c).ok())
                .map(|mut events| {
                    events.reverse();
                    events.truncate(10);
                    events
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        terminal
            .draw(|frame| {
                let area = frame.area();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(3),
                    ])
                    .split(area);

                let header_text = format!(
                    "kvendra v{}   vault: {}",
                    env!("CARGO_PKG_VERSION"),
                    if unlocked { "Unlocked" } else { "Locked" }
                );
                let header = Paragraph::new(header_text)
                    .style(Style::default().add_modifier(Modifier::BOLD))
                    .block(Block::default().borders(Borders::ALL).title("Dashboard"));
                frame.render_widget(header, chunks[0]);

                let body = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(chunks[1]);

                let profile_items: Vec<ListItem> = profiles
                    .iter()
                    .map(|p| ListItem::new(Line::from(p.as_str())))
                    .collect();
                let profile_list = List::new(profile_items)
                    .block(Block::default().borders(Borders::ALL).title("Profiles"));
                frame.render_widget(profile_list, body[0]);

                let audit_items: Vec<ListItem> = recent
                    .iter()
                    .map(|e| {
                        let color = match e.status.as_str() {
                            "ok" => Color::Green,
                            "error" => Color::Red,
                            _ => Color::Yellow,
                        };
                        ListItem::new(Line::from(Span::styled(
                            format!(
                                "[{}] {} {}.{} {}",
                                e.ts_unix_ms, e.profile_id, e.primitive, e.action, e.status
                            ),
                            Style::default().fg(color),
                        )))
                    })
                    .collect();
                let audit_list = List::new(audit_items).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Recent audit (10)"),
                );
                frame.render_widget(audit_list, body[1]);

                let footer =
                    Paragraph::new("r refresh now  |  q quit  |  u unlock (locked vaults)")
                        .block(Block::default().borders(Borders::ALL));
                frame.render_widget(footer, chunks[2]);
            })
            .map_err(|e| KvendraError::Tui(e.to_string()))?;

        if event::poll(refresh).map_err(|e| KvendraError::Tui(e.to_string()))?
            && let Event::Key(k) = event::read().map_err(|e| KvendraError::Tui(e.to_string()))?
        {
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('r') => continue,
                _ => {}
            }
        }
    }
}

#[cfg(not(feature = "tui"))]
pub async fn run(_home: PathBuf) -> KvendraResult<()> {
    println!("dashboard requires the `tui` feature (default-enabled).");
    Ok(())
}
