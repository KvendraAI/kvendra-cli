//! `kvendra audit --watch` live TUI (REQ-KVD-002 AC-TUI-2).
//!
//! - Polling cadence: 250 ms (matches AC).
//! - Filters: `--profile`, `--primitive`, `--since` (parsed `5m`/`1h`/`30s`).
//! - Color coding: success green, error red, warning yellow.
//! - Keybindings: `q` quit, `c` clear screen, ↑/↓ scroll, `h` toggle help.
//! - Clean exit (AC-TUI-3): `Drop` guard restores terminal even on panic.

use crate::audit::reader::{StoredEvent, list_all, open_readonly};
use crate::error::{KvendraError, KvendraResult};
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

/// Parse a `since` string like `5m`, `1h`, `30s` into a duration in ms.
pub fn parse_since(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, unit) = s.split_at(s.len() - 1);
    let n: i64 = num_part.parse().ok()?;
    let mul = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return None,
    };
    Some(n * mul)
}

#[cfg(feature = "tui")]
struct TerminalGuard;

#[cfg(feature = "tui")]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore — we ignore errors here because we are tearing
        // down even on panic (per AC-TUI-3).
        let _ = disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    }
}

#[cfg(feature = "tui")]
pub async fn run_watch(
    home: PathBuf,
    profile: Option<String>,
    primitive_filter: Option<String>,
    since: Option<String>,
) -> KvendraResult<()> {
    let db = home.join("audit.db");
    if !db.exists() {
        println!("(no audit log yet — run `kvendra mcp serve` to generate events)");
        return Ok(());
    }

    enable_raw_mode().map_err(|e| KvendraError::Tui(e.to_string()))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| KvendraError::Tui(e.to_string()))?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| KvendraError::Tui(e.to_string()))?;

    let since_ms = since.as_deref().and_then(parse_since).unwrap_or(0);
    let mut show_help = false;
    let mut scroll_offset: usize = 0;

    let res = tokio::select! {
        out = run_loop(
            &mut terminal,
            db.clone(),
            profile.clone(),
            primitive_filter.clone(),
            since_ms,
            &mut show_help,
            &mut scroll_offset,
        ) => out,
        _ = tokio::signal::ctrl_c() => Ok(()),
    };

    res
}

#[cfg(feature = "tui")]
async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    db: PathBuf,
    profile: Option<String>,
    primitive_filter: Option<String>,
    since_ms: i64,
    show_help: &mut bool,
    scroll_offset: &mut usize,
) -> KvendraResult<()> {
    let conn = open_readonly(&db)?;
    let poll_dur = Duration::from_millis(250);
    loop {
        let now_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000;
        let cutoff = if since_ms > 0 { now_ms - since_ms } else { 0 };
        let events: Vec<StoredEvent> = list_all(&conn)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                if e.ts_unix_ms < cutoff {
                    return false;
                }
                if let Some(p) = &profile
                    && &e.profile_id != p
                {
                    return false;
                }
                if let Some(pn) = &primitive_filter
                    && &e.primitive != pn
                {
                    return false;
                }
                true
            })
            .collect();

        terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(if *show_help { 5 } else { 1 }),
                    ])
                    .split(frame.area());

                let header = Paragraph::new(format!(
                    "kvendra audit --watch  ({} events shown)  poll=250ms",
                    events.len()
                ))
                .style(Style::default().add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Audit Watch"));
                frame.render_widget(header, chunks[0]);

                let visible = events
                    .iter()
                    .rev()
                    .skip(*scroll_offset)
                    .take(chunks[1].height as usize)
                    .map(|ev| {
                        let color = match ev.status.as_str() {
                            "ok" | "success" => Color::Green,
                            "error" => Color::Red,
                            "warning" | "started" => Color::Yellow,
                            _ => Color::White,
                        };
                        // For error rows, surface the v3 `error_code` (and a
                        // short slice of the sanitized message) right next to
                        // the status so a failure is diagnosable in the TUI
                        // without dropping to `audit --json` (ISSUE-KVD-CLI-6C43AA).
                        let err_suffix = if ev.status == "error" {
                            match (&ev.error_code, &ev.error_message) {
                                (Some(code), Some(msg)) => {
                                    let m: String = msg.chars().take(80).collect();
                                    format!(" {code}: {m}")
                                }
                                (Some(code), None) => format!(" {code}"),
                                _ => String::new(),
                            }
                        } else {
                            String::new()
                        };
                        let text = format!(
                            "[{ts}] [{pid}] {prim}.{act} {st}{err} (id={id})",
                            ts = ev.ts_unix_ms,
                            pid = ev.profile_id,
                            prim = ev.primitive,
                            act = ev.action,
                            st = ev.status,
                            err = err_suffix,
                            id = ev.id,
                        );
                        ListItem::new(Line::from(Span::styled(text, Style::default().fg(color))))
                    })
                    .collect::<Vec<_>>();
                let list = List::new(visible)
                    .block(Block::default().borders(Borders::ALL).title("Events"));
                frame.render_widget(list, chunks[1]);

                let footer_text = if *show_help {
                    "q quit  |  c clear screen  |  ↑/↓ scroll  |  h toggle help"
                } else {
                    "h help"
                };
                let footer =
                    Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
                frame.render_widget(footer, chunks[2]);
            })
            .map_err(|e| KvendraError::Tui(e.to_string()))?;

        // Poll for keypresses up to `poll_dur`.
        if event::poll(poll_dur).map_err(|e| KvendraError::Tui(e.to_string()))?
            && let Event::Key(k) = event::read().map_err(|e| KvendraError::Tui(e.to_string()))?
        {
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('c') => {
                    terminal
                        .clear()
                        .map_err(|e| KvendraError::Tui(e.to_string()))?;
                }
                KeyCode::Char('h') => *show_help = !*show_help,
                KeyCode::Up if *scroll_offset > 0 => *scroll_offset -= 1,
                KeyCode::Down => *scroll_offset += 1,
                _ => {}
            }
        }
    }
}

#[cfg(not(feature = "tui"))]
pub async fn run_watch(
    _home: PathBuf,
    _profile: Option<String>,
    _primitive_filter: Option<String>,
    _since: Option<String>,
) -> KvendraResult<()> {
    println!("audit --watch requires the `tui` feature (default-enabled).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_seconds() {
        assert_eq!(parse_since("30s"), Some(30_000));
    }

    #[test]
    fn parse_since_minutes() {
        assert_eq!(parse_since("5m"), Some(300_000));
    }

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since("2h"), Some(7_200_000));
    }

    #[test]
    fn parse_since_invalid() {
        assert!(parse_since("abc").is_none());
        assert!(parse_since("").is_none());
        assert!(parse_since("5x").is_none());
    }
}
