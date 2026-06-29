//! Minimal ratatui-based pending request UI.

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::ipc::{self, Request, Response};
use crate::runtime::RuntimePaths;
use crate::{Error, Result};

pub fn run(name: String) -> Result<i32> {
    let runtime = RuntimePaths::discover()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    crossterm::terminal::enable_raw_mode()?;
    let result = run_loop(&mut terminal, &runtime, &name);
    crossterm::terminal::disable_raw_mode()?;
    terminal.show_cursor()?;
    result
}

pub fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    runtime: &RuntimePaths,
    name: &str,
) -> Result<i32> {
    let mut selected = 0usize;
    let mut message = String::new();
    loop {
        let pending = match send(
            runtime,
            name,
            &Request::Pending {
                name: name.to_string(),
            },
        )? {
            Response::Pending { items } => items,
            Response::Error { message } => return Err(Error::msg(message)),
            other => {
                return Err(Error::msg(format!(
                    "unexpected session response: {other:?}"
                )));
            }
        };
        if selected >= pending.len() && !pending.is_empty() {
            selected = pending.len() - 1;
        }
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(3),
                    Constraint::Length(3),
                ])
                .split(area);
            let first = pending
                .get(selected)
                .map(|p| p.description.clone())
                .unwrap_or_else(|| "no pending requests".to_string());
            frame.render_widget(
                Paragraph::new(first)
                    .block(Block::default().title("Operation").borders(Borders::ALL)),
                chunks[0],
            );
            let items: Vec<ListItem> = pending
                .iter()
                .enumerate()
                .map(|(idx, p)| {
                    let line = Line::from(format!("{} {}", p.id, p.description));
                    let item = ListItem::new(line);
                    if idx == selected {
                        item.style(Style::default().add_modifier(Modifier::REVERSED))
                    } else {
                        item
                    }
                })
                .collect();
            frame.render_widget(
                List::new(items).block(Block::default().title("Pending").borders(Borders::ALL)),
                chunks[1],
            );
            frame.render_widget(
                Paragraph::new(format!(
                    "a=allow d=deny n=do-nothing e=edit q=quit {message}"
                ))
                .block(Block::default().borders(Borders::ALL)),
                chunks[2],
            );
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(0),
                    KeyCode::Down => {
                        selected = selected
                            .saturating_add(1)
                            .min(pending.len().saturating_sub(1));
                    }
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    KeyCode::Char('a') => {
                        if let Some(p) = pending.get(selected) {
                            message = response_message(send(
                                runtime,
                                name,
                                &Request::Allow {
                                    name: name.to_string(),
                                    id: p.id,
                                    do_nothing: false,
                                },
                            )?);
                        }
                    }
                    KeyCode::Char('n') => {
                        if let Some(p) = pending.get(selected) {
                            message = response_message(send(
                                runtime,
                                name,
                                &Request::Allow {
                                    name: name.to_string(),
                                    id: p.id,
                                    do_nothing: true,
                                },
                            )?);
                        }
                    }
                    KeyCode::Char('d') => {
                        if let Some(p) = pending.get(selected) {
                            message = response_message(send(
                                runtime,
                                name,
                                &Request::Deny {
                                    name: name.to_string(),
                                    id: p.id,
                                },
                            )?);
                        }
                    }
                    KeyCode::Char('e') => {
                        message = "edit-command is available through CLI in this build".to_string();
                    }
                    _ => {}
                }
            }
        }
    }
}

fn send(runtime: &RuntimePaths, name: &str, request: &Request) -> Result<Response> {
    ipc::send(&runtime.socket_path(name), request).map_err(|error| {
        Error::msg(format!(
            "could not contact sandbox session {name}; is `sandboxfs run {name}` running? ({error})"
        ))
    })
}

fn response_message(response: Response) -> String {
    match response {
        Response::Ok => "ok".to_string(),
        Response::Error { message } => message,
        other => format!("{other:?}"),
    }
}
