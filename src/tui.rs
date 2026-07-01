//! Minimal ratatui-based pending request UI.

use std::ffi::OsString;
use std::process::Command;
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
use crate::state::PendingRequest;
use crate::{Error, Result};

pub fn run(name: String) -> Result<i32> {
    let runtime = RuntimePaths::discover()?;
    match send(&runtime, &name, &Request::Pending { name: name.clone() })? {
        Response::Pending { .. } => {}
        Response::Error { message } => return Err(Error::msg(message)),
        other => {
            return Err(Error::msg(format!(
                "unexpected session response: {other:?}"
            )));
        }
    }
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
) -> Result<i32>
where
    B::Error: std::fmt::Display,
{
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
        terminal
            .draw(|frame| draw_pending(frame, &pending, selected, &message))
            .map_err(|error| Error::msg(error.to_string()))?;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
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
                        message =
                            resolve_pending_action(runtime, name, p.id(), PendingAction::Allow)?;
                    }
                }
                KeyCode::Char('n') => {
                    if let Some(p) = pending.get(selected) {
                        message = resolve_pending_action(
                            runtime,
                            name,
                            p.id(),
                            PendingAction::DoNothing,
                        )?;
                    }
                }
                KeyCode::Char('d') => {
                    if let Some(p) = pending.get(selected) {
                        message =
                            resolve_pending_action(runtime, name, p.id(), PendingAction::Deny)?;
                    }
                }
                KeyCode::Char('e') => {
                    if let Some(p) = pending.get(selected) {
                        message = match p.metadata_shell_hint() {
                            Some(command) => edit_pending_command(name, p.id(), &command)?,
                            None => "edit is only available for metadata requests".to_string(),
                        };
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    Allow,
    DoNothing,
    Deny,
}

pub fn resolve_pending_action(
    runtime: &RuntimePaths,
    name: &str,
    id: u64,
    action: PendingAction,
) -> Result<String> {
    let request = match action {
        PendingAction::Allow => Request::Allow {
            name: name.to_string(),
            id,
            do_nothing: false,
        },
        PendingAction::DoNothing => Request::Allow {
            name: name.to_string(),
            id,
            do_nothing: true,
        },
        PendingAction::Deny => Request::Deny {
            name: name.to_string(),
            id,
        },
    };
    Ok(response_message(send(runtime, name, &request)?))
}

pub fn draw_pending(
    frame: &mut ratatui::Frame<'_>,
    pending: &[PendingRequest],
    selected: usize,
    message: &str,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    let first = pending
        .get(selected)
        .map(format_selected_pending)
        .unwrap_or_else(|| "no pending requests".to_string());
    frame.render_widget(
        Paragraph::new(first).block(Block::default().title("Operation").borders(Borders::ALL)),
        chunks[0],
    );
    let items: Vec<ListItem> = pending
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let line = Line::from(format_pending_row(p));
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
    let controls = match pending.get(selected) {
        Some(PendingRequest::Metadata(_)) => "a=allow d=deny n=do-nothing e=edit q=quit",
        Some(PendingRequest::ReadWrite(_)) => "a=allow d=deny n=do-nothing q=quit",
        None => "q=quit",
    };
    frame.render_widget(
        Paragraph::new(format!("{controls} {message}"))
            .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

fn format_pending_row(pending: &PendingRequest) -> String {
    match pending {
        PendingRequest::Metadata(request) => format!("id={} {}", request.id, request.description),
        PendingRequest::ReadWrite(request) => format!(
            "id={} {} path={} {} pid={} uid={} gid={}",
            request.id,
            request.kind,
            request.path,
            request.description,
            request.pid,
            request.uid,
            request.gid
        ),
    }
}

fn format_selected_pending(pending: &PendingRequest) -> String {
    match pending {
        PendingRequest::Metadata(request) => format!(
            "id={}\npath={}\n{}",
            request.id,
            request.operation.path(),
            request.description
        ),
        PendingRequest::ReadWrite(request) => format!(
            "id={}\nkind={}\npath={}\npid={} uid={} gid={}\n{}",
            request.id,
            request.kind,
            request.path,
            request.pid,
            request.uid,
            request.gid,
            request.description
        ),
    }
}

pub fn edit_pending_command(name: &str, id: u64, current_command: &str) -> Result<String> {
    let edited = std::env::var("SANDBOXFS_EDIT_COMMAND")
        .ok()
        .or_else(|| edit_with_external_editor(current_command).ok())
        .ok_or_else(|| Error::msg("no edit command was provided"))?;
    edit_pending_command_with_options(name, id, &edited, None, None)
}

pub fn edit_pending_command_with_options(
    name: &str,
    id: u64,
    edited: &str,
    sandboxfs_bin: Option<OsString>,
    runtime: Option<&RuntimePaths>,
) -> Result<String> {
    let mut argv =
        shlex::split(edited).ok_or_else(|| Error::msg("could not parse edit command"))?;
    if argv.is_empty() {
        return Err(Error::msg("edit command is empty"));
    }
    let command = argv.remove(0);
    match command.as_str() {
        "chmod" | "chown" | "chattr" => {}
        _ => {
            return Err(Error::msg(
                "edit command must start with chmod, chown, or chattr",
            ));
        }
    }

    let mut command_status = sandboxfs_command(sandboxfs_bin.clone());
    apply_runtime_env(&mut command_status, runtime);
    let status = command_status
        .arg(name)
        .arg(&command)
        .args(&argv)
        .status()?;
    if !status.success() {
        return Ok(format!("edited command failed with {status}"));
    }
    let mut release_command = sandboxfs_command(sandboxfs_bin);
    apply_runtime_env(&mut release_command, runtime);
    let status = release_command
        .arg(name)
        .args(["allow", "--do-nothing", &id.to_string()])
        .status()?;
    if status.success() {
        Ok("edited command applied".to_string())
    } else {
        Ok(format!(
            "edited command applied, but original request was not released: {status}"
        ))
    }
}

fn sandboxfs_command(explicit_bin: Option<OsString>) -> Command {
    if let Some(bin) = explicit_bin.or_else(|| std::env::var_os("SANDBOXFS_BIN")) {
        return Command::new(bin);
    }
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("sandboxfs");
        if sibling.exists() {
            return Command::new(sibling);
        }
    }
    Command::new("sandboxfs")
}

fn apply_runtime_env(command: &mut Command, runtime: Option<&RuntimePaths>) {
    if let Some(runtime) = runtime {
        command
            .env(crate::runtime::ENV_RUNTIME_DIR, &runtime.runtime_dir)
            .env(crate::runtime::ENV_LOG_DIR, &runtime.log_dir)
            .env_remove(crate::runtime::ENV_SOCKET);
    }
}

fn edit_with_external_editor(current_command: &str) -> Result<String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| Error::msg("set SANDBOXFS_EDIT_COMMAND or EDITOR to edit commands"))?;
    let path = RuntimePaths::discover()?
        .runtime_dir
        .join("tmp")
        .join(format!(
            "edit-{}-{}.txt",
            std::process::id(),
            monotonic_id()
        ));
    std::fs::write(&path, format!("{current_command}\n"))?;
    let status = Command::new(editor).arg(&path).status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&path);
        return Err(Error::msg(format!("editor exited with {status}")));
    }
    let edited = std::fs::read_to_string(&path)?;
    let _ = std::fs::remove_file(&path);
    Ok(edited.trim().to_string())
}

fn monotonic_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
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
