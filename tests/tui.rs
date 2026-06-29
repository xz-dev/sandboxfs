mod common;

use assert_cmd::cargo::CommandCargoExt;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sandboxfs::path::SandboxPath;
use sandboxfs::state::{MetadataOperation, PendingMetadataRequest};
use sandboxfs::tui::PendingAction;
use tempfile::TempDir;

use common::RunningSession;

fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
    let area = *buffer.area();
    let mut out = String::new();
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
fn tui_renders_pending_request_and_controls() {
    let pending = vec![PendingMetadataRequest {
        id: 42,
        sandbox: "demo_tui".to_string(),
        operation: MetadataOperation::Chmod {
            path: SandboxPath::new("/data/file").unwrap(),
            mode: 0o444,
        },
        kinds: vec![sandboxfs::state::PendingOperationKind::Mode],
        pid: 123,
        uid: 1000,
        gid: 1000,
        description: "path=/data/file SETATTR mode=0444".to_string(),
    }];
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| sandboxfs::tui::draw_pending(frame, &pending, 0, "ok"))
        .unwrap();
    let rendered = buffer_text(terminal.backend().buffer());
    assert!(rendered.contains("Operation"));
    assert!(rendered.contains("42 path=/data/file SETATTR mode=0444"));
    assert!(rendered.contains("a=allow d=deny n=do-nothing e=edit q=quit ok"));
}

#[test]
fn edit_pending_command_uses_configured_binary_and_releases_original_request() {
    let session = RunningSession::start("demo_tui_edit");
    let sandboxfs_bin = std::process::Command::cargo_bin("sandboxfs").unwrap();
    let sandboxfs_bin = sandboxfs_bin.get_program().to_owned();

    session
        .sandbox_cmd()
        .args(["mount", session.temp.path().to_str().unwrap(), "/data"])
        .assert()
        .success();

    let runtime = sandboxfs::runtime::RuntimePaths::for_tests_with_log_dir(
        session.runtime(),
        session.log_dir(),
        None,
    );
    let message = sandboxfs::tui::edit_pending_command_with_options(
        &session.name,
        9999,
        "chmod 444 /data",
        Some(sandboxfs_bin),
        Some(&runtime),
    )
    .unwrap();
    assert!(message.contains("original request was not released"));

    session
        .sandbox_cmd()
        .arg("metadata")
        .assert()
        .success()
        .stdout(predicate::str::contains("/data"));
}

#[test]
fn pending_actions_report_session_errors() {
    let temp = TempDir::new().unwrap();
    let runtime = sandboxfs::runtime::RuntimePaths::for_tests_with_log_dir(
        temp.path().join("run"),
        temp.path().join("logs"),
        None,
    );
    let error = sandboxfs::tui::resolve_pending_action(
        &runtime,
        "missing_tui_action",
        1,
        PendingAction::Allow,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("sandboxfs run missing_tui_action"));
}

#[test]
fn access_tui_reports_missing_foreground_session() {
    let temp = TempDir::new().unwrap();
    std::process::Command::cargo_bin("sandboxfs-access-tui")
        .unwrap()
        .env("SANDBOXFS_RUNTIME_DIR", temp.path().join("run"))
        .env("SANDBOXFS_LOG_DIR", temp.path().join("logs"))
        .env_remove("SANDBOXFS_SOCKET")
        .arg("missing_tui")
        .assert()
        .failure()
        .stderr(predicate::str::contains("sandboxfs run missing_tui"));
}
