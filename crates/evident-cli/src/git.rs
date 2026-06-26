use std::process::Command;

use evident_audit::evidence::CiInfo;

pub fn git_commit() -> Option<String> {
    run("git", &["rev-parse", "HEAD"])
}

pub fn git_branch() -> Option<String> {
    run("git", &["rev-parse", "--abbrev-ref", "HEAD"])
}

pub fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

pub fn git_remote() -> Option<String> {
    run("git", &["config", "--get", "remote.origin.url"])
}

pub fn detect_ci() -> Option<CiInfo> {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return Some(CiInfo {
            provider: "github_actions".into(),
            run_id: std::env::var("GITHUB_RUN_ID").ok(),
            workflow: std::env::var("GITHUB_WORKFLOW").ok(),
        });
    }
    None
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
