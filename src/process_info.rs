//! Cross-platform process identity and process-tree lookup adapter.

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessIdentityEvidence {
    pub pid: u32,
    pub start_time: u64,
}

pub trait ProcessInfoProvider {
    fn identity_for_pid(&self, pid: u32) -> Option<ProcessIdentityEvidence>;
    fn process_tree_for_pid(&self, root_pid: u32) -> Option<Vec<ProcessIdentityEvidence>>;
}

#[derive(Debug, Clone, Default)]
pub struct SysinfoProcessInfoProvider;

impl SysinfoProcessInfoProvider {
    fn refreshed_system_for_pid(pid: u32) -> System {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
            ProcessRefreshKind::nothing().without_tasks(),
        );
        system
    }

    fn refreshed_system_for_tree() -> System {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().without_tasks(),
        );
        system
    }
}

impl ProcessInfoProvider for SysinfoProcessInfoProvider {
    fn identity_for_pid(&self, pid: u32) -> Option<ProcessIdentityEvidence> {
        let system = Self::refreshed_system_for_pid(pid);
        process_identity(&system, Pid::from_u32(pid))
    }

    fn process_tree_for_pid(&self, root_pid: u32) -> Option<Vec<ProcessIdentityEvidence>> {
        let system = Self::refreshed_system_for_tree();
        let root = Pid::from_u32(root_pid);
        process_identity(&system, root)?;

        let mut identities = Vec::new();
        for pid in system.processes().keys().copied() {
            if is_process_in_tree(&system, root, pid)
                && let Some(identity) = process_identity(&system, pid)
            {
                identities.push(identity);
            }
        }
        identities.sort_unstable();
        identities.dedup();
        Some(identities)
    }
}

fn process_identity(system: &System, pid: Pid) -> Option<ProcessIdentityEvidence> {
    let process = system.process(pid)?;
    Some(ProcessIdentityEvidence {
        pid: pid.as_u32(),
        start_time: process.start_time(),
    })
}

fn is_process_in_tree(system: &System, root: Pid, pid: Pid) -> bool {
    let mut current = Some(pid);
    while let Some(current_pid) = current {
        if current_pid == root {
            return true;
        }
        current = system
            .process(current_pid)
            .and_then(|process| process.parent());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysinfo_provider_returns_current_process_identity() {
        let provider = SysinfoProcessInfoProvider;
        let pid = std::process::id();
        let identity = provider.identity_for_pid(pid).unwrap();
        assert_eq!(identity.pid, pid);
        assert!(identity.start_time > 0);
    }

    #[test]
    fn sysinfo_provider_tree_contains_root_process() {
        let provider = SysinfoProcessInfoProvider;
        let pid = std::process::id();
        let tree = provider.process_tree_for_pid(pid).unwrap();
        assert!(tree.iter().any(|identity| identity.pid == pid));
    }
}
