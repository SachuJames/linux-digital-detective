//! Process-tree analysis.
//!
//! Builds process forests from [`ProcessInfo`] records (live snapshots or
//! synthetic evidence) and renders them as text trees.

use std::collections::HashMap;

/// One observed process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
    pub state: String,
    pub rss_kb: Option<u64>,
}

/// A node in the rendered tree.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub info: ProcessInfo,
    pub children: Vec<ProcessNode>,
}

/// Build a forest (roots = processes whose parent is unknown or 0).
pub fn build_forest(processes: &[ProcessInfo]) -> Vec<ProcessNode> {
    let mut by_ppid: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
    let mut by_pid: HashMap<u32, &ProcessInfo> = HashMap::new();
    for p in processes {
        by_ppid.entry(p.ppid).or_default().push(p);
        by_pid.insert(p.pid, p);
    }
    let mut roots: Vec<&ProcessInfo> = processes
        .iter()
        .filter(|p| p.ppid == 0 || !by_pid.contains_key(&p.ppid))
        .collect();
    // Deterministic order.
    roots.sort_by_key(|p| p.pid);
    for v in by_ppid.values_mut() {
        v.sort_by_key(|p| p.pid);
    }
    roots.into_iter().map(|r| build_node(r, &by_ppid)).collect()
}

fn build_node(
    info: &ProcessInfo,
    by_ppid: &HashMap<u32, Vec<&ProcessInfo>>,
) -> ProcessNode {
    let children = by_ppid
        .get(&info.pid)
        .map(|kids| kids.iter().map(|k| build_node(k, by_ppid)).collect())
        .unwrap_or_default();
    ProcessNode {
        info: info.clone(),
        children,
    }
}

/// Render a forest as an indented text tree.
pub fn render_forest(forest: &[ProcessNode]) -> String {
    let mut out = String::new();
    for (i, root) in forest.iter().enumerate() {
        render_node(root, "", i == forest.len() - 1, &mut out);
    }
    out
}

fn render_node(node: &ProcessNode, prefix: &str, last: bool, out: &mut String) {
    let branch = if last { "└── " } else { "├── " };
    let exe = short_exe(&node.info.exe);
    out.push_str(&format!(
        "{prefix}{branch}{exe} (pid {}, uid {})\n",
        node.info.pid, node.info.uid
    ));
    let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, &child_prefix, i == node.children.len() - 1, out);
    }
}

fn short_exe(exe: &str) -> &str {
    if exe.is_empty() {
        return "?";
    }
    exe.rsplit('/').next().unwrap_or(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, exe: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            exe: exe.into(),
            cmdline: String::new(),
            uid: 1000,
            state: "S".into(),
            rss_kb: None,
        }
    }

    #[test]
    fn builds_tree_with_orphans_as_roots() {
        let procs = vec![
            p(100, 1, "/usr/sbin/sshd"),
            p(101, 100, "/bin/bash"),
            p(102, 101, "/usr/bin/python3"),
            p(999, 4242, "/tmp/orphan"), // parent unknown -> root
        ];
        let forest = build_forest(&procs);
        assert_eq!(forest.len(), 2);
        let sshd = forest.iter().find(|n| n.info.pid == 100).unwrap();
        assert_eq!(sshd.children.len(), 1);
        assert_eq!(sshd.children[0].children.len(), 1);
    }

    #[test]
    fn renders_expected_tree_shape() {
        let procs = vec![p(1, 0, "/sbin/init"), p(2, 1, "/bin/bash")];
        let text = render_forest(&build_forest(&procs));
        assert!(text.contains("init (pid 1"));
        assert!(text.contains("└── bash (pid 2"));
    }
}
