//! Discover subcommand - scan for running AI agents
//!
//! This module provides the `discover` subcommand which scans the system
//! for running AI agent processes.

use agentsight::AgentScanner;
use agentsight::config::CmdlineRule;
use structopt::StructOpt;

/// Discover subcommand for finding AI agents running on the system
#[derive(Debug, StructOpt, Clone)]
pub struct DiscoverCommand {
    /// Show detailed output including executable path
    #[structopt(short, long)]
    pub verbose: bool,

    /// List all known agents without scanning
    #[structopt(long)]
    pub list_known: bool,
}

impl DiscoverCommand {
    pub fn execute(&self) {
        if self.list_known {
            self.list_known_agents();
            return;
        }

        self.scan_agents();
    }

    /// List all known agents that can be detected
    fn list_known_agents(&self) {
        let rules = agentsight::default_cmdline_rules();
        let grouped = group_known_agents(&rules);

        println!("Known AI Agents ({} total):", grouped.len());
        println!("{}", "=".repeat(60));
        println!();

        for (name, patterns) in &grouped {
            println!("  {name}");
            for pattern in patterns {
                println!("    Match: {pattern}");
            }
            println!();
        }
    }

    /// Scan the system for running AI agents
    fn scan_agents(&self) {
        let mut scanner = AgentScanner::from_rules(&agentsight::default_cmdline_rules(), &[]);
        let agents = scanner.scan();

        if agents.is_empty() {
            println!("No AI agents found running on this system.");
            println!();
            println!("Tip: Use --list-known to see all detectable agents.");
            return;
        }

        println!("Discovered AI Agents ({} found):", agents.len());
        println!("{}", "=".repeat(60));
        println!();

        for agent in &agents {
            println!("  {} [PID: {}]", agent.agent_info.name, agent.pid);
            println!("    Category: {}", agent.agent_info.category);

            // Truncate long command lines
            let cmdline_str = agent.cmdline_args.join(" ");
            let cmdline = if cmdline_str.len() > 80 && !self.verbose {
                format!("{}...", &cmdline_str[..77])
            } else {
                cmdline_str
            };
            println!("    Command:  {cmdline}");

            if self.verbose && !agent.exe_path.is_empty() {
                println!("    Executable: {}", agent.exe_path);
            }

            println!();
        }

        println!("Total: {} agent(s) found", agents.len());
    }
}

/// Group allow rules by agent name (first-seen order).
///
/// Each agent maps to the list of its cmdline glob rules, one display string
/// per rule with the positional patterns joined by spaces.
fn group_known_agents(rules: &[CmdlineRule]) -> Vec<(String, Vec<String>)> {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for rule in rules {
        if !rule.allow || rule.patterns.is_empty() {
            continue;
        }
        let name = rule.agent_name.as_deref().unwrap_or("Custom Agent");
        let display = rule.patterns.join(" ");
        match grouped.iter_mut().find(|(n, _)| n == name) {
            Some((_, patterns)) => patterns.push(display),
            None => grouped.push((name.to_string(), vec![display])),
        }
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_rule(name: &str, patterns: &[&str]) -> CmdlineRule {
        CmdlineRule {
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            agent_name: Some(name.to_string()),
            allow: true,
        }
    }

    #[test]
    fn group_known_agents_merges_rules_of_same_agent() {
        let rules = vec![
            allow_rule("Cosh", &["node*", "*/bin/cosh*"]),
            allow_rule("Claude", &["claude*"]),
            allow_rule("Cosh", &["*node*", "*cosh*"]),
        ];
        let grouped = group_known_agents(&rules);
        assert_eq!(grouped.len(), 2);
        // First-seen order is preserved
        assert_eq!(grouped[0].0, "Cosh");
        assert_eq!(
            grouped[0].1,
            vec!["node* */bin/cosh*".to_string(), "*node* *cosh*".to_string()]
        );
        assert_eq!(grouped[1].0, "Claude");
        assert_eq!(grouped[1].1, vec!["claude*".to_string()]);
    }

    #[test]
    fn group_known_agents_skips_deny_and_empty_rules() {
        let rules = vec![
            CmdlineRule {
                patterns: vec!["*spam*".to_string()],
                agent_name: None,
                allow: false,
            },
            CmdlineRule {
                patterns: vec![],
                agent_name: Some("Empty".to_string()),
                allow: true,
            },
            allow_rule("Claude", &["claude*"]),
        ];
        let grouped = group_known_agents(&rules);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].0, "Claude");
    }

    #[test]
    fn group_known_agents_default_rules_not_empty() {
        let grouped = group_known_agents(&agentsight::default_cmdline_rules());
        assert!(!grouped.is_empty());
        // Every entry has a non-empty name and at least one match pattern
        for (name, patterns) in &grouped {
            assert!(!name.is_empty());
            assert!(!patterns.is_empty());
            assert!(patterns.iter().all(|p| !p.is_empty()));
        }
    }
}
