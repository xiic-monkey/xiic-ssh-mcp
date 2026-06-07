use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;

use crate::models::{OperationContext, RuleAction, RuleDecision, RuleType, WhitelistRule};
use crate::storage::InstanceStore;

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandAnalysis {
    Segments(Vec<String>),
    NeedsReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

#[derive(Clone)]
pub struct WhitelistChecker {
    store: InstanceStore,
    session_approvals: HashMap<String, Instant>,
}

impl WhitelistChecker {
    pub fn new(store: InstanceStore) -> Self {
        Self {
            store,
            session_approvals: HashMap::new(),
        }
    }

    pub fn check(&self, ctx: &OperationContext) -> Result<RuleDecision> {
        let rules = self.store.list_whitelist_rules()?;
        Ok(Self::evaluate(&rules, ctx, &self.session_approvals))
    }

    fn evaluate(
        rules: &[WhitelistRule],
        ctx: &OperationContext,
        approvals: &HashMap<String, Instant>,
    ) -> RuleDecision {
        let command_analysis = ctx.command.as_deref().map(analyze_command);

        // deny rules have highest priority
        if let Some((value, rule)) = rules
            .iter()
            .filter(|r| r.enabled && r.action == RuleAction::Deny)
            .find_map(|rule| matching_deny_value(ctx, command_analysis.as_ref(), rule))
        {
            return RuleDecision::Deny(format!(
                "denied by rule #{}: {} '{}' matches deny pattern '{}'",
                rule.id,
                rule.rule_type.as_str(),
                value,
                rule.pattern,
            ));
        }

        // Collect which dimensions have allow rules
        let mut covered_dims: HashMap<&str, i64> = HashMap::new();
        for rule in rules
            .iter()
            .filter(|r| r.enabled && r.action == RuleAction::Allow)
        {
            match rule.rule_type {
                RuleType::Command | RuleType::Path => {}
                _ => {
                    if let Some(value) = matching_rule_value(ctx, rule)
                        && glob_match(&rule.pattern, value)
                    {
                        covered_dims
                            .entry(rule.rule_type.as_str())
                            .or_insert(rule.id);
                    }
                }
            }
        }

        if command_allow_covered(command_analysis.as_ref(), rules) {
            covered_dims.entry("command").or_insert(0);
        }
        if path_allow_covered(ctx, rules) {
            covered_dims.entry("path").or_insert(0);
        }

        // All present dimensions must be covered by allow rules
        let dims_missing: Vec<&str> = Self::present_dimensions(ctx)
            .into_iter()
            .filter(|dim| !covered_dims.contains_key(*dim))
            .collect();

        if dims_missing.is_empty() {
            return RuleDecision::Allow;
        }

        // Check session approval cache
        let approval_key = approval_key(ctx);
        if approvals.contains_key(&approval_key) {
            return RuleDecision::Allow;
        }

        RuleDecision::NeedsApproval
    }

    fn present_dimensions(ctx: &OperationContext) -> Vec<&str> {
        let mut dims = vec!["tool"];
        if ctx.command.is_some() {
            dims.push("command");
        }
        if ctx.remote_path.is_some() || ctx.local_path.is_some() {
            dims.push("path");
        }
        if ctx.instance_id.is_some() {
            dims.push("instance");
        }
        dims
    }

    pub fn cache_approval(&mut self, ctx: &OperationContext) {
        let key = approval_key(ctx);
        self.session_approvals.insert(key, Instant::now());
    }
}

fn rule_values<'a>(ctx: &'a OperationContext, rule_type: &RuleType) -> Vec<&'a str> {
    match rule_type {
        RuleType::Tool => vec![ctx.tool_name.as_str()],
        RuleType::Command => ctx.command.as_deref().into_iter().collect(),
        RuleType::Path => path_values(ctx),
        RuleType::Instance => ctx.instance_id.as_deref().into_iter().collect(),
    }
}

fn matching_rule_value<'a>(ctx: &'a OperationContext, rule: &'a WhitelistRule) -> Option<&'a str> {
    rule_values(ctx, &rule.rule_type)
        .into_iter()
        .find(|value| glob_match(&rule.pattern, value))
}

fn path_values(ctx: &OperationContext) -> Vec<&str> {
    let mut values = Vec::new();
    if let Some(remote_path) = ctx.remote_path.as_deref() {
        values.push(remote_path);
    }
    if let Some(local_path) = ctx.local_path.as_deref() {
        values.push(local_path);
    }
    values
}

fn matching_deny_value<'a>(
    ctx: &'a OperationContext,
    command_analysis: Option<&'a CommandAnalysis>,
    rule: &'a WhitelistRule,
) -> Option<(&'a str, &'a WhitelistRule)> {
    if rule.rule_type != RuleType::Command {
        return matching_rule_value(ctx, rule).map(|value| (value, rule));
    }

    let command = ctx.command.as_deref()?;
    if glob_match(&rule.pattern, command) {
        return Some((command, rule));
    }

    let Some(CommandAnalysis::Segments(segments)) = command_analysis else {
        return None;
    };

    segments
        .iter()
        .find(|segment| glob_match(&rule.pattern, segment))
        .map(|segment| (segment.as_str(), rule))
}

fn command_allow_covered(analysis: Option<&CommandAnalysis>, rules: &[WhitelistRule]) -> bool {
    let Some(CommandAnalysis::Segments(segments)) = analysis else {
        return false;
    };

    !segments.is_empty()
        && segments.iter().all(|segment| {
            rules.iter().any(|rule| {
                rule.enabled
                    && rule.action == RuleAction::Allow
                    && rule.rule_type == RuleType::Command
                    && glob_match(&rule.pattern, segment)
            })
        })
}

fn path_allow_covered(ctx: &OperationContext, rules: &[WhitelistRule]) -> bool {
    let values = path_values(ctx);
    !values.is_empty()
        && values.iter().all(|value| {
            rules.iter().any(|rule| {
                rule.enabled
                    && rule.action == RuleAction::Allow
                    && rule.rule_type == RuleType::Path
                    && glob_match(&rule.pattern, value)
            })
        })
}

fn analyze_command(command: &str) -> CommandAnalysis {
    let command = command.trim();
    if command.is_empty() {
        return CommandAnalysis::NeedsReview;
    }

    let bytes = command.as_bytes();
    let mut segments = Vec::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut segment_start = 0;
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];

        if escaped {
            escaped = false;
            index += 1;
            continue;
        }

        match quote {
            QuoteState::Single => {
                if byte == b'\'' {
                    quote = QuoteState::None;
                }
                index += 1;
            }
            QuoteState::Double => match byte {
                b'\\' => {
                    escaped = true;
                    index += 1;
                }
                b'"' => {
                    quote = QuoteState::None;
                    index += 1;
                }
                b'`' => return CommandAnalysis::NeedsReview,
                b'$' if bytes.get(index + 1) == Some(&b'(') => {
                    return CommandAnalysis::NeedsReview;
                }
                _ => index += 1,
            },
            QuoteState::None => match byte {
                b'\\' => {
                    escaped = true;
                    index += 1;
                }
                b'\'' => {
                    quote = QuoteState::Single;
                    index += 1;
                }
                b'"' => {
                    quote = QuoteState::Double;
                    index += 1;
                }
                b'`' => return CommandAnalysis::NeedsReview,
                b'$' if bytes.get(index + 1) == Some(&b'(') => {
                    return CommandAnalysis::NeedsReview;
                }
                b'(' | b')' | b'{' | b'}' | b'<' | b'>' => {
                    return CommandAnalysis::NeedsReview;
                }
                b';' | b'\n' => {
                    if !push_segment(command, segment_start, index, &mut segments) {
                        return CommandAnalysis::NeedsReview;
                    }
                    index += 1;
                    segment_start = index;
                }
                b'&' | b'|' => {
                    if !push_segment(command, segment_start, index, &mut segments) {
                        return CommandAnalysis::NeedsReview;
                    }
                    let operator_len = if bytes.get(index + 1) == Some(&byte) {
                        2
                    } else {
                        1
                    };
                    index += operator_len;
                    segment_start = index;
                }
                _ => index += 1,
            },
        }
    }

    if escaped || quote != QuoteState::None {
        return CommandAnalysis::NeedsReview;
    }

    if !push_segment(command, segment_start, bytes.len(), &mut segments) {
        return CommandAnalysis::NeedsReview;
    }

    CommandAnalysis::Segments(segments)
}

fn push_segment(command: &str, start: usize, end: usize, segments: &mut Vec<String>) -> bool {
    let segment = command[start..end].trim();
    if segment.is_empty() {
        return false;
    }
    segments.push(segment.to_string());
    true
}

pub fn approval_key(ctx: &OperationContext) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        ctx.tool_name,
        ctx.command.as_deref().unwrap_or(""),
        ctx.remote_path.as_deref().unwrap_or(""),
        ctx.local_path.as_deref().unwrap_or(""),
        ctx.instance_id.as_deref().unwrap_or(""),
    )
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let value_bytes = value.as_bytes();
    match_impl(pattern_bytes, value_bytes, 0, 0)
}

fn match_impl(pat: &[u8], val: &[u8], pi: usize, vi: usize) -> bool {
    if pi == pat.len() {
        return vi == val.len();
    }

    match pat[pi] {
        b'*' => {
            // * matches zero or more characters
            if match_impl(pat, val, pi + 1, vi) {
                return true;
            }
            for offset in 0..=(val.len() - vi) {
                if match_impl(pat, val, pi + 1, vi + offset) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            // ? matches exactly one character
            if vi < val.len() {
                match_impl(pat, val, pi + 1, vi + 1)
            } else {
                false
            }
        }
        c => {
            if vi < val.len() && val[vi] == c {
                match_impl(pat, val, pi + 1, vi + 1)
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RuleAction;

    fn rule(id: i64, rule_type: RuleType, pattern: &str, action: RuleAction) -> WhitelistRule {
        WhitelistRule {
            id,
            rule_type,
            pattern: pattern.into(),
            action,
            enabled: true,
            created_at: String::new(),
        }
    }

    fn execute_ctx(command: &str) -> OperationContext {
        OperationContext {
            tool_name: "execute_command".into(),
            command: Some(command.into()),
            remote_path: None,
            local_path: None,
            instance_id: Some("dev-server".into()),
        }
    }

    fn base_rules(command_rules: Vec<WhitelistRule>) -> Vec<WhitelistRule> {
        let mut rules = vec![
            rule(1, RuleType::Tool, "execute_command", RuleAction::Allow),
            rule(2, RuleType::Instance, "*", RuleAction::Allow),
        ];
        rules.extend(command_rules);
        rules
    }

    fn transfer_ctx(tool_name: &str, remote_path: &str, local_path: &str) -> OperationContext {
        OperationContext {
            tool_name: tool_name.into(),
            command: None,
            remote_path: Some(remote_path.into()),
            local_path: Some(local_path.into()),
            instance_id: Some("dev-server".into()),
        }
    }

    fn transfer_rules(tool_name: &str, path_rules: Vec<WhitelistRule>) -> Vec<WhitelistRule> {
        let mut rules = vec![
            rule(1, RuleType::Tool, tool_name, RuleAction::Allow),
            rule(2, RuleType::Instance, "*", RuleAction::Allow),
        ];
        rules.extend(path_rules);
        rules
    }

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("ls *", "ls -la /tmp"));
        assert!(glob_match("ls -*", "ls -la"));
    }

    #[test]
    fn glob_question_matches_one() {
        assert!(glob_match("ls -?", "ls -l"));
        assert!(!glob_match("ls -?", "ls -la"));
        assert!(glob_match("??", "ab"));
        assert!(!glob_match("??", "a"));
    }

    #[test]
    fn glob_literal_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
        assert!(glob_match("git status", "git status"));
    }

    #[test]
    fn evaluate_allow_all() {
        let rules = vec![
            rule(1, RuleType::Tool, "*", RuleAction::Allow),
            rule(2, RuleType::Command, "*", RuleAction::Allow),
            rule(3, RuleType::Instance, "*", RuleAction::Allow),
        ];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("ls -la".into()),
            remote_path: None,
            local_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn evaluate_deny_wins() {
        let rules = vec![
            rule(1, RuleType::Tool, "*", RuleAction::Allow),
            rule(2, RuleType::Command, "rm *", RuleAction::Deny),
        ];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("rm -rf /".into()),
            remote_path: None,
            local_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::Deny(_)));
    }

    #[test]
    fn evaluate_needs_approval() {
        let rules = vec![rule(1, RuleType::Tool, "list_servers", RuleAction::Allow)];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("ls -la".into()),
            remote_path: None,
            local_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn path_allow_requires_local_path_for_uploads() {
        let rules = transfer_rules(
            "upload_file",
            vec![rule(3, RuleType::Path, "/srv/uploads/*", RuleAction::Allow)],
        );
        let ctx = transfer_ctx("upload_file", "/srv/uploads/config.txt", "/etc/shadow");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn path_allow_requires_local_path_for_downloads() {
        let rules = transfer_rules(
            "download_to_local",
            vec![rule(
                3,
                RuleType::Path,
                "/srv/downloads/*",
                RuleAction::Allow,
            )],
        );
        let ctx = transfer_ctx(
            "download_to_local",
            "/srv/downloads/report.txt",
            "/Users/test/.ssh/authorized_keys",
        );

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn path_allow_covers_transfer_when_remote_and_local_paths_match() {
        let rules = transfer_rules(
            "upload_file",
            vec![
                rule(3, RuleType::Path, "/srv/uploads/*", RuleAction::Allow),
                rule(
                    4,
                    RuleType::Path,
                    "/Users/test/exports/*",
                    RuleAction::Allow,
                ),
            ],
        );
        let ctx = transfer_ctx(
            "upload_file",
            "/srv/uploads/config.txt",
            "/Users/test/exports/config.txt",
        );

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn path_deny_matches_local_path() {
        let rules = transfer_rules(
            "upload_file",
            vec![
                rule(3, RuleType::Path, "/srv/uploads/*", RuleAction::Allow),
                rule(
                    4,
                    RuleType::Path,
                    "/Users/test/exports/*",
                    RuleAction::Allow,
                ),
                rule(5, RuleType::Path, "/etc/*", RuleAction::Deny),
            ],
        );
        let ctx = transfer_ctx("upload_file", "/srv/uploads/config.txt", "/etc/shadow");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Deny(_)));
    }

    #[test]
    fn approval_key_includes_local_path() {
        let first = transfer_ctx(
            "download_to_local",
            "/srv/downloads/report.txt",
            "/tmp/a.txt",
        );
        let second = transfer_ctx(
            "download_to_local",
            "/srv/downloads/report.txt",
            "/tmp/b.txt",
        );

        assert_ne!(approval_key(&first), approval_key(&second));
    }

    #[test]
    fn compound_command_allows_when_every_segment_is_allowed() {
        let rules = base_rules(vec![
            rule(3, RuleType::Command, "cd *", RuleAction::Allow),
            rule(4, RuleType::Command, "ls *", RuleAction::Allow),
        ]);
        let ctx = execute_ctx("cd /app && ls -la");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn compound_command_needs_approval_when_any_segment_is_not_allowed() {
        let rules = base_rules(vec![rule(3, RuleType::Command, "cd *", RuleAction::Allow)]);
        let ctx = execute_ctx("cd xx & rm -rf /");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn compound_command_deny_matches_any_segment() {
        let rules = base_rules(vec![
            rule(3, RuleType::Command, "cd *", RuleAction::Allow),
            rule(4, RuleType::Command, "rm *", RuleAction::Deny),
        ]);
        let ctx = execute_ctx("cd xx & rm -rf /");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Deny(_)));
    }

    #[test]
    fn quoted_connectors_do_not_split_segments() {
        let rules = base_rules(vec![
            rule(3, RuleType::Command, "echo *", RuleAction::Allow),
            rule(4, RuleType::Command, "printf *", RuleAction::Allow),
        ]);
        let ctx = execute_ctx("echo 'a;b' && printf \"x|y\"");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn escaped_connectors_do_not_split_segments() {
        let rules = base_rules(vec![rule(
            3,
            RuleType::Command,
            r"echo a\;b",
            RuleAction::Allow,
        )]);
        let ctx = execute_ctx(r"echo a\;b");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn pipe_requires_each_side_to_be_allowed() {
        let rules = base_rules(vec![
            rule(3, RuleType::Command, "cat *", RuleAction::Allow),
            rule(4, RuleType::Command, "grep *", RuleAction::Allow),
        ]);
        let ctx = execute_ctx("cat /tmp/a | grep foo");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn complex_command_substitution_needs_approval() {
        let rules = base_rules(vec![rule(
            3,
            RuleType::Command,
            "echo *",
            RuleAction::Allow,
        )]);
        let ctx = execute_ctx("echo $(rm -rf /)");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn complex_backticks_need_approval() {
        let rules = base_rules(vec![rule(
            3,
            RuleType::Command,
            "echo *",
            RuleAction::Allow,
        )]);
        let ctx = execute_ctx("echo `whoami`");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn redirection_needs_approval() {
        let rules = base_rules(vec![rule(
            3,
            RuleType::Command,
            "echo *",
            RuleAction::Allow,
        )]);
        let ctx = execute_ctx("echo ok > /tmp/x");

        let result = WhitelistChecker::evaluate(&rules, &ctx, &HashMap::new());

        assert!(matches!(result, RuleDecision::NeedsApproval));
    }

    #[test]
    fn malformed_commands_need_approval() {
        let rules = base_rules(vec![rule(3, RuleType::Command, "ls *", RuleAction::Allow)]);

        let unclosed_quote =
            WhitelistChecker::evaluate(&rules, &execute_ctx("ls 'tmp"), &HashMap::new());
        let empty_segment =
            WhitelistChecker::evaluate(&rules, &execute_ctx("ls &&"), &HashMap::new());

        assert!(matches!(unclosed_quote, RuleDecision::NeedsApproval));
        assert!(matches!(empty_segment, RuleDecision::NeedsApproval));
    }
}
