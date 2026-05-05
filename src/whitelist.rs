use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;

use crate::models::{OperationContext, RuleAction, RuleDecision, RuleType, WhitelistRule};
use crate::storage::InstanceStore;

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
        let apply_rules = |act: RuleAction| {
            rules
                .iter()
                .filter(move |r| r.enabled && r.action == act)
                .filter_map(|r| {
                    let value = match r.rule_type {
                        RuleType::Tool => Some(ctx.tool_name.as_str()),
                        RuleType::Command => ctx.command.as_deref(),
                        RuleType::Path => ctx.remote_path.as_deref(),
                        RuleType::Instance => ctx.instance_id.as_deref(),
                    };

                    value.map(|v| (v, r))
                })
                .filter(|(value, rule)| glob_match(&rule.pattern, value))
        };

        // deny rules have highest priority
        if let Some((value, rule)) = apply_rules(RuleAction::Deny).next() {
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
        for (_, rule) in apply_rules(RuleAction::Allow) {
            covered_dims
                .entry(rule.rule_type.as_str())
                .or_insert(rule.id);
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

        RuleDecision::NeedsElicitation
    }

    fn present_dimensions(ctx: &OperationContext) -> Vec<&str> {
        let mut dims = vec!["tool"];
        if ctx.command.is_some() {
            dims.push("command");
        }
        if ctx.remote_path.is_some() {
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

pub fn approval_key(ctx: &OperationContext) -> String {
    format!(
        "{}|{}|{}|{}",
        ctx.tool_name,
        ctx.command.as_deref().unwrap_or(""),
        ctx.remote_path.as_deref().unwrap_or(""),
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
            WhitelistRule {
                id: 1,
                rule_type: RuleType::Tool,
                pattern: "*".into(),
                action: RuleAction::Allow,
                enabled: true,
                created_at: String::new(),
            },
            WhitelistRule {
                id: 2,
                rule_type: RuleType::Command,
                pattern: "*".into(),
                action: RuleAction::Allow,
                enabled: true,
                created_at: String::new(),
            },
            WhitelistRule {
                id: 3,
                rule_type: RuleType::Instance,
                pattern: "*".into(),
                action: RuleAction::Allow,
                enabled: true,
                created_at: String::new(),
            },
        ];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("ls -la".into()),
            command_description: Some("查看目录".into()),
            remote_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::Allow));
    }

    #[test]
    fn evaluate_deny_wins() {
        let rules = vec![
            WhitelistRule {
                id: 1,
                rule_type: RuleType::Tool,
                pattern: "*".into(),
                action: RuleAction::Allow,
                enabled: true,
                created_at: String::new(),
            },
            WhitelistRule {
                id: 2,
                rule_type: RuleType::Command,
                pattern: "rm *".into(),
                action: RuleAction::Deny,
                enabled: true,
                created_at: String::new(),
            },
        ];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("rm -rf /".into()),
            command_description: Some("危险删除".into()),
            remote_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::Deny(_)));
    }

    #[test]
    fn evaluate_needs_elicitation() {
        let rules = vec![WhitelistRule {
            id: 1,
            rule_type: RuleType::Tool,
            pattern: "list_servers".into(),
            action: RuleAction::Allow,
            enabled: true,
            created_at: String::new(),
        }];

        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("ls -la".into()),
            command_description: Some("查看目录".into()),
            remote_path: None,
            instance_id: Some("dev-server".into()),
        };

        let approvals = HashMap::new();
        let result = WhitelistChecker::evaluate(&rules, &ctx, &approvals);
        assert!(matches!(result, RuleDecision::NeedsElicitation));
    }
}
