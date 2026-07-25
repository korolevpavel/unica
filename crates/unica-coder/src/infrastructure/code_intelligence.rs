use crate::domain::cancellation::{CancellationToken, CANCELLED_PREFIX};
use crate::domain::code_intelligence::{
    CodeIntelligenceProvider, ProviderCapability, ProviderId, ProviderSearchHit,
    ProviderSearchSection, ProviderSectionStatus, SearchRequest,
};
use crate::domain::workspace::WorkspaceContext;
use crate::infrastructure::internal_adapters::{
    ProcessCommand, ProcessRunner, SystemProcessRunner, DEFAULT_PROCESS_TIMEOUT,
    SYSTEM_PROCESS_RUNNER,
};
use serde_json::Map;
use std::path::PathBuf;

const GIT_GREP_CAPABILITIES: &[ProviderCapability] = &[ProviderCapability::Search];

pub(crate) struct GitGrepProvider {
    runner: &'static SystemProcessRunner,
}

impl GitGrepProvider {
    pub(crate) fn new() -> Self {
        Self {
            runner: &SYSTEM_PROCESS_RUNNER,
        }
    }
}

impl CodeIntelligenceProvider for GitGrepProvider {
    fn id(&self) -> ProviderId {
        ProviderId::GitGrep
    }

    fn capabilities(&self) -> &[ProviderCapability] {
        GIT_GREP_CAPABILITIES
    }

    fn search(
        &self,
        request: &SearchRequest,
        context: &WorkspaceContext,
        cancellation: &CancellationToken,
    ) -> ProviderSearchSection {
        let source_root = match request.source_root.strip_prefix(&context.workspace_root) {
            Ok(path) if !path.as_os_str().is_empty() => path,
            Ok(_) => std::path::Path::new("."),
            Err(_) => return unavailable_section("source root is outside workspace root"),
        };
        let args = vec![
            "grep".to_string(),
            "-n".to_string(),
            "-m".to_string(),
            request.limit.to_string(),
            "-F".to_string(),
            "-e".to_string(),
            request.query.clone(),
            "--".to_string(),
            source_root.to_string_lossy().into_owned(),
        ];
        let output = match self.runner.run(&ProcessCommand {
            program: PathBuf::from("git"),
            args,
            cwd: context.workspace_root.clone(),
            timeout: Some(DEFAULT_PROCESS_TIMEOUT),
            cancellation: cancellation.clone(),
        }) {
            Ok(output) => output,
            Err(error) => return unavailable_section(&error),
        };
        if output.cancelled {
            return unavailable_section(&format!("{CANCELLED_PREFIX} git grep cancelled"));
        }
        if output.timed_out {
            return failed_section("git grep timed out");
        }
        if !output.status_success && output.status.trim() != "1" {
            let diagnostic = if output.stderr.trim().is_empty() {
                format!("git grep exited with status {}", output.status)
            } else {
                output.stderr.trim().to_string()
            };
            return failed_section(&diagnostic);
        }

        let hits = output
            .stdout
            .lines()
            .filter_map(parse_git_grep_hit)
            .enumerate()
            .map(|(index, (path, line, snippet))| ProviderSearchHit {
                rank: index + 1,
                provider_score: None,
                path,
                line,
                end_line: None,
                symbol: None,
                kind: None,
                snippet,
                attributes: Map::new(),
            })
            .collect::<Vec<_>>();
        ProviderSearchSection {
            provider: ProviderId::GitGrep,
            status: if hits.is_empty() {
                ProviderSectionStatus::Empty
            } else {
                ProviderSectionStatus::Ok
            },
            hits,
            diagnostics: Vec::new(),
            artifacts: Vec::new(),
        }
    }
}

fn parse_git_grep_hit(line: &str) -> Option<(String, usize, String)> {
    let (path, remainder) = line.split_once(':')?;
    let (line_number, snippet) = remainder.split_once(':')?;
    Some((
        path.to_string(),
        line_number.parse().ok()?,
        snippet.to_string(),
    ))
}

fn unavailable_section(diagnostic: &str) -> ProviderSearchSection {
    provider_section(ProviderSectionStatus::Unavailable, diagnostic)
}

fn failed_section(diagnostic: &str) -> ProviderSearchSection {
    provider_section(ProviderSectionStatus::Failed, diagnostic)
}

fn provider_section(status: ProviderSectionStatus, diagnostic: &str) -> ProviderSearchSection {
    ProviderSearchSection {
        provider: ProviderId::GitGrep,
        status,
        hits: Vec::new(),
        diagnostics: vec![diagnostic.to_string()],
        artifacts: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_grep_line_into_provider_hit_parts() {
        assert_eq!(
            parse_git_grep_hit("CommonModules/Sales/Ext/Module.bsl:42:Procedure Post() Export"),
            Some((
                "CommonModules/Sales/Ext/Module.bsl".to_string(),
                42,
                "Procedure Post() Export".to_string(),
            ))
        );
    }
}
