use super::types::{LLMAnalysis, ServiceIdentification, VulnerabilityAssessment, RiskLevel};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use reqwest::Client;

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";

pub struct ClaudeClient {
    api_key: String,
    client: Client,
}

impl ClaudeClient {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
        }
    }

    pub async fn analyze_banner(&self, banner: &str, port: u16) -> Result<LLMAnalysis> {
        let prompt = format!(
            r#"You are a cybersecurity expert analyzing network service banners.

Port: {}
Banner: {}

Analyze this service banner and respond ONLY with JSON (no markdown):
{{
    "service_name": "...",
    "technology": "...",
    "version": "..." or null,
    "risk_level": "critical"|"high"|"medium"|"low"|"info",
    "reasoning": "...",
    "vulnerabilities": ["CVE-XXXX-YYYY", ...],
    "potential_issues": ["...", ...],
    "recommendations": ["...", ...]
}}

Only include real CVEs if certain."#,
            port, banner
        );

        let response_text = self.send_message(&prompt).await?;
        self.parse_analysis(&response_text)
    }

    pub async fn analyze_vulnerabilities(
        &self,
        service: &str,
        version: Option<&str>,
    ) -> Result<VulnerabilityAssessment> {
        let version_str = version.unwrap_or("unknown");

        let prompt = format!(
            r#"You are a cybersecurity expert. Analyze security of {} version {}.

Respond ONLY with JSON (no markdown):
{{
    "risk_level": "critical"|"high"|"medium"|"low"|"info",
    "known_cves": ["CVE-XXXX-YYYY", ...],
    "potential_issues": ["...", ...],
    "remediation_steps": ["...", ...]
}}

Only include confirmed CVEs."#,
            service, version_str
        );

        let response_text = self.send_message(&prompt).await?;
        self.parse_vulnerability_assessment(&response_text)
    }

    pub async fn generate_report(&self, scan_json: &str) -> Result<String> {
        let prompt = format!(
            r#"You are a cybersecurity expert. Analyze these scan results and produce an executive security report.

Scan Results:
{}

Produce a concise report with:
1. Executive Summary
2. Critical Findings (sorted by severity)
3. Risk Assessment
4. Remediation Priorities
5. Recommendations

Be specific and actionable."#,
            scan_json
        );

        self.send_message(&prompt).await
    }

    async fn send_message(&self, prompt: &str) -> Result<String> {
        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 2048,
            messages: vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let response = self
            .client
            .post(CLAUDE_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call Claude API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {}: {}", status, error_text);
        }

        let claude_response: ClaudeResponse = response
            .json()
            .await
            .context("Failed to parse Claude response")?;

        claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .ok_or_else(|| anyhow::anyhow!("No response from Claude"))
    }

    fn parse_analysis(&self, response: &str) -> Result<LLMAnalysis> {
        let json_str = extract_json(response);

        #[derive(Deserialize)]
        struct ParsedResponse {
            service_name: String,
            technology: String,
            version: Option<String>,
            risk_level: String,
            reasoning: String,
            vulnerabilities: Vec<String>,
            potential_issues: Vec<String>,
            recommendations: Vec<String>,
        }

        let parsed: ParsedResponse = serde_json::from_str(&json_str)
            .context("Failed to parse LLM JSON response")?;

        Ok(LLMAnalysis {
            service_identification: Some(ServiceIdentification {
                service_name: parsed.service_name,
                likely_technology: parsed.technology,
                version_guess: parsed.version,
                reasoning: parsed.reasoning,
            }),
            vulnerability_assessment: Some(VulnerabilityAssessment {
                risk_level: parse_risk_level(&parsed.risk_level),
                known_cves: parsed.vulnerabilities,
                potential_issues: parsed.potential_issues,
                remediation_steps: parsed.recommendations.clone(),
            }),
            recommendations: parsed.recommendations,
            confidence: 0.85,
        })
    }

    fn parse_vulnerability_assessment(&self, response: &str) -> Result<VulnerabilityAssessment> {
        let json_str = extract_json(response);

        #[derive(Deserialize)]
        struct ParsedVuln {
            risk_level: String,
            known_cves: Vec<String>,
            potential_issues: Vec<String>,
            remediation_steps: Vec<String>,
        }

        let parsed: ParsedVuln = serde_json::from_str(&json_str)?;

        Ok(VulnerabilityAssessment {
            risk_level: parse_risk_level(&parsed.risk_level),
            known_cves: parsed.known_cves,
            potential_issues: parsed.potential_issues,
            remediation_steps: parsed.remediation_steps,
        })
    }
}

#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: i32,
    messages: Vec<ClaudeMessage>,
}

#[derive(Debug, Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContent {
    text: String,
}

pub fn extract_json(text: &str) -> String {
    if let Some(start) = text.find("```json") {
        let json_start = start + 7;
        if let Some(end_pos) = text[json_start..].find("```") {
            return text[json_start..json_start + end_pos].trim().to_string();
        }
    }
    if let Some(start) = text.find("```") {
        let content_start = start + 3;
        if let Some(end_pos) = text[content_start..].find("```") {
            return text[content_start..content_start + end_pos].trim().to_string();
        }
    }
    text.trim().to_string()
}

pub fn parse_risk_level(level: &str) -> RiskLevel {
    match level.to_lowercase().as_str() {
        "critical" => RiskLevel::Critical,
        "high" => RiskLevel::High,
        "medium" => RiskLevel::Medium,
        "low" => RiskLevel::Low,
        _ => RiskLevel::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_markdown() {
        let input = "Here's the result:\n```json\n{\"test\": true}\n```\nDone!";
        assert_eq!(extract_json(input), "{\"test\": true}");
    }

    #[test]
    fn test_extract_json_raw() {
        let input = "{\"test\": true}";
        assert_eq!(extract_json(input), "{\"test\": true}");
    }

    #[test]
    fn test_parse_risk_level() {
        assert!(matches!(parse_risk_level("critical"), RiskLevel::Critical));
        assert!(matches!(parse_risk_level("HIGH"), RiskLevel::High));
        assert!(matches!(parse_risk_level("unknown"), RiskLevel::Info));
    }
}
