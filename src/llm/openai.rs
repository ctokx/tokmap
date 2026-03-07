use super::types::{LLMAnalysis, ServiceIdentification, VulnerabilityAssessment};
use super::claude::{extract_json, parse_risk_level};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use reqwest::Client;

const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";

pub struct OpenAIClient {
    api_key: String,
    client: Client,
    model: String,
}

impl OpenAIClient {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
            model: "gpt-4o".to_string(),
        }
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }

    pub async fn analyze_banner(&self, banner: &str, port: u16) -> Result<LLMAnalysis> {
        let prompt = format!(
            r#"You are a cybersecurity expert analyzing network service banners.

Port: {}
Banner: {}

Respond ONLY with JSON:
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

        let response_text = self.chat(&prompt).await?;
        self.parse_analysis(&response_text)
    }

    pub async fn analyze_vulnerabilities(
        &self,
        service: &str,
        version: Option<&str>,
    ) -> Result<VulnerabilityAssessment> {
        let version_str = version.unwrap_or("unknown");

        let prompt = format!(
            r#"Analyze security of {} version {}. Respond ONLY with JSON:
{{
    "risk_level": "critical"|"high"|"medium"|"low"|"info",
    "known_cves": ["CVE-XXXX-YYYY", ...],
    "potential_issues": ["...", ...],
    "remediation_steps": ["...", ...]
}}

Only include confirmed CVEs."#,
            service, version_str
        );

        let response_text = self.chat(&prompt).await?;
        self.parse_vulnerability_assessment(&response_text)
    }

    pub async fn generate_report(&self, scan_json: &str) -> Result<String> {
        let prompt = format!(
            "You are a cybersecurity expert. Analyze these scan results and produce an executive security report.\n\nScan Results:\n{}\n\nProduce: Executive Summary, Critical Findings, Risk Assessment, Remediation Priorities.",
            scan_json
        );
        self.chat(&prompt).await
    }

    async fn chat(&self, prompt: &str) -> Result<String> {
        let request = OpenAIRequest {
            model: self.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: "You are a cybersecurity expert. Respond concisely.".to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            temperature: 0.2,
            max_tokens: 2048,
        };

        let response = self
            .client
            .post(OPENAI_API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call OpenAI API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("OpenAI API error {}: {}", status, error_text);
        }

        let openai_response: OpenAIResponse = response
            .json()
            .await
            .context("Failed to parse OpenAI response")?;

        openai_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| anyhow::anyhow!("No response from OpenAI"))
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

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
    max_tokens: i32,
}

#[derive(Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIResponseMessage,
}

#[derive(Deserialize)]
struct OpenAIResponseMessage {
    content: String,
}
