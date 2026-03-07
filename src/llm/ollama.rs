use super::types::{LLMAnalysis, ServiceIdentification, VulnerabilityAssessment};
use super::claude::{extract_json, parse_risk_level};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use reqwest::Client;

pub struct OllamaClient {
    client: Client,
    base_url: String,
    model: String,
}

impl OllamaClient {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            model,
        }
    }

    pub fn default_local() -> Self {
        Self::new(
            "http://localhost:11434".to_string(),
            "llama3.1".to_string(),
        )
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
    "vulnerabilities": [],
    "potential_issues": ["...", ...],
    "recommendations": ["...", ...]
}}"#,
            port, banner
        );

        let response_text = self.generate(&prompt).await?;
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
    "known_cves": [],
    "potential_issues": ["...", ...],
    "remediation_steps": ["...", ...]
}}"#,
            service, version_str
        );

        let response_text = self.generate(&prompt).await?;
        self.parse_vulnerability_assessment(&response_text)
    }

    pub async fn generate_report(&self, scan_json: &str) -> Result<String> {
        let prompt = format!(
            "You are a cybersecurity expert. Analyze these scan results and produce an executive security report.\n\nScan Results:\n{}\n\nProduce: Executive Summary, Critical Findings, Risk Assessment, Remediation Priorities.",
            scan_json
        );
        self.generate(&prompt).await
    }

    async fn generate(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.base_url);

        let request = OllamaRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            stream: false,
            options: OllamaOptions {
                temperature: 0.2,
                num_predict: 2048,
            },
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to call Ollama API (is ollama running?)")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Ollama API error {}: {}", status, error_text);
        }

        let ollama_response: OllamaResponse = response
            .json()
            .await
            .context("Failed to parse Ollama response")?;

        Ok(ollama_response.response)
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
            #[serde(default)]
            vulnerabilities: Vec<String>,
            #[serde(default)]
            potential_issues: Vec<String>,
            #[serde(default)]
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
            confidence: 0.6,
        })
    }

    fn parse_vulnerability_assessment(&self, response: &str) -> Result<VulnerabilityAssessment> {
        let json_str = extract_json(response);

        #[derive(Deserialize)]
        struct ParsedVuln {
            risk_level: String,
            #[serde(default)]
            known_cves: Vec<String>,
            #[serde(default)]
            potential_issues: Vec<String>,
            #[serde(default)]
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
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f32,
    num_predict: i32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}
