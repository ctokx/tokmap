use super::types::{LLMAnalysis, ServiceIdentification, VulnerabilityAssessment};
use super::claude::{extract_json, parse_risk_level};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use reqwest::Client;

const GEMINI_API_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent";

pub struct GeminiClient {
    api_key: String,
    client: Client,
}

impl GeminiClient {
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

Analyze this service banner and provide:
1. Service identification (what service is this?)
2. Technology stack (what software/framework)
3. Version if detectable
4. Security assessment
5. Potential vulnerabilities
6. Recommendations

Respond in JSON format with this structure:
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

Be concise but thorough. Only include real CVEs if you're certain."#,
            port, banner
        );

        let response_text = self.generate_content(&prompt).await?;
        self.parse_analysis(&response_text)
    }

    pub async fn analyze_vulnerabilities(
        &self,
        service: &str,
        version: Option<&str>,
    ) -> Result<VulnerabilityAssessment> {
        let version_str = version.unwrap_or("unknown");

        let prompt = format!(
            r#"You are a cybersecurity expert analyzing software vulnerabilities.

Service: {}
Version: {}

Provide a security assessment including:
1. Known CVEs (only real, verified CVEs)
2. Risk level (critical/high/medium/low/info)
3. Exploitation difficulty
4. Remediation steps
5. Additional security concerns

Respond in JSON format:
{{
    "risk_level": "critical"|"high"|"medium"|"low"|"info",
    "known_cves": ["CVE-XXXX-YYYY", ...],
    "potential_issues": ["...", ...],
    "remediation_steps": ["...", ...]
}}

Only include confirmed information. If version is unknown, provide general guidance."#,
            service, version_str
        );

        let response_text = self.generate_content(&prompt).await?;
        self.parse_vulnerability_assessment(&response_text)
    }

    pub async fn generate_report(&self, scan_json: &str) -> Result<String> {
        let prompt = format!(
            "You are a cybersecurity expert. Analyze these scan results and produce an executive security report.\n\nScan Results:\n{}\n\nProduce: Executive Summary, Critical Findings, Risk Assessment, Remediation Priorities.",
            scan_json
        );
        self.generate_content(&prompt).await
    }

    async fn generate_content(&self, prompt: &str) -> Result<String> {
        let request = GeminiRequest {
            contents: vec![Content {
                parts: vec![Part {
                    text: prompt.to_string(),
                }],
            }],
            generation_config: Some(GenerationConfig {
                temperature: Some(0.2),
                top_p: Some(0.95),
                top_k: Some(40),
                max_output_tokens: Some(2048),
            }),
        };

        let response = self
            .client
            .post(GEMINI_API_URL)
            .header("x-goog-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call Gemini API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gemini API error {}: {}", status, error_text);
        }

        let gemini_response: GeminiResponse = response
            .json()
            .await
            .context("Failed to parse Gemini response")?;

        gemini_response
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .ok_or_else(|| anyhow::anyhow!("No response from Gemini"))
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
            confidence: 0.8,
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
struct GeminiRequest {
    contents: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    content: Content,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::RiskLevel;

    #[test]
    fn test_extract_json() {
        let input = r#"Sure! Here's the analysis:
```json
{"service": "nginx"}
```
Hope this helps!"#;
        let result = extract_json(input);
        assert_eq!(result, r#"{"service": "nginx"}"#);

        let input2 = r#"{"service": "apache"}"#;
        let result2 = extract_json(input2);
        assert_eq!(result2, r#"{"service": "apache"}"#);
    }

    #[test]
    fn test_parse_risk_level() {
        assert!(matches!(parse_risk_level("critical"), RiskLevel::Critical));
        assert!(matches!(parse_risk_level("HIGH"), RiskLevel::High));
        assert!(matches!(parse_risk_level("Medium"), RiskLevel::Medium));
        assert!(matches!(parse_risk_level("unknown"), RiskLevel::Info));
    }
}
