pub mod claude;
pub mod gemini;
pub mod ollama;
pub mod openai;
pub mod types;

pub use claude::ClaudeClient;
pub use gemini::GeminiClient;
pub use ollama::OllamaClient;
pub use openai::OpenAIClient;
pub use types::{
    LLMAnalysis, LLMProvider, RiskLevel, ServiceIdentification, VulnerabilityAssessment,
};

use anyhow::Result;
use tracing::info;

pub struct LLMAnalyzer {
    provider: LLMProvider,
}

impl LLMAnalyzer {
    pub fn new(provider: LLMProvider) -> Self {
        Self { provider }
    }

    pub fn from_env() -> Self {
        Self::new(LLMProvider::from_env())
    }

    pub fn from_provider_name(name: &str) -> Self {
        Self::new(LLMProvider::from_name(name))
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.provider, LLMProvider::Disabled)
    }

    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    pub async fn analyze_banner(&self, banner: &str, port: u16) -> Result<Option<LLMAnalysis>> {
        match &self.provider {
            LLMProvider::Gemini { api_key } => {
                let client = GeminiClient::new(api_key.clone());
                Ok(Some(client.analyze_banner(banner, port).await?))
            }
            LLMProvider::Claude { api_key } => {
                let client = ClaudeClient::new(api_key.clone());
                Ok(Some(client.analyze_banner(banner, port).await?))
            }
            LLMProvider::OpenAI { api_key } => {
                let client = OpenAIClient::new(api_key.clone());
                Ok(Some(client.analyze_banner(banner, port).await?))
            }
            LLMProvider::Ollama { base_url, model } => {
                let client = OllamaClient::new(base_url.clone(), model.clone());
                Ok(Some(client.analyze_banner(banner, port).await?))
            }
            LLMProvider::Disabled => Ok(None),
        }
    }

    pub async fn analyze_vulnerabilities(
        &self,
        service: &str,
        version: Option<&str>,
    ) -> Result<Option<VulnerabilityAssessment>> {
        match &self.provider {
            LLMProvider::Gemini { api_key } => {
                let client = GeminiClient::new(api_key.clone());
                Ok(Some(client.analyze_vulnerabilities(service, version).await?))
            }
            LLMProvider::Claude { api_key } => {
                let client = ClaudeClient::new(api_key.clone());
                Ok(Some(client.analyze_vulnerabilities(service, version).await?))
            }
            LLMProvider::OpenAI { api_key } => {
                let client = OpenAIClient::new(api_key.clone());
                Ok(Some(client.analyze_vulnerabilities(service, version).await?))
            }
            LLMProvider::Ollama { base_url, model } => {
                let client = OllamaClient::new(base_url.clone(), model.clone());
                Ok(Some(client.analyze_vulnerabilities(service, version).await?))
            }
            LLMProvider::Disabled => Ok(None),
        }
    }

    pub async fn generate_report(&self, scan_json: &str) -> Result<Option<String>> {
        info!("Generating security report using {} LLM", self.provider.name());
        match &self.provider {
            LLMProvider::Gemini { api_key } => {
                let client = GeminiClient::new(api_key.clone());
                Ok(Some(client.generate_report(scan_json).await?))
            }
            LLMProvider::Claude { api_key } => {
                let client = ClaudeClient::new(api_key.clone());
                Ok(Some(client.generate_report(scan_json).await?))
            }
            LLMProvider::OpenAI { api_key } => {
                let client = OpenAIClient::new(api_key.clone());
                Ok(Some(client.generate_report(scan_json).await?))
            }
            LLMProvider::Ollama { base_url, model } => {
                let client = OllamaClient::new(base_url.clone(), model.clone());
                Ok(Some(client.generate_report(scan_json).await?))
            }
            LLMProvider::Disabled => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_name() {
        let p = LLMProvider::from_name("claude");
        assert_eq!(p.name(), "claude");

        let p = LLMProvider::from_name("openai");
        assert_eq!(p.name(), "openai");

        let p = LLMProvider::from_name("ollama");
        assert_eq!(p.name(), "ollama");

        let p = LLMProvider::from_name("gemini");
        assert_eq!(p.name(), "gemini");

        let p = LLMProvider::from_name("bogus");
        assert_eq!(p.name(), "disabled");
    }

    #[test]
    fn test_analyzer_disabled() {
        let analyzer = LLMAnalyzer::new(LLMProvider::Disabled);
        assert!(!analyzer.is_enabled());
    }
}
