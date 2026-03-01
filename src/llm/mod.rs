pub mod gemini;
pub mod types;

pub use gemini::GeminiClient;
pub use types::{
    LLMAnalysis, LLMProvider, RiskLevel, ServiceIdentification, VulnerabilityAssessment,
};

use anyhow::Result;

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

    pub fn is_enabled(&self) -> bool {
        !matches!(self.provider, LLMProvider::Disabled)
    }

    pub async fn analyze_banner(&self, banner: &str, port: u16) -> Result<Option<LLMAnalysis>> {
        match &self.provider {
            LLMProvider::Gemini { api_key } => {
                let client = GeminiClient::new(api_key.clone());
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
            LLMProvider::Disabled => Ok(None),
        }
    }
}
