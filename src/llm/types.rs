use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMAnalysis {
    pub service_identification: Option<ServiceIdentification>,
    pub vulnerability_assessment: Option<VulnerabilityAssessment>,
    pub recommendations: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIdentification {
    pub service_name: String,
    pub likely_technology: String,
    pub version_guess: Option<String>,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityAssessment {
    pub risk_level: RiskLevel,
    pub known_cves: Vec<String>,
    pub potential_issues: Vec<String>,
    pub remediation_steps: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub enum LLMProvider {
    Gemini { api_key: String },
    Claude { api_key: String },
    OpenAI { api_key: String },
    Ollama { base_url: String, model: String },
    Disabled,
}

impl LLMProvider {
    pub fn from_env() -> Self {
        if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
            return Self::Claude { api_key };
        }
        if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
            return Self::OpenAI { api_key };
        }
        if let Ok(api_key) = std::env::var("GEMINI_API_KEY") {
            return Self::Gemini { api_key };
        }
        if std::env::var("OLLAMA_HOST").is_ok() || std::env::var("OLLAMA_MODEL").is_ok() {
            let base_url = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string());
            let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.1".to_string());
            return Self::Ollama { base_url, model };
        }
        Self::Disabled
    }

    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "claude" | "anthropic" => {
                let api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
                Self::Claude { api_key }
            }
            "openai" | "gpt" => {
                let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
                Self::OpenAI { api_key }
            }
            "gemini" | "google" => {
                let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
                Self::Gemini { api_key }
            }
            "ollama" | "local" => {
                let base_url = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string());
                let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.1".to_string());
                Self::Ollama { base_url, model }
            }
            _ => Self::Disabled,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Gemini { .. } => "gemini",
            Self::Claude { .. } => "claude",
            Self::OpenAI { .. } => "openai",
            Self::Ollama { .. } => "ollama",
            Self::Disabled => "disabled",
        }
    }
}
