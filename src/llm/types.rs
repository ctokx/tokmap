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
    Disabled,
}

impl LLMProvider {
    pub fn from_env() -> Self {
        if let Ok(api_key) = std::env::var("GEMINI_API_KEY") {
            Self::Gemini { api_key }
        } else {
            Self::Disabled
        }
    }
}
