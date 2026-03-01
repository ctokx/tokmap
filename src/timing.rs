use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimingTemplate {
    Paranoid,    // T0
    Sneaky,      // T1
    Polite,      // T2
    Normal,      // T3 (default)
    Aggressive,  // T4
    Insane,      // T5
}

#[derive(Debug, Clone)]
pub struct TimingConfig {
    pub max_concurrent: usize,
    pub timeout: Duration,
    pub scan_delay: Duration,
    pub max_retries: u32,
    pub host_timeout: Duration,
    pub rate_limit: Option<u32>,
}

impl TimingTemplate {
    pub fn from_level(level: u8) -> Self {
        match level {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => TimingTemplate::Normal,
        }
    }

    pub fn to_config(&self) -> TimingConfig {
        match self {
            TimingTemplate::Paranoid => TimingConfig {
                max_concurrent: 1,
                timeout: Duration::from_secs(300),
                scan_delay: Duration::from_secs(300),
                max_retries: 10,
                host_timeout: Duration::from_secs(0),
                rate_limit: Some(1),
            },
            TimingTemplate::Sneaky => TimingConfig {
                max_concurrent: 1,
                timeout: Duration::from_secs(15),
                scan_delay: Duration::from_secs(15),
                max_retries: 10,
                host_timeout: Duration::from_secs(0),
                rate_limit: Some(1),
            },
            TimingTemplate::Polite => TimingConfig {
                max_concurrent: 10,
                timeout: Duration::from_secs(10),
                scan_delay: Duration::from_millis(400),
                max_retries: 10,
                host_timeout: Duration::from_secs(0),
                rate_limit: Some(10),
            },
            TimingTemplate::Normal => TimingConfig {
                max_concurrent: 200,
                timeout: Duration::from_millis(1000),
                scan_delay: Duration::ZERO,
                max_retries: 3,
                host_timeout: Duration::from_secs(0),
                rate_limit: None,
            },
            TimingTemplate::Aggressive => TimingConfig {
                max_concurrent: 1000,
                timeout: Duration::from_millis(500),
                scan_delay: Duration::ZERO,
                max_retries: 2,
                host_timeout: Duration::from_secs(300),
                rate_limit: None,
            },
            TimingTemplate::Insane => TimingConfig {
                max_concurrent: 5000,
                timeout: Duration::from_millis(250),
                scan_delay: Duration::ZERO,
                max_retries: 1,
                host_timeout: Duration::from_secs(75),
                rate_limit: None,
            },
        }
    }
}

impl std::fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimingTemplate::Paranoid => write!(f, "T0 (Paranoid)"),
            TimingTemplate::Sneaky => write!(f, "T1 (Sneaky)"),
            TimingTemplate::Polite => write!(f, "T2 (Polite)"),
            TimingTemplate::Normal => write!(f, "T3 (Normal)"),
            TimingTemplate::Aggressive => write!(f, "T4 (Aggressive)"),
            TimingTemplate::Insane => write!(f, "T5 (Insane)"),
        }
    }
}
