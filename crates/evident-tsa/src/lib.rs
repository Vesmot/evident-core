pub mod native;

pub use native::{seal_with_fallback, TsaResult, TsaStatus};

pub struct TsaConfig {
    pub urls: Vec<String>,
}

impl Default for TsaConfig {
    fn default() -> Self {
        Self {
            urls: vec![
                "https://freetsa.org/tsr".to_string(),
                "http://timestamp.digicert.com".to_string(),
            ],
        }
    }
}

pub fn seal(file_hash_bytes: &[u8; 32], config: &TsaConfig) -> TsaResult {
    seal_with_fallback(file_hash_bytes, &config.urls)
}
