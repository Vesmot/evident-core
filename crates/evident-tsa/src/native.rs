use std::thread;
use std::time::Duration;

use chrono::Utc;
use reqwest::blocking::Client;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TsaStatus {
    Anchored,
    Skipped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TsaResult {
    pub status: TsaStatus,
    pub provider: Option<String>,
    pub tsr_data: Option<Vec<u8>>,
    pub verified_time: Option<String>,
    pub error: Option<String>,
}

const TIMEOUT_SECS: u64 = 15;
const MAX_RETRIES: u32 = 3;
const BACKOFF_MS: [u64; 3] = [200, 400, 800];

fn provider_name(url: &str) -> String {
    if url.contains("freetsa") {
        "FreeTSA".to_string()
    } else if url.contains("digicert") {
        "DigiCert".to_string()
    } else {
        url.to_string()
    }
}

fn skipped_result(error: Option<String>) -> TsaResult {
    TsaResult {
        status: TsaStatus::Skipped,
        provider: None,
        tsr_data: None,
        verified_time: None,
        error,
    }
}

fn anchored_result(provider: String, tsr_data: Vec<u8>) -> TsaResult {
    TsaResult {
        status: TsaStatus::Anchored,
        provider: Some(provider),
        tsr_data: Some(tsr_data),
        verified_time: Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        error: None,
    }
}

pub fn seal_with_tsa(file_hash_bytes: &[u8; 32], url: &str) -> TsaResult {
    let client = match Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return skipped_result(Some(format!("HTTP client build failed: {e}")));
        }
    };

    let provider = provider_name(url);

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(BACKOFF_MS[(attempt - 1) as usize]));
        }

        match client.post(url).body(file_hash_bytes.to_vec()).send() {
            Ok(response) => {
                if !response.status().is_success() {
                    continue;
                }
                match response.bytes() {
                    Ok(bytes) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        return anchored_result(provider, bytes.to_vec());
                    }
                    Err(e) => {
                        return skipped_result(Some(format!("read TSA response: {e}")));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    skipped_result(Some(format!("TSA request failed after {MAX_RETRIES} retries: {url}")))
}

pub fn seal_with_fallback(file_hash_bytes: &[u8; 32], urls: &[String]) -> TsaResult {
    let mut last_error = None;

    for url in urls {
        let result = seal_with_tsa(file_hash_bytes, url);
        if result.status == TsaStatus::Anchored {
            return result;
        }
        last_error = result.error;
    }

    skipped_result(last_error.or_else(|| Some("all TSA sources failed".to_string())))
}