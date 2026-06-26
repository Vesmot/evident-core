use std::path::PathBuf;

use anyhow::Result;
use evident_case::{CaseEngine, CaseVerifyResult, VERIFY_VALID};
use evident_crypto::key_store;
use serde::Serialize;
use serde_json::Value;

pub fn default_case_root() -> PathBuf {
    std::env::var("EVIDENT_CASE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| CaseEngine::default_root())
}

pub fn cmd_case_create(case_id: &str, root: &PathBuf, pin: &[u8], json: bool) -> Result<u8> {
    let signing_key = key_store::load(pin)?;
    let engine = CaseEngine::new(root, signing_key);
    engine.create_case(case_id)?;

    if json {
        let out = CaseActionOutput {
            case_id: case_id.to_string(),
            status: "created".to_string(),
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Case created: {case_id}");
        println!("Root: {}", root.display());
    }

    Ok(0)
}

pub fn cmd_case_append(
    case_id: &str,
    event_type: &str,
    data: Value,
    root: &PathBuf,
    pin: &[u8],
    json: bool,
) -> Result<u8> {
    let signing_key = key_store::load(pin)?;
    let engine = CaseEngine::new(root, signing_key);
    let current_hash = engine.append_event(case_id, event_type, data)?;

    if json {
        let out = CaseAppendOutput {
            case_id: case_id.to_string(),
            current_hash: current_hash.clone(),
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Event appended to case: {case_id}");
        println!("current_hash: {current_hash}");
    }

    Ok(0)
}

pub fn cmd_case_verify(case_id: &str, root: &PathBuf, pin: &[u8], json: bool) -> Result<u8> {
    let signing_key = key_store::load(pin)?;
    let engine = CaseEngine::new(root, signing_key);
    let result = engine.verify_case(case_id)?;

    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        print_verify_human(case_id, &result);
    }

    if result.status == VERIFY_VALID {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn print_verify_human(case_id: &str, result: &CaseVerifyResult) {
    println!("Case:   {case_id}");
    println!("Status: {}", result.status);
    if let Some(idx) = result.failed_at {
        println!("Failed: event index {idx}");
    }
    if let Some(ref reason) = result.reason {
        println!("Reason: {reason}");
    }
}

pub fn parse_data_json(data: Option<&str>) -> Result<Value> {
    match data {
        Some(raw) => serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("invalid --data JSON: {e}")),
        None => Ok(Value::Object(serde_json::Map::new())),
    }
}

#[derive(Serialize)]
struct CaseActionOutput {
    case_id: String,
    status: String,
}

#[derive(Serialize)]
struct CaseAppendOutput {
    case_id: String,
    current_hash: String,
}
