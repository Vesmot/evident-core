use evident_crypto::hash;
use serde_json::Value;

pub const GENESIS_SEED: &str = "CASE::GENESIS::v1";

pub trait ChainLinker {
    fn genesis_hash() -> String;

    fn compute_hash(data: &[u8], prev: &str) -> String;

    fn verify(prev: &str, current: &str, data: &[u8]) -> bool;
}

pub struct CaseChainLinker;

impl ChainLinker for CaseChainLinker {
    fn genesis_hash() -> String {
        hash::sha256_hex(GENESIS_SEED.as_bytes())
    }

    fn compute_hash(data: &[u8], prev: &str) -> String {
        let mut buf = Vec::with_capacity(data.len() + prev.len());
        buf.extend_from_slice(data);
        buf.extend_from_slice(prev.as_bytes());
        hash::sha256_hex(&buf)
    }

    fn verify(prev: &str, current: &str, data: &[u8]) -> bool {
        Self::compute_hash(data, prev) == current
    }
}

/// Deterministic JSON: object keys sorted recursively.
pub fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
    let sorted = sort_json_value(value);
    Ok(serde_json::to_vec(&sorted)?)
}

fn sort_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    out.insert(key, sort_json_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json_value).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic() {
        let g1 = CaseChainLinker::genesis_hash();
        let g2 = CaseChainLinker::genesis_hash();
        assert_eq!(g1, g2);
        assert_eq!(g1.len(), 64);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v1: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let v2: Value = serde_json::from_str(r#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(
            canonical_json_bytes(&v1).unwrap(),
            canonical_json_bytes(&v2).unwrap()
        );
    }
}
