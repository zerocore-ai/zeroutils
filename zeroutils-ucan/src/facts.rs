use std::collections::BTreeMap;

use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A collection of additional facts or assertions stored as key-value pairs in a UCAN token.
pub type UcanFacts = BTreeMap<String, Value>;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_ucan_facts_serde() -> anyhow::Result<()> {
        let mut facts = UcanFacts::new();
        facts.insert("key1".to_string(), json!("value1"));
        facts.insert("key2".to_string(), json!("value2"));

        let serialized = serde_json::to_string(&facts)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(facts, deserialized);

        Ok(())
    }
}
