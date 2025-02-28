use serde_json::json;
use std::fs;

use serde_json::Value;

use crate::parser::config::ExtractorConfig;

#[test]
fn test_coinbase_extraction() {
    let json_data: Value =
        serde_json::from_str(&fs::read_to_string("../web-prover-core/fixtures/coinbase.json").unwrap())
            .unwrap();

    // Create extractor config for Ethereum data
    let eth_config = serde_json::from_value::<ExtractorConfig>(json!({
    "format": "json",
    "extractors": [
      {
        "id": "eth_name",
        "description": "Extract Ethereum name",
        "selector": ["data", "viewer", "ownedAssets", "edges", "1", "node", "asset", "name"],
        "type": "string",
        "predicates": [{
          "type": "value",
          "comparison": "equal",
          "value": "Ethereum"
        }]
      },
      {
        "id": "eth_price",
        "description": "Extract Ethereum price",
        "selector": ["data", "viewer", "ownedAssets", "edges", "1", "node", "asset", "latestPrice", "price"],
        "type": "string",
      },
      {
        "id": "eth_balance",
        "description": "Extract Ethereum balance",
        "selector": ["data", "viewer", "ownedAssets", "edges", "1", "node", "assetCurrentBalance", "totalBalance", "value"],
        "type": "string",
      },
      {
        "id": "eth_balance_fiat",
        "description": "Extract Ethereum balance in fiat",
        "selector": ["data", "viewer", "ownedAssets", "edges", "1", "node", "assetCurrentBalance", "totalBalanceFiat", "value"],
        "type": "string",
      }
    ]
  })).unwrap();

    // Create extractor config for USDC data
    let usdc_config = serde_json::from_value::<ExtractorConfig>(json!({
    "format": "json",
    "extractors": [
      {
        "id": "usdc_name",
        "description": "Extract USDC name",
        "selector": ["data", "viewer", "ownedAssets", "edges", "2", "node", "asset", "name"],
        "type": "string",
        "predicates": [{
          "type": "value",
          "comparison": "equal",
          "value": "USDC"
        }]
      },
      {
        "id": "usdc_price",
        "description": "Extract USDC price",
        "selector": ["data", "viewer", "ownedAssets", "edges", "2", "node", "asset", "latestPrice", "price"],
        "type": "string",
      },
      {
        "id": "usdc_balance",
        "description": "Extract USDC balance",
        "selector": ["data", "viewer", "ownedAssets", "edges", "2", "node", "assetCurrentBalance", "totalBalance", "value"],
        "type": "string",
      },
      {
        "id": "usdc_balance_fiat",
        "description": "Extract USDC balance in fiat",
        "selector": ["data", "viewer", "ownedAssets", "edges", "2", "node", "assetCurrentBalance", "totalBalanceFiat", "value"],
        "type": "string",
      }
    ]
  })).unwrap();

    // Extract data using the configs
    let eth_result = eth_config.extract_and_validate(&json_data).unwrap();
    let usdc_result = usdc_config.extract_and_validate(&json_data).unwrap();

    // Verify Ethereum extraction
    assert_eq!(eth_result.errors.len(), 0);
    assert_eq!(eth_result.values.len(), 4);
    assert_eq!(eth_result.values.get("eth_name").unwrap().as_str().unwrap(), "Ethereum");
    assert_eq!(eth_result.values.get("eth_price").unwrap().as_str().unwrap(), "8.405987856750084");
    assert_eq!(eth_result.values.get("eth_balance").unwrap().as_str().unwrap(), "0.000523067532462");
    assert_eq!(
        eth_result.values.get("eth_balance_fiat").unwrap().as_str().unwrap(),
        "1.21843089477932049"
    );

    // Verify USDC extraction
    assert_eq!(usdc_result.errors.len(), 0);
    assert_eq!(usdc_result.values.len(), 4);
    assert_eq!(usdc_result.values.get("usdc_name").unwrap().as_str().unwrap(), "USDC");
    assert_eq!(usdc_result.values.get("usdc_price").unwrap().as_str().unwrap(), "1");
    assert_eq!(usdc_result.values.get("usdc_balance").unwrap().as_str().unwrap(), "8.967465955899945");
    assert_eq!(usdc_result.values.get("usdc_balance_fiat").unwrap().as_str().unwrap(), "8.967465955899945");
}