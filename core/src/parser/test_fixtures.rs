use std::fs;

use serde_json::{json, Value};

use crate::parser::config::ExtractorConfig;

#[test]
fn test_coinbase_extraction() {
  let json_data: Value =
    serde_json::from_str(&fs::read_to_string("../core/fixtures/coinbase.json").unwrap()).unwrap();
  let json_data = json_data.to_string().into_bytes();

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
  assert_eq!(
    usdc_result.values.get("usdc_balance").unwrap().as_str().unwrap(),
    "8.967465955899945"
  );
  assert_eq!(
    usdc_result.values.get("usdc_balance_fiat").unwrap().as_str().unwrap(),
    "8.967465955899945"
  );
}

#[test]
fn test_website_extraction() {
  let html_data = fs::read_to_string("../core/fixtures/website.html").unwrap().into_bytes();

  // Create extractor config for main content
  let main_config = serde_json::from_value::<ExtractorConfig>(json!({
      "format": "html",
      "extractors": [
          {
              "id": "page_title",
              "description": "Extract page title",
              "selector": ["head", "title"],
              "type": "string"
          },
          {
              "id": "meta_description",
              "description": "Extract meta description",
              "selector": ["head", "meta[name='description']"],
              "type": "string",
              "attribute": "content"
          },
          {
              "id": "hero_title",
              "description": "Extract hero title",
              "selector": ["main", "section.hero-section", "h1"],
              "type": "string"
          },
          {
              "id": "feature_titles",
              "description": "Extract all feature titles",
              "selector": [
                  "main",
                  "section.features-section",
                  "div.features-grid",
                  "article.feature-card",
                  "h3.feature-title"
              ],
              "type": "array"
          },
          {
              "id": "feature_ratings",
              "description": "Extract all feature ratings",
              "selector": [
                  "main",
                  "section.features-section",
                  "div.features-grid",
                  "article.feature-card",
                  "div.feature-meta",
                  "span.feature-rating"
              ],
              "type": "array",
              "attribute": "data-rating"
          },
          {
              "id": "first_rating",
              "description": "Extract first feature rating",
              "selector": [
                  "main",
                  "section.features-section",
                  "div.features-grid",
                  "article#feature-1",
                  "div.feature-meta",
                  "span.feature-rating"
              ],
              "type": "number",
              "attribute": "data-rating"
          }
      ]
  }))
  .unwrap();

  // Extract data using the config
  let result = main_config.extract_and_validate(&html_data).unwrap();

  // Verify extraction
  assert_eq!(result.errors.len(), 0);
  assert_eq!(result.values.len(), 6);

  // Check individual values
  assert_eq!(result.values["page_title"], json!("Complex Test Page"));
  assert_eq!(result.values["meta_description"], json!("A complex test page for HTML extraction"));
  assert_eq!(result.values["hero_title"], json!("Welcome to Our Complex Test Page"));

  // Check array values
  let feature_titles = result.values["feature_titles"].as_array().unwrap();
  assert_eq!(feature_titles.len(), 3);
  assert!(feature_titles.contains(&json!("Lightning Fast")));
  assert!(feature_titles.contains(&json!("Highly Secure")));
  assert!(feature_titles.contains(&json!("Infinitely Scalable")));

  // Check feature ratings array
  let feature_ratings = result.values["feature_ratings"].as_array().unwrap();
  assert_eq!(feature_ratings.len(), 3);
  assert!(feature_ratings.contains(&json!("4.8")));
  assert!(feature_ratings.contains(&json!("4.9")));
  assert!(feature_ratings.contains(&json!("4.7")));

  // Check numeric value
  assert_eq!(result.values["first_rating"], json!(4.8));
}

#[test]
fn test_wikipedia_shannon_extraction() {
  let html_data = fs::read_to_string("../core/fixtures/claude_shannon.html").unwrap().into_bytes();

  // Create extractor config for Wikipedia content
  let wiki_config = serde_json::from_value::<ExtractorConfig>(json!({
      "format": "html",
      "extractors": [
          {
              "id": "pageTitle",
              "description": "Extract the page title",
              "selector": ["title"],
              "type": "string",
              "predicates": [{
                  "type": "value",
                  "comparison": "contains",
                  "value": "Claude Shannon",
                  "case_sensitive": true
              }]
          },
          {
              "id": "roles",
              "description": "Extract his professional roles",
              "selector": ["div#mw-content-text", "div.mw-parser-output", "p", "a"],
              "type": "array",
              "predicates": [
                  {
                      "type": "value",
                      "comparison": "contains",
                      "value": "mathematician",
                      "case_sensitive": false
                  },
                  {
                      "type": "value",
                      "comparison": "contains",
                      "value": "electrical engineer",
                      "case_sensitive": false
                  },
                  {
                      "type": "value",
                      "comparison": "contains",
                      "value": "cryptographer",
                      "case_sensitive": false
                  }
              ]
          }
      ]
  }))
  .unwrap();

  // Extract data using the config
  let result = wiki_config.extract_and_validate(&html_data).unwrap();

  // Verify extraction
  assert_eq!(result.errors.len(), 0, "Expected no errors but got: {:?}", result.errors);
  assert_eq!(result.values.len(), 2, "Expected exactly 2 extracted values");

  // Check page title
  let page_title = result.values["pageTitle"].as_str().expect("pageTitle should be a string");
  assert!(
    page_title.contains("Claude Shannon"),
    "Page title '{}' should contain 'Claude Shannon'",
    page_title
  );

  // Check roles array
  let roles = result.values["roles"].as_array().expect("roles should be an array");

  // Helper function to check if roles contain a specific profession
  let contains_role = |role: &str| {
    roles
      .iter()
      .any(|r| r.as_str().map(|s| s.to_lowercase().contains(&role.to_lowercase())).unwrap_or(false))
  };

  // Assert each required role is present
  assert!(
    contains_role("mathematician"),
    "Roles should contain 'mathematician'. Found roles: {:?}",
    roles
  );
  assert!(
    contains_role("electrical engineer"),
    "Roles should contain 'electrical engineer'. Found roles: {:?}",
    roles
  );
  assert!(
    contains_role("cryptographer"),
    "Roles should contain 'cryptographer'. Found roles: {:?}",
    roles
  );
}
