use serde_json::Value;
use tl::{Node, NodeHandle, Parser, ParserOptions, VDom};

use super::types::{ExtractionResult, Extractor, ExtractorType};
use crate::parser::{predicate, DataFormat, ExtractorConfig, ExtractorError};

/// Extracts data from HTML using CSS selectors
pub fn extract_html(
  html_str: &str,
  config: &ExtractorConfig,
) -> Result<ExtractionResult, ExtractorError> {
  if config.format != DataFormat::Html {
    return Err(ExtractorError::InvalidFormat(format!(
      "Expected HTML format, got {}",
      config.format
    )));
  }

  let mut result = ExtractionResult::default();

  // Parse the HTML document
  let dom = tl::parse(html_str, ParserOptions::default())
    .map_err(|err| ExtractorError::InvalidHtml(err.to_string()))?;

  for extractor in &config.extractors {
    match extract_html_value(&dom, &extractor.selector, extractor) {
      Ok(value) => {
        // Validate the type
        if let Err(type_err) = extractor.extractor_type.is_valid_type(&value) {
          if extractor.required {
            match &type_err {
              ExtractorError::TypeMismatch { expected, actual } => {
                result.errors.push(format!(
                  "Extractor '{}': Expected {}, got {}",
                  extractor.id, expected, actual
                ));
              },
              _ => result.errors.push(format!("Extractor '{}': {}", extractor.id, type_err)),
            }
          }
          continue;
        }

        // Validate predicates
        let mut predicate_valid = true;
        for predicate in &extractor.predicates {
          if let Err(pred_err) = predicate::validate_predicate(&value, predicate) {
            if extractor.required {
              result.errors.push(format!("Extractor '{}': {}", extractor.id, pred_err));
            }
            predicate_valid = false;
            break;
          }
        }

        if predicate_valid {
          result.values.insert(extractor.id.clone(), value);
        }
      },
      Err(err) =>
        if extractor.required {
          result.errors.push(format!("Extractor '{}': {}", extractor.id, err));
        },
    }
  }

  Ok(result)
}

/// Extracts a value from an HTML document using CSS selectors
pub fn extract_html_value(
  dom: &VDom,
  selector_path: &[String],
  extractor: &Extractor,
) -> Result<Value, ExtractorError> {
  if selector_path.is_empty() {
    return Err(ExtractorError::MissingField("Empty selector path".to_string()));
  }

  // Handle single selector case
  if selector_path.len() == 1 {
    return extract_with_single_selector(dom, &selector_path[0], extractor);
  }

  let elements: Vec<NodeHandle> = traverse_dom_with_selectors(dom, selector_path)?;
  process_elements(dom.parser(), &elements, extractor)
}

/// Traverses the DOM using a sequence of CSS selectors
fn traverse_dom_with_selectors(
  dom: &VDom,
  selector_path: &[String],
) -> Result<Vec<NodeHandle>, ExtractorError> {
  let first_selector = &selector_path[0];
  let mut current_elements = query_selector(dom, first_selector, 0)?;
  let parser = dom.parser();

  for (i, selector) in selector_path.iter().enumerate().skip(1) {
    current_elements = apply_selector_to_elements(parser, &current_elements, selector, i)?;
  }

  Ok(current_elements)
}

/// Queries DOM with a single selector
fn query_selector(
  dom: &VDom,
  selector: &str,
  position: usize,
) -> Result<Vec<NodeHandle>, ExtractorError> {
  dom.query_selector(selector)
    .ok_or_else(|| ExtractorError::InvalidPath(format!("Invalid selector '{}'", selector)))?
    .collect::<Vec<_>>()
    .into_iter()
    .filter(|_| true) // Ensure non-empty
    .collect::<Vec<_>>()
    .is_empty()
    .then(|| Err(ExtractorError::MissingField(format!(
      "No elements found for selector '{}' at position {}",
      selector, position
    ))))
    .unwrap_or_else(|| Ok(dom.query_selector(selector).unwrap().collect()))
}

/// Applies a selector to a set of elements
fn apply_selector_to_elements(
  parser: &Parser,
  elements: &[NodeHandle],
  selector: &str,
  position: usize,
) -> Result<Vec<NodeHandle>, ExtractorError> {
  let next_elements: Vec<NodeHandle> = elements
    .iter()
    .filter_map(|element| {
      element.get(parser).and_then(|node| {
        node.as_tag().and_then(|tag| {
          tag.query_selector(parser, selector).map(|matches| matches.collect::<Vec<_>>())
        })
      })
    })
    .flatten()
    .collect();

  if next_elements.is_empty() {
    return Err(ExtractorError::MissingField(format!(
      "No elements found for selector '{}' at position {}",
      selector,
      position + 1
    )));
  }

  Ok(next_elements)
}

/// Processes the final set of elements based on extractor configuration
fn process_elements(
  parser: &Parser,
  elements: &[NodeHandle],
  extractor: &Extractor,
) -> Result<Value, ExtractorError> {
  if extractor.extractor_type == ExtractorType::Array {
    return Ok(Value::Array(extract_values_from_elements(parser, elements, extractor)));
  }

  let raw_value = extract_raw_value(parser, &elements[0], extractor);
  convert_to_type(&raw_value, &extractor.extractor_type)
}

/// Extracts values from a set of elements
fn extract_values_from_elements(
  parser: &Parser,
  elements: &[NodeHandle],
  extractor: &Extractor,
) -> Vec<Value> {
  elements
    .iter()
    .filter_map(|el| {
      el.get(parser).map(|node| {
        if let Some(attr) = &extractor.attribute {
          extract_attribute_value(node, attr)
        } else {
          Value::String(node.inner_text(parser).to_string())
        }
      })
    })
    .collect()
}

/// Extracts an attribute value from a node
fn extract_attribute_value(node: &Node, attr: &str) -> Value {
  node
    .as_tag()
    .and_then(|tag| tag.attributes().get(attr))
    .and_then(|attr_value| attr_value.map(|value| value.as_utf8_str().to_string()))
    .map_or_else(|| Value::String("".to_string()), Value::String)
}

/// Extracts raw value from an element
fn extract_raw_value(parser: &Parser, element: &NodeHandle, extractor: &Extractor) -> String {
  if let Some(attr) = &extractor.attribute {
    element
      .get(parser)
      .and_then(|node| node.as_tag())
      .and_then(|tag| tag.attributes().get(attr.as_str()))
      .and_then(|attr_value| attr_value.map(|value| value.as_utf8_str().to_string()))
      .unwrap_or_default()
  } else {
    element.get(parser).map(|node| node.inner_text(parser).to_string()).unwrap_or_default()
  }
}

/// Converts a raw string value to the specified type
fn convert_to_type(
  raw_value: &str,
  extractor_type: &ExtractorType,
) -> Result<Value, ExtractorError> {
  match extractor_type {
    ExtractorType::String => Ok(Value::String(raw_value.to_string())),
    ExtractorType::Number => raw_value
      .parse::<f64>()
      .map(|num| {
        Value::Number(serde_json::Number::from_f64(num).unwrap_or(serde_json::Number::from(0)))
      })
      .map_err(|_| ExtractorError::TypeMismatch {
        expected: "number".to_string(),
        actual:   "string".to_string(),
      }),
    ExtractorType::Boolean =>
      raw_value.parse::<bool>().map(Value::Bool).map_err(|_| ExtractorError::TypeMismatch {
        expected: "boolean".to_string(),
        actual:   "string".to_string(),
      }),
    _ => Err(ExtractorError::TypeMismatch {
      expected: format!("{}", extractor_type),
      actual:   "string".to_string(),
    }),
  }
}

/// Helper function to extract values using a single selector
fn extract_with_single_selector(
  dom: &VDom,
  selector: &str,
  extractor: &Extractor,
) -> Result<Value, ExtractorError> {
  // Query with the single selector
  let elements = match dom.query_selector(selector) {
    Some(matches) => {
      let elements = matches.collect::<Vec<_>>();
      if elements.is_empty() {
        return Err(ExtractorError::MissingField(format!(
          "No elements found for selector '{}'",
          selector
        )));
      }
      elements
    },
    None => {
      return Err(ExtractorError::InvalidPath(format!("Invalid selector '{}'", selector)));
    },
  };

  // Handle array type specially
  if extractor.extractor_type == ExtractorType::Array {
    let values: Vec<Value> = elements
      .iter()
      .filter_map(|el| {
        el.get(dom.parser()).and_then(|node| match &extractor.attribute {
          Some(attr) => node
            .as_tag()
            .and_then(|tag| tag.attributes().get(attr.as_str()))
            .and_then(|attr_value| attr_value.map(|value| value.as_utf8_str().to_string()))
            .map(Value::String),
          None => Some(Value::String(node.inner_text(dom.parser()).to_string())),
        })
      })
      .collect();
    return Ok(Value::Array(values));
  }

  // For non-array types, use the first element
  let element = &elements[0];

  // Extract the raw value (either attribute or text content)
  let raw_value = match &extractor.attribute {
    Some(attr) => element
      .get(dom.parser())
      .and_then(|node| node.as_tag())
      .and_then(|tag| tag.attributes().get(attr.as_str()))
      .and_then(|attr_value| attr_value.map(|value| value.as_utf8_str().to_string()))
      .unwrap_or_default(),
    None => element
      .get(dom.parser())
      .map(|node| node.inner_text(dom.parser()).to_string())
      .unwrap_or_default(),
  };

  // Convert the raw value to the appropriate type
  match extractor.extractor_type {
    ExtractorType::String => Ok(Value::String(raw_value)),
    ExtractorType::Number =>
      if let Ok(num) = raw_value.parse::<f64>() {
        Ok(Value::Number(serde_json::Number::from_f64(num).unwrap_or(serde_json::Number::from(0))))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "number".to_string(),
          actual:   "string".to_string(),
        })
      },
    ExtractorType::Boolean =>
      if let Ok(b) = raw_value.parse::<bool>() {
        Ok(Value::Bool(b))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "boolean".to_string(),
          actual:   "string".to_string(),
        })
      },
    _ => Err(ExtractorError::TypeMismatch {
      expected: format!("{}", extractor.extractor_type),
      actual:   "string".to_string(),
    }),
  }
}

#[cfg(test)]
mod tests {
  use serde_json::{json, Value};
  use tl::VDom;

  use crate::{
    extractor,
    parser::{
      extractors::html::{extract_html, extract_html_value},
      test_utils::{create_complex_test_html, parse_html},
      DataFormat, Extractor, ExtractorConfig, ExtractorError, ExtractorType,
    },
  };

  const BASIC_HTML: &str = r#"
      <!DOCTYPE html>
      <html>
      <head>
          <title>Test Page</title>
          <meta name="description" content="A test page for HTML extraction">
      </head>
      <body>
          <div class="container">
              <header>
                  <h1 id="main-title">Hello, World!</h1>
                  <nav>
                      <ul>
                          <li><a href="/">Home</a></li>
                          <li><a href="/about">About</a></li>
                          <li><a href="/contact">Contact</a></li>
                      </ul>
                  </nav>
              </header>
              <main>
                  <section class="content">
                      <article>
                          <h2>Article Title</h2>
                          <p class="summary">This is a summary of the article.</p>
                          <div class="tags">
                              <span>tag1</span>
                              <span>tag2</span>
                              <span>tag3</span>
                          </div>
                      </article>
                  </section>
                  <aside>
                      <div class="widget">
                          <h3>Related Links</h3>
                          <ul>
                              <li><a href="/link1">Link 1</a></li>
                              <li><a href="/link2">Link 2</a></li>
                          </ul>
                      </div>
                  </aside>
              </main>
              <footer>
                  <p>&copy; 2023 Test Company</p>
              </footer>
          </div>
      </body>
      </html>
  "#;

  // Test helper for common extraction assertions
  fn assert_html_extraction(
    dom: &VDom,
    selector_path: &[String],
    extractor_type: ExtractorType,
    attribute: Option<String>,
    expected_value: Value,
  ) {
    let extractor = extractor!(
      id: "test".to_string(),
      description: "Test extractor".to_string(),
      selector: selector_path.to_vec(),
      extractor_type: extractor_type,
      attribute: attribute
    );
    let result = extract_html_value(dom, selector_path, &extractor);
    assert!(result.is_ok(), "Extraction failed: {:?}", result.err());
    assert_eq!(result.unwrap(), expected_value);
  }

  #[test]
  fn test_html_extract_basic_text() {
    let dom = parse_html(&BASIC_HTML);
    assert_html_extraction(
      &dom,
      &["#main-title".to_string()],
      ExtractorType::String,
      None,
      json!("Hello, World!"),
    );
  }

  #[test]
  fn test_html_extraction_errors() {
    let dom = parse_html(&BASIC_HTML);
    let basic_extractor = extractor!(
      id: "test".to_string(),
      description: "Test extractor".to_string(),
      selector: vec![],
      extractor_type: ExtractorType::String,
      attribute: None
    );

    // Test invalid CSS selector
    let result = extract_html_value(&dom, &["#[invalid".to_string()], &basic_extractor);
    assert!(matches!(result, Err(ExtractorError::InvalidPath(_))));

    // Test non-existent element
    let result = extract_html_value(&dom, &["#non-existent".to_string()], &basic_extractor);
    assert!(matches!(result, Err(ExtractorError::MissingField(_))));

    // Test empty selector path
    let result = extract_html_value(&dom, &[], &basic_extractor);
    assert!(matches!(result, Err(ExtractorError::MissingField(_))));
  }

  fn page_title_extractor() -> Extractor {
    extractor!(
      id: "page_title".to_string(),
      description: "Test extractor for page_title".to_string(),
      selector: vec!["title".to_string()],
      extractor_type: ExtractorType::String
    )
  }

  fn meta_description_extractor() -> Extractor {
    extractor!(
      id: "meta_description".to_string(),
      description: "Test extractor for meta_description".to_string(),
      selector: vec!["meta[name='description']".to_string()],
      extractor_type: ExtractorType::String,
      attribute: Some("content".to_string())
    )
  }

  fn hero_title_extractor() -> Extractor {
    extractor!(
      id: "hero_title".to_string(),
      description: "Test extractor for hero_title".to_string(),
      selector: vec!["main".to_string(), "section.hero-section".to_string(), "h1.hero-title".to_string()],
      extractor_type: ExtractorType::String
    )
  }

  fn feature_titles_extractor() -> Extractor {
    extractor!(
      id: "feature_titles".to_string(),
      description: "Test extractor for feature_titles".to_string(),
      selector: vec!["main".to_string(), "section.features-section".to_string(), "div.features-grid".to_string(), "article.feature-card".to_string(), "h3.feature-title".to_string()],
      extractor_type: ExtractorType::Array
    )
  }

  fn feature_ratings_extractor() -> Extractor {
    extractor!(
      id: "feature_ratings".to_string(),
      description: "Test extractor for feature_ratings".to_string(),
      selector: vec!["main".to_string(), "section.features-section".to_string(), "div.features-grid".to_string(), "article.feature-card".to_string(), "div.feature-meta".to_string(), "span.feature-rating".to_string()],
      extractor_type: ExtractorType::Array,
      attribute: Some("data-rating".to_string())
    )
  }

  fn first_rating_extractor() -> Extractor {
    extractor!(
      id: "first_rating".to_string(),
      description: "Test extractor for first_rating".to_string(),
      selector: vec!["main".to_string(), "section.features-section".to_string(), "div.features-grid".to_string(), "article#feature-1".to_string(), "div.feature-meta".to_string(), "span.feature-rating".to_string()],
      extractor_type: ExtractorType::Number,
      attribute: Some("data-rating".to_string())
    )
  }

  fn create_complex_config() -> ExtractorConfig {
    ExtractorConfig {
      format:     DataFormat::Html,
      extractors: vec![
        page_title_extractor(),
        meta_description_extractor(),
        hero_title_extractor(),
        feature_titles_extractor(),
        feature_ratings_extractor(),
        first_rating_extractor(),
      ],
    }
  }

  #[test]
  fn test_extract_html_with_multiple_extractors() {
    let html = create_complex_test_html();
    let config = create_complex_config();

    let result = extract_html(&html, &config).unwrap();

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

    let feature_ratings = result.values["feature_ratings"].as_array().unwrap();
    assert_eq!(feature_ratings.len(), 3);
    assert!(feature_ratings.contains(&json!("4.8")));
    assert!(feature_ratings.contains(&json!("4.9")));
    assert!(feature_ratings.contains(&json!("4.7")));

    assert_eq!(result.values["first_rating"], json!(4.8));
  }

  // Helper function to test extraction errors
  fn assert_html_extraction_error(
    dom: &VDom,
    selector_path: &[String],
    extractor_type: ExtractorType,
    attribute: Option<String>,
    expected_error_type: fn(ExtractorError) -> bool,
  ) {
    let extractor = extractor!(
      id: "test".to_string(),
      description: "Test extractor".to_string(),
      selector: selector_path.to_vec(),
      extractor_type: extractor_type,
      attribute: attribute
    );
    let result = extract_html_value(dom, selector_path, &extractor);
    assert!(result.is_err(), "Expected error but got: {:?}", result.ok());
    let err = result.err().unwrap();
    assert!(expected_error_type(err), "Unexpected error type");
  }

  #[test]
  fn test_complex_html_with_long_selectors() {
    let html = create_complex_test_html();
    let dom = parse_html(&html);

    // Extract feature title with a long selector path
    assert_html_extraction(
      &dom,
      &[
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article#feature-1".to_string(),
        "h3.feature-title".to_string(),
      ],
      ExtractorType::String,
      None,
      json!("Lightning Fast"),
    );

    // Extract feature rating with attribute
    assert_html_extraction(
      &dom,
      &[
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article#feature-1".to_string(),
        "div.feature-meta".to_string(),
        "span.feature-rating".to_string(),
      ],
      ExtractorType::String,
      Some("data-rating".to_string()),
      json!("4.8"),
    );

    // Extract all feature titles as an array
    let extractor = feature_titles_extractor();

    let result = extract_html_value(
      &dom,
      &[
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article.feature-card".to_string(),
        "h3.feature-title".to_string(),
      ],
      &extractor,
    )
    .unwrap();

    let titles = result.as_array().unwrap();
    assert_eq!(titles.len(), 3);
    assert!(titles.contains(&json!("Lightning Fast")));
    assert!(titles.contains(&json!("Highly Secure")));
    assert!(titles.contains(&json!("Infinitely Scalable")));

    // Extract all feature ratings as numbers
    let extractor = feature_ratings_extractor();

    let result = extract_html_value(
      &dom,
      &[
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article.feature-card".to_string(),
        "div.feature-meta".to_string(),
        "span.feature-rating".to_string(),
      ],
      &extractor,
    )
    .unwrap();

    let ratings = result.as_array().unwrap();
    assert_eq!(ratings.len(), 3);
    assert!(ratings.contains(&json!("4.8")));
    assert!(ratings.contains(&json!("4.9")));
    assert!(ratings.contains(&json!("4.7")));
  }

  #[test]
  fn test_complex_html_edge_cases() {
    let html = create_complex_test_html();
    let dom = parse_html(&html);

    // Extract meta tags with property attributes
    let extractor = extractor!(
      id: "og_title".to_string(),
      description: "Test extractor for og_title".to_string(),
      selector: vec!["head".to_string(), "meta[property='og:title']".to_string()],
      extractor_type: ExtractorType::String,
      attribute: Some("content".to_string())
    );

    let result = extract_html_value(
      &dom,
      &["head".to_string(), "meta[property='og:title']".to_string()],
      &extractor,
    )
    .unwrap();

    assert_eq!(result, json!("Complex Test Page"));

    // Extract elements with data attributes
    let extractor = extractor!(
      id: "active_nav".to_string(),
      description: "Test extractor for active_nav".to_string(),
      selector: vec!["nav.main-nav".to_string(), "a.active".to_string()],
      extractor_type: ExtractorType::String,
      attribute: Some("data-section".to_string())
    );

    let result =
      extract_html_value(&dom, &["nav.main-nav".to_string(), "a.active".to_string()], &extractor)
        .unwrap();

    assert_eq!(result, json!("home"));

    // Extract deeply nested elements with multiple class selectors
    assert_html_extraction(
      &dom,
      &[
        "div.testimonials-slider".to_string(),
        "div.testimonial-slide".to_string(),
        "div.testimonial-author".to_string(),
        "div.testimonial-info".to_string(),
        "cite.testimonial-name".to_string(),
      ],
      ExtractorType::Array,
      None,
      json!(["Jane Doe", "John Smith"]),
    );

    // Extract elements with numeric conversion
    assert_html_extraction(
      &dom,
      &[
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article#feature-1".to_string(),
        "div.feature-meta".to_string(),
        "span.feature-rating".to_string(),
      ],
      ExtractorType::Number,
      Some("data-rating".to_string()),
      json!(4.8),
    );
  }

  #[test]
  fn test_complex_html_error_cases() {
    let html = create_complex_test_html();
    let dom = parse_html(&html);

    // Non-existent element in the middle of the selector path
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section.non-existent".to_string(), "div.features-grid".to_string()],
      ExtractorType::String,
      None,
      |err| matches!(err, ExtractorError::MissingField(_)),
    );

    // Invalid selector syntax - Note: The HTML parser treats invalid selectors as not found
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section[invalid=".to_string()],
      ExtractorType::String,
      None,
      |err| matches!(err, ExtractorError::MissingField(_)),
    );

    // Type mismatch when converting to number
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section.hero-section".to_string(), "h1.hero-title".to_string()],
      ExtractorType::Number,
      None,
      |err| matches!(err, ExtractorError::TypeMismatch { .. }),
    );

    // Empty selector path
    assert_html_extraction_error(&dom, &[], ExtractorType::String, None, |err| {
      matches!(err, ExtractorError::MissingField(_))
    });
  }
}
