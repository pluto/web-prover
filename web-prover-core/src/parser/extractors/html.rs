use std::collections::HashMap;

use serde_json::Value;
use tl::{Node, NodeHandle, Parser, ParserOptions, VDom};

use crate::parser::{
  extractors::extractor, predicate, DataFormat, ExtractionResult, Extractor, ExtractorConfig,
  ExtractorError, ExtractorType,
};

/// Extracts data from HTML using CSS selectors
pub fn extract_html(
  html_str: &str,
  config: &ExtractorConfig,
) -> Result<ExtractionResult, ExtractorError> {
  if config.format != DataFormat::Html {
    return Err(ExtractorError::InvalidFormat("HTML".to_string()));
  }

  let mut result = ExtractionResult { values: HashMap::new(), errors: Vec::new() };

  // Parse the HTML document
  let dom = tl::parse(html_str, ParserOptions::default())
    .map_err(|_| ExtractorError::InvalidFormat("Failed to parse HTML".to_string()))?;

  for extractor in &config.extractors {
    match extract_html_value(&dom, &extractor.selector, extractor) {
      Ok(value) => {
        // Validate the type
        if let Err(type_err) = extractor::validate_type(&value, &extractor.extractor_type) {
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
    .into_iter()
    .filter(|_| true)
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
    .map_or_else(|| Value::String("".to_string()), |value| Value::String(value))
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
        el.get(dom.parser()).map(|node| {
          if let Some(attr) = &extractor.attribute {
            if let Some(tag) = node.as_tag() {
              if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
                if let Some(value) = attr_value {
                  return Value::String(value.as_utf8_str().to_string());
                }
              }
            }
            Value::String("".to_string()) // Return empty string if attribute not found
          } else {
            Value::String(node.inner_text(dom.parser()).to_string())
          }
        })
      })
      .collect();
    return Ok(Value::Array(values));
  }

  // For non-array types, use the first element
  let element = &elements[0];

  // Extract the raw value (either attribute or text content)
  let raw_value = if let Some(attr) = &extractor.attribute {
    if let Some(node) = element.get(dom.parser()) {
      if let Some(tag) = node.as_tag() {
        if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
          if let Some(value) = attr_value {
            value.as_utf8_str().to_string()
          } else {
            "".to_string()
          }
        } else {
          "".to_string()
        }
      } else {
        "".to_string()
      }
    } else {
      "".to_string()
    }
  } else if let Some(node) = element.get(dom.parser()) {
    node.inner_text(dom.parser()).to_string()
  } else {
    "".to_string()
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
  use tl::{ParserOptions, VDom};

  use super::*;
  use crate::{
    extractor,
    parser::{
      extractors::html::{extract_html, extract_html_value},
      DataFormat, Extractor, ExtractorConfig, ExtractorError, ExtractorType,
    },
  };

  fn create_test_html() -> String {
    r#"
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
      "#
    .to_string()
  }

  fn parse_test_html(html: &str) -> VDom {
    tl::parse(html, ParserOptions::default()).expect("Failed to parse HTML")
  }

  #[test]
  fn test_html_extract_basic_text() {
    let html = create_test_html();
    let dom = parse_test_html(&html);

    let extractor = extractor!(
        id: "title".to_string(),
        description: "Main title".to_string(),
        selector: vec!["#main-title".to_string()],
        extractor_type: ExtractorType::String
    );
    let result = extract_html_value(&dom, &["#main-title".to_string()], &extractor).unwrap();
    assert_eq!(result, json!("Hello, World!"));
  }

  #[test]
  fn test_html_extraction_errors() {
    let html = create_test_html();
    let dom = parse_test_html(&html);

    let basic_extractor = extractor!(
      id: "test".to_string(),
      description: "Test extractor".to_string(),
      extractor_type: ExtractorType::String
    );

    // Test invalid CSS selector
    let result = extract_html_value(&dom, &["#[invalid".to_string()], &basic_extractor);
    assert!(result.is_err());
    assert!(matches!(result, Err(ExtractorError::InvalidPath(_))));

    // Test non-existent element
    let result = extract_html_value(&dom, &["#non-existent".to_string()], &basic_extractor);
    assert!(result.is_err());
    assert!(matches!(result, Err(ExtractorError::MissingField(_))));

    // Test empty selector path
    let result = extract_html_value(&dom, &[], &basic_extractor);
    assert!(result.is_err());
    assert!(matches!(result, Err(ExtractorError::MissingField(_))));

    // Test attribute extraction error
    let attr_extractor = extractor!(
      id: "test".to_string(),
      description: "Test extractor".to_string(),
      selector: vec!["#main-title".to_string()],
      extractor_type: ExtractorType::String,
      attribute: Some("non-existent".to_string())
    );
    let result = extract_html_value(&dom, &["#main-title".to_string()], &attr_extractor);
    // With our new implementation, missing attributes return an empty string instead of an error
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!(""));
  }

  #[test]
  fn test_extract_html_with_multiple_extractors() {
    let html = create_complex_test_html();

    // Create a config with multiple extractors using different selector paths
    let config = ExtractorConfig {
      format:     DataFormat::Html,
      extractors: vec![
        // Single selector extractors
        create_test_extractor("page_title", vec!["title".to_string()], ExtractorType::String, None),
        create_test_extractor(
          "meta_description",
          vec!["meta[name='description']".to_string()],
          ExtractorType::String,
          Some("content".to_string()),
        ),
        // Multi-selector extractors
        create_test_extractor(
          "hero_title",
          vec!["main".to_string(), "section.hero-section".to_string(), "h1.hero-title".to_string()],
          ExtractorType::String,
          None,
        ),
        // Array extractors
        create_test_extractor(
          "feature_titles",
          vec![
            "main".to_string(),
            "section.features-section".to_string(),
            "div.features-grid".to_string(),
            "article.feature-card".to_string(),
            "h3.feature-title".to_string(),
          ],
          ExtractorType::Array,
          None,
        ),
        // Attribute extractors
        create_test_extractor(
          "feature_ratings",
          vec![
            "main".to_string(),
            "section.features-section".to_string(),
            "div.features-grid".to_string(),
            "article.feature-card".to_string(),
            "div.feature-meta".to_string(),
            "span.feature-rating".to_string(),
          ],
          ExtractorType::Array,
          Some("data-rating".to_string()),
        ),
        // Numeric extractors
        create_test_extractor(
          "first_rating",
          vec![
            "main".to_string(),
            "section.features-section".to_string(),
            "div.features-grid".to_string(),
            "article#feature-1".to_string(),
            "div.feature-meta".to_string(),
            "span.feature-rating".to_string(),
          ],
          ExtractorType::Number,
          Some("data-rating".to_string()),
        ),
      ],
    };

    // Extract all values
    let result = extract_html(&html, &config).unwrap();

    // Verify all extractions were successful
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

    // Check attribute array values
    let feature_ratings = result.values["feature_ratings"].as_array().unwrap();
    assert_eq!(feature_ratings.len(), 3);
    assert!(feature_ratings.contains(&json!("4.8")));
    assert!(feature_ratings.contains(&json!("4.9")));
    assert!(feature_ratings.contains(&json!("4.7")));

    // Check numeric value
    assert_eq!(result.values["first_rating"], json!(4.8));
  }

  fn create_complex_test_html() -> String {
    r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Complex Test Page</title>
          <meta name="description" content="A complex test page for HTML extraction">
          <meta property="og:title" content="Complex Test Page">
          <meta property="og:description" content="Testing complex HTML extraction">
        </head>
        <body>
          <div class="container">
            <header class="main-header">
              <div class="logo-wrapper">
                <a href="/" class="logo">
                  <img src="/logo.png" alt="Logo" width="100" height="50" data-test="logo-image">
                </a>
              </div>
              <nav class="main-nav">
                <ul class="nav-list">
                  <li class="nav-item"><a href="/" class="nav-link active" data-section="home">Home</a></li>
                  <li class="nav-item"><a href="/products" class="nav-link" data-section="products">Products</a></li>
                  <li class="nav-item dropdown">
                    <a href="/services" class="nav-link" data-section="services">Services</a>
                    <ul class="dropdown-menu">
                      <li class="dropdown-item"><a href="/services/consulting">Consulting</a></li>
                      <li class="dropdown-item"><a href="/services/development">Development</a></li>
                      <li class="dropdown-item"><a href="/services/training">Training</a></li>
                    </ul>
                  </li>
                  <li class="nav-item"><a href="/about" class="nav-link" data-section="about">About</a></li>
                  <li class="nav-item"><a href="/contact" class="nav-link" data-section="contact">Contact</a></li>
                </ul>
              </nav>
              <div class="search-wrapper">
                <form class="search-form" action="/search" method="get">
                  <input type="text" name="q" placeholder="Search..." class="search-input">
                  <button type="submit" class="search-button">Search</button>
                </form>
              </div>
            </header>

            <main class="main-content">
              <section class="hero-section">
                <h1 class="hero-title">Welcome to Our Complex Test Page</h1>
                <p class="hero-subtitle">Testing nested selectors and complex HTML structures</p>
                <div class="cta-container">
                  <a href="/signup" class="cta-button primary">Sign Up</a>
                  <a href="/learn-more" class="cta-button secondary">Learn More</a>
                </div>
              </section>

              <section class="features-section">
                <h2 class="section-title">Features</h2>
                <div class="features-grid">
                  <article class="feature-card" id="feature-1">
                    <div class="feature-icon">
                      <i class="icon icon-speed"></i>
                    </div>
                    <h3 class="feature-title">Lightning Fast</h3>
                    <p class="feature-description">Our solution is optimized for maximum performance.</p>
                    <a href="/features/speed" class="feature-link">Learn more about speed</a>
                    <div class="feature-meta">
                      <span class="feature-rating" data-rating="4.8">4.8</span>
                      <span class="feature-category">Performance</span>
                    </div>
                  </article>

                  <article class="feature-card" id="feature-2">
                    <div class="feature-icon">
                      <i class="icon icon-secure"></i>
                    </div>
                    <h3 class="feature-title">Highly Secure</h3>
                    <p class="feature-description">Enterprise-grade security for your peace of mind.</p>
                    <a href="/features/security" class="feature-link">Learn more about security</a>
                    <div class="feature-meta">
                      <span class="feature-rating" data-rating="4.9">4.9</span>
                      <span class="feature-category">Security</span>
                    </div>
                  </article>

                  <article class="feature-card" id="feature-3">
                    <div class="feature-icon">
                      <i class="icon icon-scale"></i>
                    </div>
                    <h3 class="feature-title">Infinitely Scalable</h3>
                    <p class="feature-description">Grows with your business without compromises.</p>
                    <a href="/features/scalability" class="feature-link">Learn more about scalability</a>
                    <div class="feature-meta">
                      <span class="feature-rating" data-rating="4.7">4.7</span>
                      <span class="feature-category">Scalability</span>
                    </div>
                  </article>
                </div>
              </section>

              <section class="testimonials-section">
                <h2 class="section-title">What Our Customers Say</h2>
                <div class="testimonials-slider">
                  <div class="testimonial-slide" id="testimonial-1">
                    <blockquote class="testimonial-quote">
                      <p>This product has completely transformed our business operations.</p>
                    </blockquote>
                    <div class="testimonial-author">
                      <img src="/avatars/jane.jpg" alt="Jane Doe" class="testimonial-avatar">
                      <div class="testimonial-info">
                        <cite class="testimonial-name">Jane Doe</cite>
                        <span class="testimonial-position">CEO, Example Corp</span>
                      </div>
                    </div>
                  </div>

                  <div class="testimonial-slide" id="testimonial-2">
                    <blockquote class="testimonial-quote">
                      <p>The best solution we've found after trying dozens of alternatives.</p>
                    </blockquote>
                    <div class="testimonial-author">
                      <img src="/avatars/john.jpg" alt="John Smith" class="testimonial-avatar">
                      <div class="testimonial-info">
                        <cite class="testimonial-name">John Smith</cite>
                        <span class="testimonial-position">CTO, Another Company</span>
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            </main>

            <footer class="main-footer">
              <div class="footer-columns">
                <div class="footer-column">
                  <h4 class="footer-title">Company</h4>
                  <ul class="footer-links">
                    <li><a href="/about">About Us</a></li>
                    <li><a href="/careers">Careers</a></li>
                    <li><a href="/press">Press</a></li>
                  </ul>
                </div>

                <div class="footer-column">
                  <h4 class="footer-title">Resources</h4>
                  <ul class="footer-links">
                    <li><a href="/blog">Blog</a></li>
                    <li><a href="/guides">Guides</a></li>
                    <li><a href="/webinars">Webinars</a></li>
                  </ul>
                </div>

                <div class="footer-column">
                  <h4 class="footer-title">Legal</h4>
                  <ul class="footer-links">
                    <li><a href="/terms">Terms of Service</a></li>
                    <li><a href="/privacy">Privacy Policy</a></li>
                    <li><a href="/cookies">Cookie Policy</a></li>
                  </ul>
                </div>

                <div class="footer-column">
                  <h4 class="footer-title">Connect</h4>
                  <div class="social-links">
                    <a href="https://twitter.com/example" class="social-link" aria-label="Twitter">
                      <i class="icon icon-twitter"></i>
                    </a>
                    <a href="https://facebook.com/example" class="social-link" aria-label="Facebook">
                      <i class="icon icon-facebook"></i>
                    </a>
                    <a href="https://linkedin.com/company/example" class="social-link" aria-label="LinkedIn">
                      <i class="icon icon-linkedin"></i>
                    </a>
                  </div>
                </div>
              </div>

              <div class="footer-bottom">
                <p class="copyright">&copy; 2023 Example Company. All rights reserved.</p>
                <div class="language-selector">
                  <select name="language" id="language-select">
                    <option value="en">English</option>
                    <option value="es">Español</option>
                    <option value="fr">Français</option>
                    <option value="de">Deutsch</option>
                  </select>
                </div>
              </div>
            </footer>
          </div>
        </body>
        </html>
      "#
            .to_string()
  }

  fn parse_complex_test_html(html: &str) -> VDom {
    tl::parse(html, ParserOptions::default()).expect("Failed to parse complex HTML")
  }

  // Helper function to create an extractor with common defaults
  fn create_test_extractor(
    id: &str,
    selector_path: Vec<String>,
    extractor_type: ExtractorType,
    attribute: Option<String>,
  ) -> Extractor {
    Extractor {
      id: id.to_string(),
      description: format!("Test extractor for {}", id),
      selector: selector_path,
      extractor_type,
      required: true,
      predicates: vec![],
      attribute,
    }
  }

  // Helper function to test extraction and assert the result
  fn assert_html_extraction(
    dom: &VDom,
    selector_path: &[String],
    extractor_type: ExtractorType,
    attribute: Option<String>,
    expected_value: Value,
  ) {
    let extractor =
      create_test_extractor("test", selector_path.to_vec(), extractor_type, attribute);
    let result = extract_html_value(dom, selector_path, &extractor);
    assert!(result.is_ok(), "Extraction failed: {:?}", result.err());
    assert_eq!(result.unwrap(), expected_value);
  }

  // Helper function to test extraction errors
  fn assert_html_extraction_error(
    dom: &VDom,
    selector_path: &[String],
    extractor_type: ExtractorType,
    attribute: Option<String>,
    expected_error_type: fn(ExtractorError) -> bool,
  ) {
    let extractor =
      create_test_extractor("test", selector_path.to_vec(), extractor_type, attribute);
    let result = extract_html_value(dom, selector_path, &extractor);
    assert!(result.is_err(), "Expected error but got: {:?}", result.ok());
    let err = result.err().unwrap();
    assert!(expected_error_type(err), "Unexpected error type");
  }

  #[test]
  fn test_complex_html_with_long_selectors() {
    let html = create_complex_test_html();
    let dom = parse_complex_test_html(&html);

    // Test 1: Extract feature title with a long selector path
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

    // Test 2: Extract feature rating with attribute
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

    // Test 3: Extract all feature titles as an array
    let extractor = create_test_extractor(
      "feature_titles",
      vec![
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article.feature-card".to_string(),
        "h3.feature-title".to_string(),
      ],
      ExtractorType::Array,
      None,
    );

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

    // Test 4: Extract all feature ratings as numbers
    let extractor = create_test_extractor(
      "feature_ratings",
      vec![
        "main".to_string(),
        "section.features-section".to_string(),
        "div.features-grid".to_string(),
        "article.feature-card".to_string(),
        "div.feature-meta".to_string(),
        "span.feature-rating".to_string(),
      ],
      ExtractorType::Array,
      Some("data-rating".to_string()),
    );

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
    let dom = parse_complex_test_html(&html);

    // Test 1: Extract meta tags with property attributes
    let extractor = create_test_extractor(
      "og_title",
      vec!["head".to_string(), "meta[property='og:title']".to_string()],
      ExtractorType::String,
      Some("content".to_string()),
    );

    let result = extract_html_value(
      &dom,
      &["head".to_string(), "meta[property='og:title']".to_string()],
      &extractor,
    )
    .unwrap();

    assert_eq!(result, json!("Complex Test Page"));

    // Test 2: Extract elements with data attributes
    let extractor = create_test_extractor(
      "active_nav",
      vec!["nav.main-nav".to_string(), "a.active".to_string()],
      ExtractorType::String,
      Some("data-section".to_string()),
    );

    let result =
      extract_html_value(&dom, &["nav.main-nav".to_string(), "a.active".to_string()], &extractor)
        .unwrap();

    assert_eq!(result, json!("home"));

    // Test 3: Extract deeply nested elements with multiple class selectors
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

    // Test 4: Extract elements with numeric conversion
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
    let dom = parse_complex_test_html(&html);

    // Test 1: Non-existent element in the middle of the selector path
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section.non-existent".to_string(), "div.features-grid".to_string()],
      ExtractorType::String,
      None,
      |err| matches!(err, ExtractorError::MissingField(_)),
    );

    // Test 2: Invalid selector syntax - Note: The HTML parser treats invalid selectors as not
    // found
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section[invalid=".to_string()],
      ExtractorType::String,
      None,
      |err| matches!(err, ExtractorError::MissingField(_)),
    );

    // Test 3: Type mismatch when converting to number
    assert_html_extraction_error(
      &dom,
      &["main".to_string(), "section.hero-section".to_string(), "h1.hero-title".to_string()],
      ExtractorType::Number,
      None,
      |err| matches!(err, ExtractorError::TypeMismatch { .. }),
    );

    // Test 4: Empty selector path
    assert_html_extraction_error(&dom, &[], ExtractorType::String, None, |err| {
      matches!(err, ExtractorError::MissingField(_))
    });
  }
}
