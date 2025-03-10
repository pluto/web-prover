//! Parser module for extracting and validating data.
//!
//! This module provides functionality for extracting data from various sources
//! and validating it against predicates. It includes:
//!
//! - Extractors for different data formats (JSON, HTML)
//! - Predicates for validating extracted data
//! - Error types for handling extraction and validation failures
//!
//! The main entry points are the `Extractor` trait and its implementations.

mod config;
mod error;
pub mod predicate;

mod extractors;
#[cfg(test)] mod test_fixtures;
#[cfg(test)] mod test_utils;

// Re-export public types from submodules
pub use config::{DataFormat, ExtractorConfig};
pub use error::{ExtractorError, ExtractorErrorWithId, PredicateError};
pub use extractors::{
  DocumentExtractor, ExtractionResult, ExtractionValues, Extractor, ExtractorType,
  HtmlDocumentExtractor, JsonDocumentExtractor,
};
