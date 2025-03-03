mod config;
mod errors;
mod predicate;

mod extractors;
#[cfg(test)] mod test_fixtures;
#[cfg(test)] mod test_utils;

pub use config::{DataFormat, ExtractorConfig};
pub use errors::ExtractorError;
pub use extractors::{
  DocumentExtractor, ExtractionResult, ExtractionValues, Extractor, ExtractorType,
  HtmlDocumentExtractor, JsonDocumentExtractor,
};
