mod html;
mod json;
mod types;

pub use html::HtmlDocumentExtractor;
pub use json::{get_value_type, JsonDocumentExtractor};
pub use types::{DocumentExtractor, ExtractionResult, ExtractionValues, Extractor, ExtractorType};
