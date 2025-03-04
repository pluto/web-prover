mod extractor;
pub(crate) mod html;
mod json;

pub use extractor::{ExtractionResult, ExtractionValues, Extractor, ExtractorType};
pub use html::extract_html;
pub use json::extract_json;
