mod html;
mod json;
mod types;

pub use html::extract_html;
pub use json::{extract_json, get_value_type};
pub use types::{ExtractionResult, ExtractionValues, Extractor, ExtractorType};
