pub(crate) mod html;
mod json;
mod types;
mod utils;

pub use html::extract_html;
pub use json::extract_json;
pub use types::{ExtractionResult, ExtractionValues, Extractor, ExtractorType};
pub use utils::validate_type;
