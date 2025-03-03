use serde_json::Value;
use thiserror::Error;

use crate::parser::predicate::{Comparison, PredicateType};

/// Errors that can occur during extraction operations
#[derive(Debug, Error)]
pub enum ExtractorError {
  /// Error when an unsupported extractor type is provided
  #[error("Unsupported extractor type: {0}")]
  UnsupportedExtractorType(String),

  /// Error when a value doesn't match the expected type
  #[error("Type mismatch: expected {expected}, got {actual}")]
  TypeMismatch { expected: String, actual: String },

  /// Error when a required field is missing
  #[error("Required field not found: {0}")]
  MissingField(String),

  /// Error when a predicate validation fails
  #[error("Predicate validation failed: {0}")]
  PredicateFailure(String),

  /// Error when a JSON path is invalid
  #[error("Invalid path: {0}")]
  InvalidPath(String),

  /// Error when a regex pattern is invalid
  #[error("Invalid regex pattern: {0}")]
  InvalidRegex(String),

  /// Error when JSON parsing fails
  #[error(transparent)]
  JsonError(#[from] serde_json::Error),

  /// Error when an array index is out of bounds
  #[error("Array index {index} out of bounds at path segment {segment}")]
  ArrayIndexOutOfBounds { index: usize, segment: usize },

  /// Error when an array index is not a valid number
  #[error("Invalid array index '{index}' at path segment {segment}")]
  InvalidArrayIndex { index: String, segment: usize },

  /// Error when trying to navigate into a non-navigable value
  #[error("Cannot navigate into {value_type} value at path segment {segment}")]
  NonNavigableValue { value_type: String, segment: usize },

  /// Error when a comparison is not applicable for a predicate type
  #[error("Comparison {comparison:?} not applicable for {predicate_type:?} predicate")]
  InvalidComparison { comparison: Comparison, predicate_type: PredicateType },

  /// Error when a predicate is not applicable for a value type
  #[error("{predicate_type:?} predicate not applicable for type {value_type}")]
  InvalidPredicateForType { predicate_type: PredicateType, value_type: String },

  /// Error when a length value is invalid
  #[error("Invalid length value: {0}")]
  InvalidLengthValue(Value),

  /// Error when a format is invalid for extraction
  #[error("Invalid format for {0} extraction")]
  InvalidFormat(String),

  /// Predicate error
  // TODO: Should this be a standalone error?
  #[error(transparent)]
  PredicateError(#[from] PredicateError),

  /// Error when HTML parsing fails
  #[error("Invalid HTML document: {0}")]
  InvalidHtml(String),

  /// Empty selector
  #[error("Empty selector")]
  EmptySelector,

  /// Selector failed
  #[error("Selector failed: {0}")]
  SelectorFailed(String),
}

/// Errors that can occur during predicate validation
#[derive(Debug, Error)]
pub enum PredicateError {
  /// Value is not equal to expected value
  #[error("Value {actual:?} is not equal to {expected:?}")]
  NotEqual { actual: Value, expected: Value },

  /// Value is equal to expected value (when it shouldn't be)
  #[error("Value {actual:?} is equal to {expected:?}")]
  Equal { actual: Value, expected: Value },

  /// Value is not greater than expected value
  #[error("Value {actual:?} is not greater than {expected:?}")]
  NotGreaterThan { actual: Value, expected: Value },

  /// Value is not less than expected value
  #[error("Value {actual:?} is not less than {expected:?}")]
  NotLessThan { actual: Value, expected: Value },

  /// Value is less than expected value (when it should be greater or equal)
  #[error("Value {actual:?} is less than {expected:?}")]
  LessThan { actual: Value, expected: Value },

  /// Value is greater than expected value (when it should be less or equal)
  #[error("Value {actual:?} is greater than {expected:?}")]
  GreaterThan { actual: Value, expected: Value },

  /// String does not contain expected pattern
  #[error("String '{string}' does not contain '{pattern}'")]
  StringNotContains { string: String, pattern: String },

  /// String contains expected pattern (when it shouldn't)
  #[error("String '{string}' contains '{pattern}'")]
  StringContains { string: String, pattern: String },

  /// Array does not include expected value
  #[error("Array {array:?} does not include {value:?}")]
  ArrayNotIncludes { array: Vec<Value>, value: Value },

  /// Array includes expected value (when it shouldn't)
  #[error("Array {array:?} contains {value:?}")]
  ArrayContains { array: Vec<Value>, value: Value },

  /// Comparison not applicable for given types
  #[error(
    "{comparison:?} comparison not applicable for types {actual_type:?} and {expected_type:?}"
  )]
  InvalidComparison { comparison: Comparison, actual_type: String, expected_type: String },

  /// String does not start with expected prefix
  #[error("String '{string}' does not start with '{prefix}'")]
  StringNotStartsWith { string: String, prefix: String, case_sensitive: bool },

  /// String does not end with expected suffix
  #[error("String '{string}' does not end with '{suffix}'")]
  StringNotEndsWith { string: String, suffix: String, case_sensitive: bool },

  /// Comparison should be handled by array predicate validator
  #[error("Comparison {0:?} should be handled by array predicate validator")]
  ShouldBeHandledByArrayValidator(Comparison),

  /// Predicate not applicable for value type
  #[error("{predicate_type:?} predicate not applicable for type {value_type:?}")]
  InvalidPredicateForType { predicate_type: PredicateType, value_type: String },

  /// Invalid length value
  #[error("Invalid length value: {0:?}")]
  InvalidLengthValue(Value),

  /// Length is not equal to expected length
  #[error("Length {actual} is not equal to {expected}")]
  LengthNotEqual { actual: usize, expected: usize },

  /// Length is equal to expected length (when it shouldn't be)
  #[error("Length {actual} is equal to {expected}")]
  LengthEqual { actual: usize, expected: usize },

  /// Length is not greater than expected length
  #[error("Length {actual} is not greater than {expected}")]
  LengthNotGreaterThan { actual: usize, expected: usize },

  /// Length is not less than expected length
  #[error("Length {actual} is not less than {expected}")]
  LengthNotLessThan { actual: usize, expected: usize },

  /// Length is less than expected length
  #[error("Length {actual} is less than {expected}")]
  LengthLessThan { actual: usize, expected: usize },

  /// Length is greater than expected length
  #[error("Length {actual} is greater than {expected}")]
  LengthGreaterThan { actual: usize, expected: usize },

  /// Comparison not applicable for length predicate
  #[error("Comparison {comparison:?} not applicable for {predicate_type:?} predicate")]
  InvalidLengthComparison { comparison: Comparison, predicate_type: PredicateType },

  /// Regex predicate not applicable for value type
  #[error("Regex predicate not applicable for type {0:?}")]
  RegexNotApplicable(String),

  /// Invalid regex pattern
  #[error("Invalid regex pattern: {0:?}")]
  InvalidRegexPattern(Value),

  /// String does not match regex pattern
  #[error("String '{string}' does not match pattern '{pattern}'")]
  RegexNoMatch { string: String, pattern: String },

  /// String matches regex pattern (when it shouldn't)
  #[error("String '{string}' matches pattern '{pattern}'")]
  RegexMatch { string: String, pattern: String },

  /// Comparison not applicable for regex predicate
  #[error("Comparison {0:?} not applicable for Regex predicate")]
  InvalidRegexComparison(Comparison),

  /// String predicate not applicable for value type
  #[error("String predicate not applicable for type {0:?}")]
  StringPredicateNotApplicable(String),

  /// Invalid prefix value
  #[error("Invalid prefix value: {0:?}")]
  InvalidPrefixValue(Value),

  /// Invalid suffix value
  #[error("Invalid suffix value: {0:?}")]
  InvalidSuffixValue(Value),

  /// Comparison not applicable for string predicate
  #[error("Comparison {0:?} not applicable for String predicate")]
  InvalidStringComparison(Comparison),

  /// Array predicate not applicable for value type
  #[error("Array predicate not applicable for type {0:?}")]
  ArrayPredicateNotApplicable(String),

  /// Cannot apply 'some' predicate to empty array
  #[error("Cannot apply 'some' predicate to empty array")]
  SomePredicateEmptyArray,

  /// No elements in array satisfy the predicate
  #[error("No elements in array {0:?} satisfy the predicate")]
  NoElementsSatisfyPredicate(Vec<Value>),

  /// Not all elements in array satisfy the predicate
  #[error("Not all elements in array satisfy the predicate: {0}")]
  NotAllElementsSatisfyPredicate(String),

  /// Invalid regex error
  #[error("Invalid regex pattern: {0}")]
  RegexError(String),
}
