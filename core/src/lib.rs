//! # Web Prover Core
//!
//! `web-prover-core` is a foundational crate for creating and validating proofs of web
//! interactions. It provides the core data structures and validation logic needed to create
//! verifiable proofs that specific HTTP requests were made and specific responses were received.
//!
//! ## Overview
//!
//! This crate implements the core functionality for a system that allows users to:
//!
//! 1. Define a "manifest" that specifies expected HTTP requests and responses
//! 2. Execute those requests in a trusted execution environment (TEE)
//! 3. Generate cryptographic proofs that the specified interactions occurred
//! 4. Verify those proofs
//!
//! ## Key Components
//!
//! - **Manifest**: Defines the expected HTTP request and response patterns
//! - **HTTP**: Utilities for parsing and validating HTTP requests and responses
//! - **Proof**: Data structures for representing cryptographic proofs
//! - **Error**: Error types specific to the web prover system
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use web_prover_core::{
//!   http::{ManifestRequest, ManifestResponse},
//!   manifest::Manifest,
//! };
//!
//! // Parse a manifest from JSON
//! let manifest_json = r#"{"request": {...}, "response": {...}}"#;
//! let manifest: Manifest = serde_json::from_str(manifest_json).unwrap();
//!
//! // Validate the manifest
//! manifest.validate().unwrap();
//!
//! // Generate a digest for the manifest
//! let digest = manifest.to_keccak_digest().unwrap();
//! ```
//!
//! ## Modules
//!
//! - [`manifest`](manifest/index.html): Core manifest data structures and validation
//! - [`http`](http/index.html): HTTP request and response handling
//! - [`proof`](proof/index.html): Proof generation and verification
//! - [`error`](error/index.html): Error types for the crate

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

pub mod error;
pub mod http;
pub mod manifest;

pub mod proof;
#[cfg(test)] mod test_utils;
