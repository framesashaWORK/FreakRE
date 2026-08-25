#![allow(dead_code, unused_assignments)]
//! # ml-detection
//!
//! Heuristic malware classification engine for Bibleteks.
//!
//! Despite the crate name, this is **not** machine learning: it is a
//! hand-tuned ensemble of weighted heuristic decision trees that score a
//! binary's extracted features. All tree weights and thresholds were set
//! manually from common malware patterns — nothing here is trained on data.
//!
//! ## Architecture
//!
//! ```text
//! Binary ──→ Feature Extraction (96 features)
//!                ↓
//!    Heuristic Ensemble (8 hand-tuned decision trees)
//!                ↓
//!         ┌──────────────────┐
//!         │  Clean           │
//!         │  Suspicious      │
//!         │  Malicious       │
//!         │  Packed          │
//!         │  PUA             │
//!         └──────────────────┘
//! ```
//!
//! ## Roadmap
//!
//! A future iteration may replace the hand-tuned ensemble with a real,
//! trained ML model (e.g. gradient-boosted trees over the same feature
//! vector). Until then, treat all verdicts as heuristic signals that
//! warrant manual review, not model predictions.
//!
//! ## Quick Start
//!
//! ```rust
//! use ml_detection::{EnsembleClassifier, extract_features, BinaryInfo};
//!
//! let data: Vec<u8> = std::fs::read("malware.exe").unwrap_or_else(|_| vec![0x4D, 0x5A, 0x90, 0x00]);
//! let info = BinaryInfo::default(); // populate from PE/ELF parsing
//! let features = extract_features(&data, &info);
//!
//! let classifier = EnsembleClassifier::new();
//! let result = classifier.classify(&features);
//!
//! println!("Classification: {} ({:.0}% confidence)",
//!          result.class, result.confidence * 100.0);
//! println!("{}", result.explanation);
//! ```

pub mod features;
pub mod classifier;

pub use features::{
    extract_features, FeatureVector, BinaryInfo, StringPatterns,
    ImportStats, BehavioralStats, NUM_FEATURES,
};
pub use classifier::{
    EnsembleClassifier, ClassificationResult, MalwareClass,
    ClassProbabilities, TreeScore, FeatureImportance,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MlDetectionError {
    #[error("Feature extraction failed: {0}")]
    FeatureExtractionError(String),
    #[error("Classification failed: {0}")]
    ClassificationError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, MlDetectionError>;


