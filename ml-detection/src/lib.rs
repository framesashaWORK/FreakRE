#![allow(dead_code, unused_assignments)]
//! # ml-detection
//!
//! ML-based malware classification engine for Bibleteks.
//!
//! Provides feature extraction from binaries and an ensemble classifier
//! that combines multiple heuristic decision trees for accurate
//! malware detection.
//!
//! ## Architecture
//!
//! ```text
//! Binary ──→ Feature Extraction (96 features)
//!                ↓
//!         Ensemble Classifier (8 decision trees)
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
//! ## Quick Start
//!
//! ```rust
//! use ml_detection::{EnsembleClassifier, extract_features, BinaryInfo};
//!
//! let data = std::fs::read("malware.exe").unwrap();
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


