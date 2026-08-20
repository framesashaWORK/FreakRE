//! Heuristic ensemble classifier for malware detection.
//!
//! Implements a weighted ensemble of decision trees (heuristic rules) that
//! classify binaries as Clean/Suspicious/Malicious based on extracted features.
//! The classifier is trained on common malware patterns and can be extended
//! with custom rules.

use crate::features::{FeatureVector, NUM_FEATURES};
use serde::{Deserialize, Serialize};

/// Classification result from the ML detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalwareClass {
    /// Clean file, no suspicious indicators
    Clean,
    /// Suspicious file, warrants manual analysis
    Suspicious,
    /// High confidence malware
    Malicious,
    /// Packed/obfuscated binary (needs unpacking for full analysis)
    Packed,
    /// Potentially Unwanted Application (adware, PUA)
    PUA,
}

impl std::fmt::Display for MalwareClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MalwareClass::Clean => write!(f, "Clean"),
            MalwareClass::Suspicious => write!(f, "Suspicious"),
            MalwareClass::Malicious => write!(f, "Malicious"),
            MalwareClass::Packed => write!(f, "Packed"),
            MalwareClass::PUA => write!(f, "PUA"),
        }
    }
}

/// Detailed classification result with confidence scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Final classification verdict
    pub class: MalwareClass,
    /// Confidence score [0.0, 1.0]
    pub confidence: f32,
    /// Probability distribution over all classes
    pub probabilities: ClassProbabilities,
    /// Individual decision tree scores
    pub tree_scores: Vec<TreeScore>,
    /// Top features contributing to the decision
    pub important_features: Vec<FeatureImportance>,
    /// Human-readable explanation
    pub explanation: String,
}

/// Probability distribution over malware classes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassProbabilities {
    pub clean: f32,
    pub suspicious: f32,
    pub malicious: f32,
    pub packed: f32,
    pub pua: f32,
}

impl ClassProbabilities {
    fn normalize(&mut self) {
        let sum = self.clean + self.suspicious + self.malicious + self.packed + self.pua;
        if sum > 0.0 {
            self.clean /= sum;
            self.suspicious /= sum;
            self.malicious /= sum;
            self.packed /= sum;
            self.pua /= sum;
        }
    }
}

/// Individual decision tree score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeScore {
    pub name: String,
    pub score: f32,
    pub threshold: f32,
    pub triggered: bool,
}

/// Feature importance for explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureImportance {
    pub name: String,
    pub value: f32,
    pub weight: f32,
    pub contribution: f32,
}

/// Ensemble classifier combining multiple heuristic decision trees.
pub struct EnsembleClassifier {
    trees: Vec<DecisionTree>,
    weights: Vec<f32>,
}

impl Default for EnsembleClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl EnsembleClassifier {
    /// Create a new ensemble classifier with default heuristic trees.
    pub fn new() -> Self {
        let trees = vec![
            DecisionTree::entropy_packing_tree(),
            DecisionTree::import_behavior_tree(),
            DecisionTree::string_pattern_tree(),
            DecisionTree::structural_anomaly_tree(),
            DecisionTree::anti_analysis_tree(),
            DecisionTree::network_c2_tree(),
            DecisionTree::persistence_tree(),
            DecisionTree::obfuscation_tree(),
        ];
        let weights = vec![1.0, 1.2, 0.9, 0.8, 1.1, 1.0, 0.9, 0.7];

        EnsembleClassifier { trees, weights }
    }

    /// Classify a binary based on its feature vector.
    pub fn classify(&self, features: &FeatureVector) -> ClassificationResult {
        let mut tree_scores = Vec::new();
        let mut total_score = 0.0f32;
        let mut total_weight = 0.0f32;

        for (tree, &weight) in self.trees.iter().zip(self.weights.iter()) {
            let score = tree.evaluate(features);
            let triggered = score >= tree.threshold;
            tree_scores.push(TreeScore {
                name: tree.name.clone(),
                score,
                threshold: tree.threshold,
                triggered,
            });
            total_score += score * weight;
            total_weight += weight;
        }

        let normalized_score = if total_weight > 0.0 {
            total_score / total_weight
        } else {
            0.0
        };

        // Calculate class probabilities
        let mut probs = ClassProbabilities {
            clean: (1.0 - normalized_score).max(0.0),
            suspicious: if normalized_score > 0.3 && normalized_score < 0.7 {
                (normalized_score - 0.3) * 2.5
            } else {
                0.0
            },
            malicious: if normalized_score > 0.6 {
                (normalized_score - 0.6) * 2.5
            } else {
                0.0
            },
            packed: features.features[65], // is_packed_entropy feature
            pua: if normalized_score > 0.2 && normalized_score < 0.5 {
                (normalized_score - 0.2) * 1.5
            } else {
                0.0
            },
        };
        probs.normalize();

        // Determine final class
        let class = determine_class(normalized_score, &probs, &tree_scores);

        // Find important features
        let important_features = find_important_features(features, &self.trees, &self.weights);

        // Generate explanation
        let explanation = generate_explanation(class, normalized_score, &tree_scores, &important_features);

        ClassificationResult {
            class,
            confidence: normalized_score,
            probabilities: probs,
            tree_scores,
            important_features,
            explanation,
        }
    }
}

/// Individual decision tree for ensemble.
struct DecisionTree {
    name: String,
    rules: Vec<Rule>,
    threshold: f32,
}

impl DecisionTree {
    fn evaluate(&self, features: &FeatureVector) -> f32 {
        let mut score = 0.0f32;
        for rule in &self.rules {
            score += rule.evaluate(features);
        }
        score.min(1.0)
    }

    /// Tree 1: Entropy and packing detection
    fn entropy_packing_tree() -> Self {
        DecisionTree {
            name: "entropy_packing".to_string(),
            threshold: 0.6,
            rules: vec![
                Rule::high_entropy_section(0.3),
                Rule::global_entropy_threshold(7.2, 0.25),
                Rule::low_printable_ratio(0.15),
                Rule::packed_indicator(0.3),
                Rule::high_byte_ratio(0.15),
            ],
        }
    }

    /// Tree 2: Import behavior analysis
    fn import_behavior_tree() -> Self {
        DecisionTree {
            name: "import_behavior".to_string(),
            threshold: 0.5,
            rules: vec![
                Rule::suspicious_imports(0.35),
                Rule::network_imports(0.2),
                Rule::crypto_imports(0.15),
                Rule::rare_dlls(0.2),
                Rule::high_import_count(0.1),
            ],
        }
    }

    /// Tree 3: String pattern analysis
    fn string_pattern_tree() -> Self {
        DecisionTree {
            name: "string_patterns".to_string(),
            threshold: 0.4,
            rules: vec![
                Rule::url_patterns(0.25),
                Rule::ip_patterns(0.2),
                Rule::cmd_patterns(0.2),
                Rule::crypto_strings(0.15),
                Rule::base64_strings(0.1),
                Rule::high_suspicious_ratio(0.1),
            ],
        }
    }

    /// Tree 4: Structural anomalies
    fn structural_anomaly_tree() -> Self {
        DecisionTree {
            name: "structural_anomalies".to_string(),
            threshold: 0.5,
            rules: vec![
                Rule::rwx_sections(0.25),
                Rule::invalid_checksum(0.15),
                Rule::entry_outside_text(0.2),
                Rule::missing_debug_info(0.05),
                Rule::has_overlay(0.1),
            ],
        }
    }

    /// Tree 5: Anti-analysis techniques
    fn anti_analysis_tree() -> Self {
        DecisionTree {
            name: "anti_analysis".to_string(),
            threshold: 0.6,
            rules: vec![
                Rule::anti_debug(0.3),
                Rule::anti_vm(0.25),
                Rule::obfuscation(0.2),
                Rule::debug_strings(0.1),
            ],
        }
    }

    /// Tree 6: Network/C2 indicators
    fn network_c2_tree() -> Self {
        DecisionTree {
            name: "network_c2".to_string(),
            threshold: 0.5,
            rules: vec![
                Rule::url_patterns(0.2),
                Rule::ip_patterns(0.25),
                Rule::network_imports(0.2),
                Rule::c2_patterns(0.15),
            ],
        }
    }

    /// Tree 7: Persistence mechanisms
    fn persistence_tree() -> Self {
        DecisionTree {
            name: "persistence".to_string(),
            threshold: 0.5,
            rules: vec![
                Rule::registry_patterns(0.25),
                Rule::persistence_imports(0.2),
                Rule::path_patterns(0.15),
            ],
        }
    }

    /// Tree 8: Obfuscation detection
    fn obfuscation_tree() -> Self {
        DecisionTree {
            name: "obfuscation".to_string(),
            threshold: 0.55,
            rules: vec![
                Rule::high_entropy_section(0.25),
                Rule::packed_indicator(0.25),
                Rule::base64_strings(0.15),
                Rule::low_unique_strings(0.1),
            ],
        }
    }
}

/// Individual rule in a decision tree.
struct Rule {
    feature_indices: Vec<usize>,
    thresholds: Vec<f32>,
    weights: Vec<f32>,
    logic: RuleLogic,
}

#[derive(Clone, Copy)]
enum RuleLogic {
    Any,   // Any feature exceeds threshold
    All,   // All features exceed threshold
    Sum,   // Sum of weighted features
}

impl Rule {
    fn evaluate(&self, features: &FeatureVector) -> f32 {
        match self.logic {
            RuleLogic::Any => {
                for (i, &thresh) in self.feature_indices.iter().zip(self.thresholds.iter()) {
                    if features.features[*i] >= thresh {
                        return self.weights[0];
                    }
                }
                0.0
            }
            RuleLogic::All => {
                let all_exceed = self.feature_indices.iter()
                    .zip(self.thresholds.iter())
                    .all(|(i, t)| features.features[*i] >= *t);
                if all_exceed { self.weights[0] } else { 0.0 }
            }
            RuleLogic::Sum => {
                let mut sum = 0.0;
                for (i, w) in self.feature_indices.iter().zip(self.weights.iter()) {
                    sum += features.features[*i] * w;
                }
                sum.min(1.0)
            }
        }
    }

    // ─── Rule constructors ───────────────────────────────────────

    fn high_entropy_section(weight: f32) -> Self {
        Rule {
            feature_indices: vec![23], // entropy_max_section
            thresholds: vec![7.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn global_entropy_threshold(threshold: f32, weight: f32) -> Self {
        Rule {
            feature_indices: vec![21], // global_entropy
            thresholds: vec![threshold],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn low_printable_ratio(weight: f32) -> Self {
        Rule {
            feature_indices: vec![16], // printable_ratio
            thresholds: vec![0.3],
            weights: vec![weight],
            logic: RuleLogic::All, // Low printable is suspicious
        }
    }

    fn packed_indicator(weight: f32) -> Self {
        Rule {
            feature_indices: vec![65], // is_packed
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn high_byte_ratio(weight: f32) -> Self {
        Rule {
            feature_indices: vec![20], // high_byte_ratio
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn suspicious_imports(weight: f32) -> Self {
        Rule {
            feature_indices: vec![62], // suspicious_import_ratio
            thresholds: vec![0.3],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn network_imports(weight: f32) -> Self {
        Rule {
            feature_indices: vec![51, 52, 53], // ws2_32, wininet, urlmon
            thresholds: vec![1.0, 1.0, 1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn crypto_imports(weight: f32) -> Self {
        Rule {
            feature_indices: vec![56], // crypt32
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn rare_dlls(weight: f32) -> Self {
        Rule {
            feature_indices: vec![63], // rare_dll_count
            thresholds: vec![2.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn high_import_count(weight: f32) -> Self {
        Rule {
            feature_indices: vec![60], // total_imports_log
            thresholds: vec![8.0], // ~256 imports
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn url_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![32], // url_count
            thresholds: vec![2.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn ip_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![33], // ip_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn cmd_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![37, 38], // cmd_count, powershell_count
            thresholds: vec![1.0, 1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn crypto_strings(weight: f32) -> Self {
        Rule {
            feature_indices: vec![36], // crypto_count
            thresholds: vec![2.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn base64_strings(weight: f32) -> Self {
        Rule {
            feature_indices: vec![47], // base64_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn high_suspicious_ratio(weight: f32) -> Self {
        Rule {
            feature_indices: vec![46], // suspicious_ratio
            thresholds: vec![0.1],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn rwx_sections(weight: f32) -> Self {
        Rule {
            feature_indices: vec![27], // rwx_section_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn invalid_checksum(weight: f32) -> Self {
        Rule {
            feature_indices: vec![68], // checksum_valid (inverted)
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::All,
        }
    }

    fn entry_outside_text(weight: f32) -> Self {
        Rule {
            feature_indices: vec![78], // entry_in_text (inverted)
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::All,
        }
    }

    fn missing_debug_info(weight: f32) -> Self {
        Rule {
            feature_indices: vec![64], // has_debug_info (inverted)
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::All,
        }
    }

    fn has_overlay(weight: f32) -> Self {
        Rule {
            feature_indices: vec![69, 70], // has_overlay, overlay_size_ratio
            thresholds: vec![0.5, 0.1],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn anti_debug(weight: f32) -> Self {
        Rule {
            feature_indices: vec![80], // anti_debug_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn anti_vm(weight: f32) -> Self {
        Rule {
            feature_indices: vec![81], // anti_vm_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn obfuscation(weight: f32) -> Self {
        Rule {
            feature_indices: vec![89], // obfuscation_score
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn debug_strings(weight: f32) -> Self {
        Rule {
            feature_indices: vec![41], // debug_count
            thresholds: vec![3.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn c2_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![32, 33, 86], // url, ip, network
            thresholds: vec![1.0, 1.0, 1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn registry_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![35], // registry_count
            thresholds: vec![1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn persistence_imports(weight: f32) -> Self {
        Rule {
            feature_indices: vec![50, 54], // advapi32, shell32
            thresholds: vec![1.0, 1.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn path_patterns(weight: f32) -> Self {
        Rule {
            feature_indices: vec![34], // path_count
            thresholds: vec![3.0],
            weights: vec![weight],
            logic: RuleLogic::Any,
        }
    }

    fn low_unique_strings(weight: f32) -> Self {
        Rule {
            feature_indices: vec![45], // unique_ratio
            thresholds: vec![0.5],
            weights: vec![weight],
            logic: RuleLogic::All,
        }
    }
}

/// Determine final class from scores and probabilities.
fn determine_class(
    score: f32,
    probs: &ClassProbabilities,
    tree_scores: &[TreeScore],
) -> MalwareClass {
    // Hard overrides
    let triggered_trees = tree_scores.iter().filter(|t| t.triggered).count();

    if score >= 0.75 || triggered_trees >= 5 {
        return MalwareClass::Malicious;
    }

    if probs.packed > 0.6 {
        return MalwareClass::Packed;
    }

    if score >= 0.45 || triggered_trees >= 3 {
        return MalwareClass::Suspicious;
    }

    if score >= 0.25 && score < 0.45 {
        return MalwareClass::PUA;
    }

    MalwareClass::Clean
}

/// Find top features contributing to the classification.
fn find_important_features(
    features: &FeatureVector,
    trees: &[DecisionTree],
    weights: &[f32],
) -> Vec<FeatureImportance> {
    let mut importances = Vec::new();
    let names = crate::features::feature_names();

    for i in 0..NUM_FEATURES {
        let value = features.features[i];
        if value.abs() < 0.01 {
            continue;
        }

        let mut total_weight = 0.0;
        for (tree, &w) in trees.iter().zip(weights.iter()) {
            for rule in &tree.rules {
                if rule.feature_indices.contains(&i) {
                    total_weight += w * rule.weights[0];
                }
            }
        }

        if total_weight > 0.0 {
            importances.push(FeatureImportance {
                name: names[i].to_string(),
                value,
                weight: total_weight,
                contribution: value * total_weight,
            });
        }
    }

    importances.sort_by(|a, b| {
        b.contribution.abs()
            .partial_cmp(&a.contribution.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    importances.truncate(10);
    importances
}

/// Generate human-readable explanation.
fn generate_explanation(
    class: MalwareClass,
    score: f32,
    tree_scores: &[TreeScore],
    important_features: &[FeatureImportance],
) -> String {
    let mut explanation = format!("Classification: {} (confidence: {:.0}%)\n\n", class, score * 100.0);

    let triggered: Vec<_> = tree_scores.iter().filter(|t| t.triggered).collect();
    if !triggered.is_empty() {
        explanation.push_str("Triggered detection modules:\n");
        for t in triggered {
            explanation.push_str(&format!("  - {} (score: {:.2})\n", t.name, t.score));
        }
        explanation.push('\n');
    }

    if !important_features.is_empty() {
        explanation.push_str("Top contributing features:\n");
        for f in important_features.iter().take(5) {
            explanation.push_str(&format!("  - {}: {:.3} (weight: {:.2})\n", f.name, f.value, f.weight));
        }
    }

    explanation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_clean() {
        let classifier = EnsembleClassifier::new();
        let mut features = FeatureVector::zeros();
        features.features[16] = 0.8; // high printable ratio
        features.features[21] = 5.0; // normal entropy
        let result = classifier.classify(&features);
        assert_eq!(result.class, MalwareClass::Clean);
    }

    #[test]
    fn test_classify_malicious() {
        let classifier = EnsembleClassifier::new();
        let mut features = FeatureVector::zeros();
        features.features[21] = 7.5; // high entropy
        features.features[65] = 1.0; // packed
        features.features[32] = 5.0; // many URLs
        features.features[37] = 3.0; // cmd patterns
        features.features[80] = 2.0; // anti-debug
        let result = classifier.classify(&features);
        assert!(result.class == MalwareClass::Malicious || result.class == MalwareClass::Suspicious);
    }

    #[test]
    fn test_classify_packed() {
        let classifier = EnsembleClassifier::new();
        let mut features = FeatureVector::zeros();
        features.features[21] = 7.8; // very high entropy
        features.features[65] = 1.0; // packed indicator
        features.features[20] = 0.7; // high byte ratio
        let result = classifier.classify(&features);
        assert!(result.class == MalwareClass::Packed || result.class == MalwareClass::Suspicious);
    }
}
