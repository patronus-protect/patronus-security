// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one table that maps output labels of the L2/L3 threat models onto the
//! attack-class categories. The models keep their trained label names; those
//! names appear only here, as model-output keys, never in the API, the result
//! schema or the configuration.
use crate::SecurityCategory;

/// Where one model output label lands: its category and, where the label is
/// narrower than the category, the family within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelLabelClass {
    pub category: SecurityCategory,
    pub family: Option<&'static str>,
}

/// Model output label → attack class. The benign label maps to no category.
/// Labels of the unified threat head (L3) and of its NTDB L2 head are the same.
const MODEL_LABELS: [(&str, SecurityCategory, Option<&str>); 6] = [
    ("instruction_override", SecurityCategory::Injection, None),
    (
        "secrets_access",
        SecurityCategory::UnsafeAction,
        Some("credential_access"),
    ),
    ("tool_abuse", SecurityCategory::UnsafeAction, None),
    ("harmful_behavior", SecurityCategory::HarmfulContent, None),
    ("exfiltration_attempt", SecurityCategory::Exfiltration, None),
    ("toxic_or_harmful", SecurityCategory::ToxicLanguage, None),
];

/// The attack class of a threat-model output label; `None` for `benign` and
/// for labels the table does not know.
pub fn model_label_class(label: &str) -> Option<ModelLabelClass> {
    MODEL_LABELS
        .iter()
        .find(|(name, _, _)| *name == label)
        .map(|&(_, category, family)| ModelLabelClass { category, family })
}

/// The threat-model output labels that land in `category`.
pub fn model_labels_for(category: SecurityCategory) -> impl Iterator<Item = &'static str> {
    MODEL_LABELS
        .iter()
        .filter(move |(_, target, _)| *target == category)
        .map(|(name, _, _)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_threat_model_label_has_exactly_one_attack_class() {
        for (label, category, _) in MODEL_LABELS {
            assert!(SecurityCategory::ATTACK_CLASSES.contains(&category), "{label}");
            assert_eq!(
                MODEL_LABELS.iter().filter(|(l, _, _)| *l == label).count(),
                1
            );
        }
        assert_eq!(model_label_class("benign"), None);
    }

    #[test]
    fn secrets_access_is_credential_access_of_unsafe_action() {
        assert_eq!(
            model_label_class("secrets_access"),
            Some(ModelLabelClass {
                category: SecurityCategory::UnsafeAction,
                family: Some("credential_access"),
            })
        );
        assert_eq!(
            model_labels_for(SecurityCategory::UnsafeAction).collect::<Vec<_>>(),
            ["secrets_access", "tool_abuse"]
        );
    }

    #[test]
    fn model_label_names_are_never_categories() {
        for (label, _, _) in MODEL_LABELS {
            assert!(label.parse::<SecurityCategory>().is_err(), "{label}");
        }
    }
}
