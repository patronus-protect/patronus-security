// SPDX-License-Identifier: MIT OR Apache-2.0
use super::NativeGates;
use crate::detectors::NativeDetector;
use crate::{
    detectors::{dlp, injection::*, mcp, pii, NativeDetection},
    threat::NativeText,
    SecurityCategory,
};

type Detect = Box<dyn Fn(&NativeText<'_>, &NativeGates) -> NativeDetection + Send + Sync>;

/// An opaque producer and its shared outer gates. Pipeline state lives with the spec.
pub struct NativeProducerSpec {
    category: SecurityCategory,
    id: &'static str,
    parent: Option<&'static str>,
    rule: Option<&'static str>,
    detect: Detect,
}

impl NativeProducerSpec {
    pub fn id(&self) -> &'static str {
        self.id
    }
    pub fn category(&self) -> SecurityCategory {
        self.category
    }

    /// Parent/model/required-rule gates, independent of host level or conditional gates.
    pub fn enabled(&self, gates: &NativeGates) -> bool {
        self.parent.is_none_or(|id| gates.allows_model(id))
            && gates.allows_model(self.id)
            && self.rule.is_none_or(|id| gates.allows_rule(id))
    }

    pub(super) fn detect(&self, text: &NativeText<'_>, gates: &NativeGates) -> NativeDetection {
        (self.detect)(text, gates)
    }
}

/// Producers of one native category; see [`super::NATIVE_CATEGORIES`].
pub(super) fn producers(category: SecurityCategory) -> Vec<NativeProducerSpec> {
    let mut specs = Vec::new();
    macro_rules! add {
        ($ty:path, $id:literal, $parent:expr, $rule:expr) => {{
            let pipeline = <$ty>::new();
            specs.push(NativeProducerSpec {
                category,
                id: $id,
                parent: $parent,
                rule: $rule,
                detect: Box::new(move |prepared, _gates| pipeline.detect_prepared(prepared)),
            });
        }};
    }
    match category {
        SecurityCategory::Pii => {
            let pipeline = pii::pii::PiiPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:pii",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, gates| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| gates.allows_rule(id),
                        gates.explain,
                        gates.pii_mode,
                    )
                }),
            });
        }
        SecurityCategory::Dlp => {
            let pipeline = dlp::dlp::DlpPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:dlp",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, gates| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| gates.allows_rule(id),
                        gates.explain,
                        gates.dlp_mode,
                    )
                }),
            });
            add!(
                dlp::sensitive_material::SensitiveMaterialPipeline,
                "native:sensitive_material",
                None,
                Some("dlp_sensitive_material")
            );
            add!(
                dlp::secret_transfer::SecretTransferPipeline,
                "native:secret_transfer",
                None,
                Some("dlp_secret_transfer")
            );
            add!(
                mcp::mcp_runtime_risk::McpRuntimeRiskPipeline,
                "native:mcp_runtime_risk",
                None,
                Some("dlp_mcp_runtime_risk")
            );
            add!(
                mcp::mcp_policy::McpPolicyPipeline,
                "native:mcp_policy",
                None,
                Some("dlp_mcp_policy")
            );
            add!(
                dlp::destructive_operation::DestructiveOperationPipeline,
                "native:destructive_operation",
                None,
                Some("dlp_destructive_operation")
            );
        }
        SecurityCategory::Injection => {
            let pipeline = rule_catalog::InjectionRuleCatalogPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:injection_rule_catalog",
                parent: Some("native:injection_l1"),
                rule: None,
                detect: Box::new(move |prepared, gates| {
                    pipeline.detect_prepared(prepared, |id| gates.allows_rule(id))
                }),
            });
            add!(
                structural::InjectionStructuralPipeline,
                "native:injection_structural",
                Some("native:injection_l1"),
                Some("ark.injection.structure.override_sensitive_disclosure")
            );
            macro_rules! injection {
                ($ty:path, $id:literal) => {
                    add!(
                        $ty,
                        $id,
                        Some("native:injection_l1"),
                        Some(signal::native_rule_id($id))
                    );
                };
            }
            injection!(
                cross_tool_instruction::CrossToolInstructionPipeline,
                "native:cross_tool_instruction"
            );
            injection!(
                instruction_leak::InstructionLeakPipeline,
                "native:instruction_leak"
            );
            injection!(
                encoded_instruction::EncodedInstructionPipeline,
                "native:encoded_instruction"
            );
            injection!(
                multi_turn_escalation::MultiTurnEscalationPipeline,
                "native:multi_turn_escalation"
            );
            injection!(
                guardrail_tamper::GuardrailTamperPipeline,
                "native:guardrail_tamper"
            );
            injection!(
                tool_output_instruction::ToolOutputInstructionPipeline,
                "native:tool_output_instruction"
            );
            injection!(
                hidden_html_instruction::HiddenHtmlInstructionPipeline,
                "native:hidden_html_instruction"
            );
            injection!(
                unicode_confusable::UnicodeConfusablePipeline,
                "native:unicode_confusable"
            );
            injection!(
                zero_width_obfuscation::ZeroWidthObfuscationPipeline,
                "native:zero_width_obfuscation"
            );
            injection!(
                agentic_control_abuse::AgenticControlAbusePipeline,
                "native:agentic_control_abuse"
            );
            injection!(
                binary_smuggling::BinarySmugglingPipeline,
                "native:binary_smuggling"
            );
            injection!(
                instruction_override::InstructionOverridePipeline,
                "native:instruction_override"
            );
            injection!(
                jailbreak_framing::JailbreakFramingPipeline,
                "native:jailbreak_framing"
            );
            injection!(
                covert_instruction::CovertInstructionPipeline,
                "native:covert_instruction"
            );
            injection!(
                instruction_boundary::InstructionBoundaryPipeline,
                "native:instruction_boundary"
            );
            injection!(
                authority_escalation::AuthorityEscalationPipeline,
                "native:authority_escalation"
            );
            injection!(
                tool_call_injection::ToolCallInjectionPipeline,
                "native:tool_call_injection"
            );
            injection!(
                output_manipulation::OutputManipulationPipeline,
                "native:output_manipulation"
            );
        }
        _ => {}
    }
    specs
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
