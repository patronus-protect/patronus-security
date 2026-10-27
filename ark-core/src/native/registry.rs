// SPDX-License-Identifier: MIT OR Apache-2.0
use super::NativePolicy;
use crate::{
    detectors::{dlp, injection::*, mcp, pii, NativeDetection},
    threat::NativeText,
    Category,
};

type Detect = Box<dyn Fn(&NativeText<'_>, &dyn NativePolicy) -> NativeDetection + Send + Sync>;

/// An opaque producer and its shared outer gates. Pipeline state lives with the spec.
pub struct NativeProducerSpec {
    category: Category,
    id: &'static str,
    parent: Option<&'static str>,
    rule: Option<&'static str>,
    detect: Detect,
}

impl NativeProducerSpec {
    pub fn id(&self) -> &'static str {
        self.id
    }
    pub fn category(&self) -> Category {
        self.category
    }

    /// Parent/model/required-rule gates, independent of host level or conditional gates.
    pub fn enabled(&self, policy: &dyn NativePolicy) -> bool {
        self.parent.is_none_or(|id| policy.allows_model(id))
            && policy.allows_model(self.id)
            && self.rule.is_none_or(|id| policy.allows_rule(id))
    }

    pub(super) fn detect(
        &self,
        text: &NativeText<'_>,
        policy: &dyn NativePolicy,
    ) -> NativeDetection {
        (self.detect)(text, policy)
    }
}

pub(super) fn producers(category: Category) -> Vec<NativeProducerSpec> {
    let mut specs = Vec::new();
    macro_rules! add {
        ($ty:path, $id:literal, $parent:expr, $rule:expr) => {{
            let pipeline = <$ty>::new();
            specs.push(NativeProducerSpec {
                category,
                id: $id,
                parent: $parent,
                rule: $rule,
                detect: Box::new(move |prepared, _policy| pipeline.detect_prepared(prepared)),
            });
        }};
    }
    match category {
        Category::Pii => {
            let pipeline = pii::pii::PiiPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:pii",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, policy| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| policy.allows_rule(id),
                        policy.explain(),
                        policy.pii_mode(),
                    )
                }),
            });
        }
        Category::Dlp => {
            let pipeline = dlp::dlp::DlpPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:dlp",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, policy| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| policy.allows_rule(id),
                        policy.explain(),
                        policy.dlp_mode(),
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
        Category::Injection => {
            let pipeline = rule_catalog::InjectionRuleCatalogPipeline::new();
            specs.push(NativeProducerSpec {
                category,
                id: "native:injection_rule_catalog",
                parent: Some("native:injection_l1"),
                rule: None,
                detect: Box::new(move |prepared, policy| {
                    pipeline.detect_prepared(prepared, |id| policy.allows_rule(id))
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
    }
    specs
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
