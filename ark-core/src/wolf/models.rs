//! Published Wolf Defender models: one pinned revision and one file per precision.
use crate::ScanError;
use serde::{Deserialize, Serialize};

/// Environment override for [`WolfPrecision::Auto`]; accepts any precision name.
pub const PRECISION_ENV: &str = "PATRONUS_L3_PRECISION";
/// Files every precision needs next to its ONNX graph.
pub const SUPPORT_FILES: [&str; 3] = ["config.json", "tokenizer.json", "tokenizer_config.json"];

/// Wolf Defender size. All sizes share the export format and tokenizer family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WolfModel {
    Base,
    #[default]
    Small,
    Edge,
}

/// ONNX export of a Wolf model. `Auto` resolves through [`PRECISION_ENV`], then the CPU.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WolfPrecision {
    #[default]
    Auto,
    Fp32,
    Fp16,
    Mixed,
    MixedX86,
    Int8Int4,
    Int8Int4X86,
}

pub struct WolfModelSpec {
    pub model: WolfModel,
    /// Public model id in results, gates and policies.
    pub id: &'static str,
    pub repository: &'static str,
    pub revision: &'static str,
    /// Earlier pins whose managed caches still identify this model.
    pub legacy_revisions: &'static [&'static str],
    /// Graph path per precision, in [`WolfPrecision::CONCRETE`] order.
    graphs: [&'static str; 6],
}

const BASE_SMALL_GRAPHS: [&str; 6] = [
    "onnx/onnx_fp32/model.onnx",
    "onnx/onnx_fp16/model_fp16.onnx",
    "onnx/onnx_mixed/model_mixed.onnx",
    "onnx/onnx_mixed_x86/model_mixed.onnx",
    "onnx/int8_int4_embeddings/model.onnx",
    "onnx/int8_int4_embeddings_x86/model.onnx",
];

pub const WOLF_MODELS: [WolfModelSpec; 3] = [
    WolfModelSpec {
        model: WolfModel::Base,
        id: "wolf-defender-base",
        repository: "patronus-studio/wolf-defender-prompt-injection",
        revision: "af0b16a1d40ca246595e48246ccf9f906a52a50e",
        legacy_revisions: &[],
        graphs: BASE_SMALL_GRAPHS,
    },
    WolfModelSpec {
        model: WolfModel::Small,
        id: "wolf-defender-small",
        repository: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: "2484cc9a13550aa4f2c29b577ff3ef331dc6ba07",
        legacy_revisions: &["142fadc5474163d4c483cb761d5a6b02e3aa1741"],
        graphs: BASE_SMALL_GRAPHS,
    },
    WolfModelSpec {
        model: WolfModel::Edge,
        id: "wolf-defender-edge",
        repository: "patronus-studio/wolf-defender-prompt-injection-edge",
        revision: "a65713895aafa398e71f151f50d33449b477b4c9",
        legacy_revisions: &[],
        graphs: [
            "onnx/onnx_fp32/model.onnx",
            "onnx/onnx_fp16/model_fp16.onnx",
            "onnx/onnx_mixed/model_mixed.onnx",
            "onnx/onnx_mixed_x86_weight_only/model.onnx",
            "onnx/int8_int4_embeddings/model.onnx",
            "onnx/int8_int4_embeddings_x86_weight_only/model.onnx",
        ],
    },
];

impl WolfModel {
    pub const ALL: [Self; 3] = [Self::Base, Self::Small, Self::Edge];

    pub fn spec(self) -> &'static WolfModelSpec {
        &WOLF_MODELS[self as usize]
    }

    /// The registered model a managed cache's revision marker identifies.
    pub fn of_revision(revision: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|model| {
            let spec = model.spec();
            spec.revision == revision || spec.legacy_revisions.contains(&revision)
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Small => "small",
            Self::Edge => "edge",
        }
    }

    /// Attack-probability threshold at which this model detects: the value
    /// Ark's dedicated injection L3 applies to every Wolf size by default.
    pub fn default_threshold(self) -> f64 {
        match self {
            Self::Base | Self::Small | Self::Edge => 0.93,
        }
    }
}

impl WolfModelSpec {
    /// The graph of one concrete precision; `None` for [`WolfPrecision::Auto`].
    pub fn graph(&self, precision: WolfPrecision) -> Option<&'static str> {
        WolfPrecision::CONCRETE
            .iter()
            .position(|&p| p == precision)
            .map(|index| self.graphs[index])
    }

    /// Every file a managed cache holds for one concrete precision.
    pub fn files(&self, precision: WolfPrecision) -> Option<[&'static str; 4]> {
        let [config, tokenizer, tokenizer_config] = SUPPORT_FILES;
        Some([self.graph(precision)?, config, tokenizer, tokenizer_config])
    }
}

impl WolfPrecision {
    pub const CONCRETE: [Self; 6] = [
        Self::Fp32,
        Self::Fp16,
        Self::Mixed,
        Self::MixedX86,
        Self::Int8Int4,
        Self::Int8Int4X86,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fp32 => "fp32",
            Self::Fp16 => "fp16",
            Self::Mixed => "mixed",
            Self::MixedX86 => "mixed_x86",
            Self::Int8Int4 => "int8_int4",
            Self::Int8Int4X86 => "int8_int4_x86",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        std::iter::once(Self::Auto)
            .chain(Self::CONCRETE)
            .find(|precision| precision.as_str().eq_ignore_ascii_case(value.trim()))
    }

    /// The quantized export for this CPU: x86 weight-only graphs on `x86_64`.
    pub fn platform_default() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::Int8Int4X86
        } else {
            Self::Int8Int4
        }
    }

    /// Explicit precisions stay; `auto` takes [`PRECISION_ENV`], then [`Self::platform_default`].
    pub fn resolve(self) -> Result<Self, ScanError> {
        if self != Self::Auto {
            return Ok(self);
        }
        let Ok(value) = std::env::var(PRECISION_ENV) else {
            return Ok(Self::platform_default());
        };
        match Self::parse(&value) {
            Some(Self::Auto) => Ok(Self::platform_default()),
            Some(precision) => Ok(precision),
            None => Err(ScanError::Config(format!(
                "{PRECISION_ENV}: unknown Wolf precision {value}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_order_matches_models_and_names_round_trip() {
        for model in WolfModel::ALL {
            assert_eq!(model.spec().model, model);
            assert_eq!(model.spec().revision.len(), 40);
            let json = serde_json::to_string(&model).unwrap();
            assert_eq!(json, format!("\"{}\"", model.as_str()));
        }
        for precision in std::iter::once(WolfPrecision::Auto).chain(WolfPrecision::CONCRETE) {
            assert_eq!(WolfPrecision::parse(precision.as_str()), Some(precision));
            assert_eq!(
                serde_json::to_string(&precision).unwrap(),
                format!("\"{}\"", precision.as_str())
            );
        }
        assert_eq!(WolfPrecision::parse(" FP16 "), Some(WolfPrecision::Fp16));
        assert!(WolfPrecision::parse("int4").is_none());
        assert_eq!(WolfModel::default().spec().id, "wolf-defender-small");
        for model in WolfModel::ALL {
            assert_eq!(WolfModel::of_revision(model.spec().revision), Some(model));
        }
        assert_eq!(
            WolfModel::of_revision("142fadc5474163d4c483cb761d5a6b02e3aa1741"),
            Some(WolfModel::Small)
        );
        assert_eq!(WolfModel::of_revision("local"), None);
    }

    #[test]
    fn every_model_publishes_every_precision_and_edge_keeps_its_x86_paths() {
        for model in WolfModel::ALL {
            let spec = model.spec();
            assert!(spec.graph(WolfPrecision::Auto).is_none());
            for precision in WolfPrecision::CONCRETE {
                let files = spec.files(precision).unwrap();
                assert!(files[0].starts_with("onnx/") && files[0].ends_with(".onnx"));
                assert_eq!(&files[1..], &SUPPORT_FILES);
            }
        }
        assert_eq!(
            WolfModel::Edge.spec().graph(WolfPrecision::Int8Int4X86),
            Some("onnx/int8_int4_embeddings_x86_weight_only/model.onnx")
        );
        assert_eq!(
            WolfModel::Base.spec().graph(WolfPrecision::MixedX86),
            Some("onnx/onnx_mixed_x86/model_mixed.onnx")
        );
    }

    #[test]
    fn explicit_precision_ignores_the_environment_and_auto_follows_the_cpu() {
        assert_eq!(WolfPrecision::Fp32.resolve().unwrap(), WolfPrecision::Fp32);
        let expected = if cfg!(target_arch = "x86_64") {
            WolfPrecision::Int8Int4X86
        } else {
            WolfPrecision::Int8Int4
        };
        assert_eq!(WolfPrecision::platform_default(), expected);
    }
}
