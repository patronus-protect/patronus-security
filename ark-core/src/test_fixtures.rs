//! Core's test fixtures and source catalogs for host tests (Ark), so a host
//! never reads Core's files by path.

/// The compact mmBERT tokenizer of the synthetic Wolf fixtures.
pub const TOKENIZER_MMBPE: &[u8] = include_bytes!("../tests/fixtures/tokenizer.mmbpe");
/// A tiny binary-head Wolf graph that scores batches.
pub const WOLF_BATCH_BINARY_ONNX: &[u8] =
    include_bytes!("../tests/fixtures/wolf_batch_binary.onnx");
/// A tiny scalar-head Wolf graph that scores batches.
pub const WOLF_BATCH_SCALAR_ONNX: &[u8] =
    include_bytes!("../tests/fixtures/wolf_batch_scalar.onnx");
/// A Wolf graph slow enough to be cancelled mid-run.
pub const WOLF_CANCELLABLE_ONNX: &[u8] = include_bytes!("../tests/fixtures/wolf_cancellable.onnx");
/// The synthetic fp16 Wolf graph.
pub const WOLF_SYNTHETIC_FP16_ONNX: &[u8] =
    include_bytes!("../tests/fixtures/wolf_synthetic_fp16.onnx");
/// One positive and negative case per registered L1 rule (DE/EN).
pub const L1_BILINGUAL_RULES: &str = include_str!("../tests/fixtures/l1_bilingual_rules.json");
/// The Threat L1 rule catalog.
pub const THREAT_RULES: &str = include_str!("detectors/threat/rules.json");
/// The SkillSpector injection rule catalog.
pub const SKILLSPECTOR_INJECTION_RULES: &str =
    include_str!("detectors/injection/rules/skillspector_0_1_7.json");
/// The PII anchor lexicon.
pub const PII_ANCHOR_LEXICON: &str = include_str!("detectors/anchor_lexicons/pii.json");
