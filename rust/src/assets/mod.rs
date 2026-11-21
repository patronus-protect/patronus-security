// SPDX-License-Identifier: GPL-3.0-only
mod download;
pub(crate) use patronus_ark_core::assets::mmbert_tokenizer;
pub(crate) mod specs;

use crate::{SecurityAssetProgress, SecurityAssetProgressCallback, SecurityCategory};

pub(crate) use download::prepare_cached_ntdb_l2_compact_tokenizer;
pub use download::{
    ntdb_l2_package_current, ntdb_l2_package_manifest_files, prepare_ntdb_l2_package,
};
pub(crate) use specs::prefer_fp16_l3;
pub use specs::{
    dedicated_l3_asset, PipelineModelAssetSpec, DEDICATED_L3_ASSETS, DYNAMIC_PII_ASSET,
    NTDB_L2_PACKAGE_MANIFEST, NTDB_PACKAGE_MANIFEST, UNIFIED_L3_ASSET, WOLF_PIPELINE_MODEL,
};

/// Report Core's `(completed, total)` file progress as one model's asset progress.
pub(crate) fn progress_reporter<'a>(
    progress: Option<&'a SecurityAssetProgressCallback>,
    category: SecurityCategory,
    model: &'a str,
) -> Option<impl Fn(usize, usize) + Send + Sync + 'a> {
    progress.map(move |progress| {
        move |completed_files, total_files| {
            progress(SecurityAssetProgress {
                category,
                model: model.to_string(),
                completed_files,
                total_files,
            })
        }
    })
}
