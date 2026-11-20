// SPDX-License-Identifier: GPL-3.0-only
mod download;
pub(crate) use patronus_ark_core::assets::mmbert_tokenizer;
pub(crate) mod specs;

pub use download::{
    category_assets, dedicated_l3_asset, download_category_assets, download_ntdb_l2_package,
    ntdb_l2_package_asset, ntdb_l2_package_assets, ntdb_l2_package_assets_present,
    ntdb_l2_package_manifest_files, required_assets_present,
};
pub(crate) use download::{
    prefer_fp16_l3, prepare_cached_ntdb_l2_compact_tokenizer, progress_reporter,
};
pub use specs::{
    AssetSpec, NtdbL2PackageAssetSpec, PipelineModelAssetSpec, ASSET_MANIFEST, DEDICATED_L3_ASSETS,
    DYNAMIC_PII_ASSET, NTDB_L2_PACKAGE_MANIFEST, UNIFIED_L3_ASSET, WOLF_PIPELINE_MODEL,
};
