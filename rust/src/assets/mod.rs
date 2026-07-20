// SPDX-License-Identifier: AGPL-3.0-only
mod compact_tokenizer;
mod download;
mod specs;

pub use download::{
    category_assets, dedicated_l3_asset, dedicated_l3_assets_present, download_category_assets,
    download_dedicated_l3_assets, download_dynamic_pii_assets, download_ntdb_l2_package,
    download_unified_l3_assets, dynamic_pii_assets_present, ntdb_l2_package_asset,
    ntdb_l2_package_assets, ntdb_l2_package_manifest_files, required_assets_present,
    unified_l3_assets_present,
};
pub(crate) use download::{
    download_dynamic_pii_assets_with_progress, download_ntdb_l2_package_with_progress,
    download_unified_l3_assets_with_progress, prepare_cached_ntdb_l2_compact_tokenizer,
};
pub use specs::{
    AssetSpec, NtdbL2PackageAssetSpec, PipelineModelAssetSpec, ASSET_MANIFEST, DEDICATED_L3_ASSETS,
    DYNAMIC_PII_ASSET, NTDB_L2_PACKAGE_MANIFEST, UNIFIED_L3_ASSET,
};
