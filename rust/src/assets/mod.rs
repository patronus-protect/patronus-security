// SPDX-License-Identifier: AGPL-3.0-only
mod compact_tokenizer;
mod download;
mod specs;

pub(crate) use download::prepare_cached_ntdb_l2_compact_tokenizer;
pub use download::{
    category_assets, download_category_assets, download_dynamic_pii_assets,
    download_ntdb_l2_package, dynamic_pii_assets_present, ntdb_l2_package_asset,
    ntdb_l2_package_assets, ntdb_l2_package_manifest_files, required_assets_present,
};
pub use specs::{
    AssetSpec, NtdbL2PackageAssetSpec, PipelineModelAssetSpec, ASSET_MANIFEST, DYNAMIC_PII_ASSET,
    NTDB_L2_PACKAGE_MANIFEST,
};
