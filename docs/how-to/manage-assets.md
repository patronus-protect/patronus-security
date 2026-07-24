# Manage model assets

**Goal:** control where model assets live, when they download, and how to run authenticated or
optional downloads. For the generated inventory (sizes, exact paths), see the
[Assets reference](../assets.md).

## Where assets are cached

By default, assets are stored under the platform cache directory in `patronus_ark/`.
Override the location with `model_dir` (Python) / the model-dir argument (Rust):

=== "Python"

    ```python
    scanner = SecurityGateway(
        categories=["injection"],
        max_level="l3",
        model_dir="/opt/patronus-ark-assets",
        download_files=True,
        download_categories=["injection"],
    )
    ```

=== "Rust"

    ```rust
    let scanner = SecurityGateway::with_download_categories(
        vec![SecurityCategory::Injection],
        SecurityLevel::L3,
        Some("/opt/patronus-ark-assets".into()),   // model_dir
        true,                                       // download_files
        Some(vec![SecurityCategory::Injection]),
    );
    ```

A custom `model_dir` is convenient for shipping a pre-populated cache to another machine
(see [Offline & air-gapped](offline-airgapped.md)).

## Control what downloads

| Setting | Effect |
| --- | --- |
| `download_files=False` | Never download; use native L1 + already-cached assets only. |
| `download_files=True` | Download required assets for configured categories on demand. |
| `download_categories=[…]` | Restrict automatic downloads to just these categories. |
| `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1` | Also fetch non-required asset files (currently `tokenizer_config.json` for the legacy L3 manifest), which are skipped by default. |

Required assets download during `warmup()` (or, in Rust, `prepare_assets()`); optional ones stay
skipped unless the environment variable is set.

## Authenticated / rate-limited access

Set `HF_TOKEN` when the Hugging Face repositories require authentication or you are being rate
limited:

```bash
export HF_TOKEN=hf_xxx
```

`HF_HOME` is respected for the underlying Hugging Face cache location.

## Split download from runtime (delivery windows)

If downloads must not happen at runtime, use the two-phase lifecycle (**Rust only**):
`prepare_assets()` while the network is available, then `warmup_from_local_assets()` at runtime
(local-only). In Python, `warmup()` always performs the combined prepare-and-warmup cycle; ship a
pre-populated `model_dir` and reconstruct offline with `download_files=False` instead (see
[Offline & air-gapped](offline-airgapped.md)). See
[Architecture → asset & runtime lifecycle](../concepts/architecture.md#asset-and-runtime-lifecycle).

## Local model overrides

Point a category at a local NTDB directory with the `PATRONUS_NTDB_*_DIR` environment variables
(one per model-backed category) — see the
[configuration reference](../reference/configuration.md#environment-variables). Local overrides
are treated as canonical and are never rewritten by the asset manager.

## Inspect the cache

`asset_readiness()` (Rust only) reports what is present locally **without** downloading or loading
anything into memory; `runtime_readiness()` (both languages) reports initialized runtime state. Use
these to verify a cache before going offline.
