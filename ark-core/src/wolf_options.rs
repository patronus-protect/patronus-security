use crate::ScanError;
use serde::{Deserialize, Serialize};

/// Wolf document execution. Sizes count tokens, batches count document windows.
/// Unset sizes follow the bundle's published settings (`POOLING.json`; Wolf
/// Defender publishes 2048-token windows with 64 overlap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WolfExecutionOptions {
    /// Maximum sequence length, including BOS and EOS; unset takes the bundle's window.
    pub window_tokens: Option<usize>,
    /// Content tokens retained between adjacent windows; unset takes the bundle's overlap.
    pub overlap_tokens: Option<usize>,
    /// Maximum windows in a single ONNX call (not concurrent requests).
    pub batch_size: usize,
}

impl Default for WolfExecutionOptions {
    fn default() -> Self {
        Self {
            window_tokens: None,
            overlap_tokens: None,
            batch_size: 1,
        }
    }
}

impl WolfExecutionOptions {
    /// Check the sizes that are set; unset sizes are checked once the bundle is read.
    pub fn validate(self) -> Result<(), ScanError> {
        let overlap = self.overlap_tokens.unwrap_or(0);
        self.resolve(overlap.saturating_add(3), overlap).map(drop)
    }

    /// The effective windows: set sizes win over the given (published) ones.
    pub(crate) fn resolve(
        self,
        window_tokens: usize,
        overlap_tokens: usize,
    ) -> Result<WolfWindows, ScanError> {
        let windows = WolfWindows {
            window_tokens: self.window_tokens.unwrap_or(window_tokens),
            overlap_tokens: self.overlap_tokens.unwrap_or(overlap_tokens),
            batch_size: self.batch_size,
        };
        windows.validate()?;
        Ok(windows)
    }
}

/// Resolved Wolf windowing of one runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WolfWindows {
    pub(crate) window_tokens: usize,
    pub(crate) overlap_tokens: usize,
    pub(crate) batch_size: usize,
}

impl WolfWindows {
    pub(crate) fn validate(self) -> Result<(), ScanError> {
        if self.window_tokens < 3 || self.overlap_tokens >= self.window_tokens - 2 {
            return Err(ScanError::Config("Wolf needs at least one content token and overlap smaller than its content capacity".into()));
        }
        if self.batch_size == 0
            || self
                .window_tokens
                .checked_mul(self.batch_size)
                .and_then(|n| n.checked_mul(std::mem::size_of::<i64>()))
                .is_none_or(|n| n > isize::MAX as usize)
        {
            return Err(ScanError::Config(
                "invalid Wolf batch size or tensor size overflow".into(),
            ));
        }
        Ok(())
    }

    #[cfg(any(feature = "wolf", test))]
    pub(crate) fn content_tokens(self) -> usize {
        self.window_tokens - 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_partial_configuration() {
        assert_eq!(
            serde_json::from_str::<WolfExecutionOptions>("{}").unwrap(),
            WolfExecutionOptions::default()
        );
        let options: WolfExecutionOptions =
            serde_json::from_str(r#"{"window_tokens":2048,"overlap_tokens":256,"batch_size":4}"#)
                .unwrap();
        options.validate().unwrap();
        assert_eq!(options.resolve(256, 0).unwrap().content_tokens(), 2046);
        // Unset sizes take the published ones; set sizes win.
        let partial: WolfExecutionOptions = serde_json::from_str(r#"{"batch_size":4}"#).unwrap();
        partial.validate().unwrap();
        assert_eq!(
            partial.resolve(2048, 64).unwrap(),
            WolfWindows {
                window_tokens: 2048,
                overlap_tokens: 64,
                batch_size: 4
            }
        );
        let window_only = WolfExecutionOptions {
            window_tokens: Some(32),
            ..Default::default()
        };
        window_only.validate().unwrap();
        assert!(window_only.resolve(2048, 64).is_err());
        assert_eq!(window_only.resolve(2048, 4).unwrap().window_tokens, 32);
    }
    #[test]
    fn invalid_profiles_are_rejected() {
        for options in [
            WolfExecutionOptions {
                window_tokens: Some(2),
                ..Default::default()
            },
            WolfExecutionOptions {
                window_tokens: Some(256),
                overlap_tokens: Some(254),
                ..Default::default()
            },
            WolfExecutionOptions {
                batch_size: 0,
                ..Default::default()
            },
            WolfExecutionOptions {
                window_tokens: Some(usize::MAX),
                batch_size: 2,
                ..Default::default()
            },
        ] {
            assert!(options.validate().is_err());
        }
    }
}
