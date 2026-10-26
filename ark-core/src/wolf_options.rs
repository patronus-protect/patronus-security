use crate::ScanError;
use serde::{Deserialize, Serialize};

/// Wolf document execution. Sizes count tokens, batches count document windows.
/// The defaults preserve the existing 254-content-token inference profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WolfExecutionOptions {
    /// Maximum sequence length, including BOS and EOS.
    pub window_tokens: usize,
    /// Content tokens retained between adjacent windows.
    pub overlap_tokens: usize,
    /// Maximum windows in a single ONNX call (not concurrent requests).
    pub batch_size: usize,
}

impl Default for WolfExecutionOptions {
    fn default() -> Self {
        Self {
            window_tokens: 256,
            overlap_tokens: 0,
            batch_size: 1,
        }
    }
}

impl WolfExecutionOptions {
    pub fn validate(self) -> Result<(), ScanError> {
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
        assert_eq!(options.content_tokens(), 2046);
    }
    #[test]
    fn invalid_profiles_are_rejected() {
        for options in [
            WolfExecutionOptions {
                window_tokens: 2,
                ..Default::default()
            },
            WolfExecutionOptions {
                overlap_tokens: 254,
                ..Default::default()
            },
            WolfExecutionOptions {
                batch_size: 0,
                ..Default::default()
            },
            WolfExecutionOptions {
                window_tokens: usize::MAX,
                batch_size: 2,
                ..Default::default()
            },
        ] {
            assert!(options.validate().is_err());
        }
    }
}
