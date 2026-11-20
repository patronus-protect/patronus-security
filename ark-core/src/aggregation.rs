//! Training-compatible, constant-memory document pooling of binary logits.

/// Incremental `T * (logsumexp(logits / T) - ln(n))`. A single window pools
/// to its own logit at any `T`, so only the multi-window temperature matters.
#[derive(Debug, Clone)]
pub struct SmoothMax {
    temperature: f64,
    maximum: f64,
    scaled_sum: f64,
    count: u64,
}
impl Default for SmoothMax {
    /// Wolf Defender's published multi-window temperature, 0.1.
    fn default() -> Self {
        Self::new(0.1)
    }
}
impl SmoothMax {
    /// `temperature` must be finite and positive.
    pub fn new(temperature: f64) -> Self {
        Self {
            temperature,
            maximum: 0.0,
            scaled_sum: 0.0,
            count: 0,
        }
    }
    pub fn push(&mut self, logit: f64) -> Result<(), &'static str> {
        if !logit.is_finite() {
            return Err("non-finite Wolf logit");
        }
        if self.count == u64::MAX {
            return Err("too many Wolf windows");
        }
        if self.count == 0 {
            self.maximum = logit;
            self.scaled_sum = 1.0;
        } else if logit > self.maximum {
            self.scaled_sum =
                self.scaled_sum * ((self.maximum - logit) / self.temperature).exp() + 1.0;
            self.maximum = logit;
        } else {
            self.scaled_sum += ((logit - self.maximum) / self.temperature).exp();
        }
        self.count += 1;
        Ok(())
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn logit(&self) -> Option<f64> {
        (self.count > 0).then(|| {
            self.maximum + self.temperature * (self.scaled_sum.ln() - (self.count as f64).ln())
        })
    }
    pub fn probability(&self) -> Option<f64> {
        self.logit().map(sigmoid)
    }
}
/// Wolf v2.1 document pooling: [`SmoothMax`] per class, then softmax over the pair.
/// Scalar exports pass a constant benign logit, which pools to zero.
#[derive(Debug, Clone, Default)]
pub struct ClassPool {
    benign: SmoothMax,
    injection: SmoothMax,
}
impl ClassPool {
    /// Both classes pool with the bundle's multi-window `temperature`.
    pub fn new(temperature: f64) -> Self {
        Self {
            benign: SmoothMax::new(temperature),
            injection: SmoothMax::new(temperature),
        }
    }
    pub fn push(&mut self, [benign, injection]: [f64; 2]) -> Result<(), &'static str> {
        if !benign.is_finite() || !injection.is_finite() {
            return Err("non-finite Wolf logit");
        }
        self.benign.push(benign)?;
        self.injection.push(injection)
    }
    pub fn count(&self) -> u64 {
        self.injection.count()
    }
    /// Pooled injection minus pooled benign logit; its sigmoid is the softmax probability.
    pub fn logit(&self) -> Option<f64> {
        Some(self.injection.logit()? - self.benign.logit()?)
    }
    pub fn probability(&self) -> Option<f64> {
        self.logit().map(sigmoid)
    }
}
pub fn sigmoid(logit: f64) -> f64 {
    if logit >= 0.0 {
        1.0 / (1.0 + (-logit).exp())
    } else {
        let e = logit.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_training_formula_and_preserves_logit_units() {
        for values in [
            vec![1.2],
            vec![2.0; 100],
            vec![-4.0, 0.3, 1.2],
            vec![-10000.0, 10000.0],
            vec![10000.0; 10],
        ] {
            let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let reference = maximum
                + 0.1
                    * (values
                        .iter()
                        .map(|v| ((v - maximum) / 0.1).exp())
                        .sum::<f64>()
                        .ln()
                        - (values.len() as f64).ln());
            let mut pool = SmoothMax::default();
            for value in &values {
                pool.push(*value).unwrap();
            }
            assert!((pool.logit().unwrap() - reference).abs() < 1e-10);
            let mut reverse = SmoothMax::default();
            for value in values.iter().rev() {
                reverse.push(*value).unwrap();
            }
            assert!((pool.logit().unwrap() - reverse.logit().unwrap()).abs() < 1e-10);
        }
    }
    #[test]
    fn single_attack_in_long_document_matches_normalized_logsumexp() {
        let mut pool = SmoothMax::default();
        pool.push(2.0).unwrap();
        for _ in 0..99999 {
            pool.push(-2.0).unwrap();
        }
        let reference = 2.0 + 0.1 * ((1.0 + 99999.0 * (-40.0_f64).exp()).ln() - 100000.0_f64.ln());
        assert!((pool.logit().unwrap() - reference).abs() < 1e-10);
        assert_eq!(pool.count(), 100000);
    }
    #[test]
    fn class_pool_matches_the_published_v2_1_reference() {
        // inference.py: classwise smoothmax (T=0.1 for several windows), then softmax.
        let windows = [[2.0, -1.5], [-0.5, 3.0], [1.0, 0.25]];
        let pooled = |column: usize| {
            let maximum = windows
                .iter()
                .map(|row| row[column])
                .fold(f64::MIN, f64::max);
            maximum
                + 0.1
                    * (windows
                        .iter()
                        .map(|row| ((row[column] - maximum) / 0.1).exp())
                        .sum::<f64>()
                        .ln()
                        - (windows.len() as f64).ln())
        };
        let (benign, injection) = (pooled(0), pooled(1));
        let softmax = injection.exp() / (benign.exp() + injection.exp());
        let mut pool = ClassPool::default();
        for row in windows {
            pool.push(row).unwrap();
        }
        assert_eq!(pool.count(), 3);
        assert!((pool.logit().unwrap() - (injection - benign)).abs() < 1e-12);
        assert!((pool.probability().unwrap() - softmax).abs() < 1e-12);
        // Pooling margins instead gives a different verdict for the same windows.
        let mut margins = SmoothMax::default();
        for [benign, injection] in windows {
            margins.push(injection - benign).unwrap();
        }
        assert!((margins.logit().unwrap() - pool.logit().unwrap()).abs() > 0.1);
    }
    #[test]
    fn class_pool_keeps_single_window_and_scalar_logits_unchanged() {
        let mut single = ClassPool::default();
        single.push([0.75, -1.25]).unwrap();
        assert_eq!(single.logit(), Some(-2.0));
        let mut scalar = ClassPool::default();
        let mut reference = SmoothMax::default();
        for logit in [-4.0, 0.3, 1.2] {
            scalar.push([0.0, logit]).unwrap();
            reference.push(logit).unwrap();
        }
        assert!((scalar.logit().unwrap() - reference.logit().unwrap()).abs() < 1e-12);
        assert!(scalar.push([f64::NAN, 1.0]).is_err());
        assert_eq!(scalar.count(), 3);
    }
    #[test]
    fn temperature_is_the_callers_and_a_single_window_ignores_it() {
        let mut pool = SmoothMax::new(1.0);
        pool.push(0.0).unwrap();
        pool.push(1.0).unwrap();
        let reference = 1.0 + ((-1.0_f64).exp() + 1.0).ln() - 2.0_f64.ln();
        assert!((pool.logit().unwrap() - reference).abs() < 1e-12);
        for temperature in [0.1, 1.0] {
            let mut single = ClassPool::new(temperature);
            single.push([0.25, 1.0]).unwrap();
            assert_eq!(single.logit(), Some(0.75));
        }
    }
    #[test]
    fn rejects_non_finite_and_empty_has_no_verdict() {
        let mut pool = SmoothMax::default();
        assert_eq!(pool.logit(), None);
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(pool.push(value).is_err());
        }
        assert_eq!(pool.count(), 0);
    }
}

#[cfg(test)]
mod training_reference_tests {
    use super::*;
    #[test]
    fn matches_pytorch_single_training_reference() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/wolf_smooth_max.json")).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let mut pool = SmoothMax::default();
            for value in case["logits"].as_array().unwrap() {
                pool.push(value.as_f64().unwrap()).unwrap();
            }
            let reference = case["expected_logit"].as_f64().unwrap();
            assert!(
                (pool.logit().unwrap() - reference).abs() < 0.002,
                "f32 PyTorch reference {reference}, Rust {:?}",
                pool.logit()
            );
        }
    }
}
