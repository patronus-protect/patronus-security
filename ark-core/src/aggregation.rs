//! Training-compatible, constant-memory document pooling of binary logits.

/// Incremental `T * (logsumexp(logits / T) - ln(n))`, with Wolf's fixed T=0.1.
#[derive(Debug, Clone, Default)]
pub struct SmoothMax {
    maximum: f64,
    scaled_sum: f64,
    count: u64,
}
impl SmoothMax {
    pub const TEMPERATURE: f64 = 0.1;
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
                self.scaled_sum * ((self.maximum - logit) / Self::TEMPERATURE).exp() + 1.0;
            self.maximum = logit;
        } else {
            self.scaled_sum += ((logit - self.maximum) / Self::TEMPERATURE).exp();
        }
        self.count += 1;
        Ok(())
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn logit(&self) -> Option<f64> {
        (self.count > 0).then(|| {
            self.maximum + Self::TEMPERATURE * (self.scaled_sum.ln() - (self.count as f64).ln())
        })
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
