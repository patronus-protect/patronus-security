#[derive(Debug, Clone)]
pub struct LGBMTree {
    pub split_feature: Vec<usize>,
    pub threshold: Vec<f64>,
    pub left_child: Vec<i32>,
    pub right_child: Vec<i32>,
    pub leaf_value: Vec<f64>,
}

impl LGBMTree {
    pub fn predict(&self, x: &[f64]) -> f64 {
        let mut node = 0;
        loop {
            let feat = self.split_feature[node];
            let val = x[feat];
            let thresh = self.threshold[node];
            let child = if val <= thresh {
                self.left_child[node]
            } else {
                self.right_child[node]
            };
            if child < 0 {
                let leaf_idx = (-child - 1) as usize;
                return self.leaf_value[leaf_idx];
            } else {
                node = child as usize;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LGBMBooster {
    pub trees: Vec<LGBMTree>,
}

impl LGBMBooster {
    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut trees = Vec::new();

        let mut current_split_feature = Vec::new();
        let mut current_threshold = Vec::new();
        let mut current_left_child = Vec::new();
        let mut current_right_child = Vec::new();
        let mut current_leaf_value = Vec::new();
        let mut in_tree = false;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("Tree=") {
                if in_tree {
                    trees.push(LGBMTree {
                        split_feature: current_split_feature.clone(),
                        threshold: current_threshold.clone(),
                        left_child: current_left_child.clone(),
                        right_child: current_right_child.clone(),
                        leaf_value: current_leaf_value.clone(),
                    });
                }
                current_split_feature.clear();
                current_threshold.clear();
                current_left_child.clear();
                current_right_child.clear();
                current_leaf_value.clear();
                in_tree = true;
                continue;
            }

            if in_tree {
                if line.is_empty() {
                    trees.push(LGBMTree {
                        split_feature: current_split_feature.clone(),
                        threshold: current_threshold.clone(),
                        left_child: current_left_child.clone(),
                        right_child: current_right_child.clone(),
                        leaf_value: current_leaf_value.clone(),
                    });
                    current_split_feature.clear();
                    current_threshold.clear();
                    current_left_child.clear();
                    current_right_child.clear();
                    current_leaf_value.clear();
                    in_tree = false;
                    continue;
                }

                if let Some(pos) = line.find('=') {
                    let key = &line[..pos];
                    let val_str = &line[pos + 1..];
                    match key {
                        "split_feature" => {
                            current_split_feature = val_str
                                .split_whitespace()
                                .map(|s| s.parse::<usize>().unwrap())
                                .collect();
                        }
                        "threshold" => {
                            current_threshold = val_str
                                .split_whitespace()
                                .map(|s| s.parse::<f64>().unwrap())
                                .collect();
                        }
                        "left_child" => {
                            current_left_child = val_str
                                .split_whitespace()
                                .map(|s| s.parse::<i32>().unwrap())
                                .collect();
                        }
                        "right_child" => {
                            current_right_child = val_str
                                .split_whitespace()
                                .map(|s| s.parse::<i32>().unwrap())
                                .collect();
                        }
                        "leaf_value" => {
                            current_leaf_value = val_str
                                .split_whitespace()
                                .map(|s| s.parse::<f64>().unwrap())
                                .collect();
                        }
                        _ => {}
                    }
                }
            }
        }

        if in_tree && !current_leaf_value.is_empty() {
            trees.push(LGBMTree {
                split_feature: current_split_feature,
                threshold: current_threshold,
                left_child: current_left_child,
                right_child: current_right_child,
                leaf_value: current_leaf_value,
            });
        }

        Ok(LGBMBooster { trees })
    }

    pub fn predict(&self, x: &[f64]) -> f64 {
        let mut score = 0.0;
        for tree in &self.trees {
            score += tree.predict(x);
        }
        1.0 / (1.0 + (-score).exp())
    }
}
