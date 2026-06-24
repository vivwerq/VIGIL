//! # Machine Learning Anomaly Detection
//!
//! Outlier detection using a memory-safe, pure-Rust Isolation Forest implementation.
//! Uses the `linfa` DatasetBase abstraction to represent training matrices extracted
//! from telemetry sliding windows.

use linfa::DatasetBase;
use ndarray::Array2;

/// An Isolation Forest model for unsupervised anomaly detection.
#[derive(Clone)]
pub struct IsolationForest {
    num_trees: usize,
    subsample_size: usize,
    trees: Vec<IsolationTree>,
    /// Average path length normalization factor c(subsample_size).
    c_factor: f64,
}

impl IsolationForest {
    /// Create a new untrained Isolation Forest.
    pub fn new(num_trees: usize, subsample_size: usize) -> Self {
        let actual_subsample = subsample_size.max(2);
        Self {
            num_trees,
            subsample_size: actual_subsample,
            trees: Vec::new(),
            c_factor: c_bst(actual_subsample),
        }
    }

    /// Fit the Isolation Forest on the given Linfa dataset.
    /// The dataset contains one feature column (1D time series observations)
    /// but is structured as an Array2 for general ML alignment.
    pub fn fit<S>(&mut self, dataset: &DatasetBase<Array2<f64>, S>) {
        let records = dataset.records();
        let n_samples = records.nrows();
        if n_samples < 2 {
            return;
        }

        let mut rng = simple_lcg(42); // Deterministic seed for reproducible safety audit
        let mut trees = Vec::with_capacity(self.num_trees);

        // Calculate max height limit: ceil(log2(subsample_size))
        let max_height = ((self.subsample_size as f64).log2().ceil() as usize).max(1);

        for _ in 0..self.num_trees {
            // Draw a random subsample of indices
            let mut sample_indices = Vec::with_capacity(self.subsample_size);
            for _ in 0..self.subsample_size {
                let idx = (rng.next_u32() as usize) % n_samples;
                sample_indices.push(idx);
            }

            // Extract values for this tree
            let mut sample_data = Vec::with_capacity(self.subsample_size);
            for &idx in &sample_indices {
                if let Some(val) = records.get((idx, 0)) {
                    sample_data.push(*val);
                }
            }

            let tree = IsolationTree::new(&mut sample_data, 0, max_height, &mut rng);
            trees.push(tree);
        }

        self.trees = trees;
    }

    /// Predict the anomaly score for a given new observation value.
    /// Returns a score between 0.0 (normal) and 1.0 (extreme anomaly).
    pub fn predict(&self, value: f64) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }

        let mut path_sum = 0.0;
        for tree in &self.trees {
            path_sum += tree.path_length(value, 0);
        }

        let avg_path = path_sum / self.trees.len() as f64;

        // s(x, n) = 2^(-E(h(x)) / c(n))
        if self.c_factor > 0.0 {
            (2.0f64.powf(-avg_path / self.c_factor)).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

/// A single Isolation Tree.
#[derive(Clone)]
struct IsolationTree {
    root: Option<Box<Node>>,
}

#[derive(Clone)]
enum Node {
    Internal {
        split_val: f64,
        left: Box<Node>,
        right: Box<Node>,
    },
    Leaf {
        size: usize,
    },
}

impl IsolationTree {
    fn new(data: &mut [f64], current_height: usize, max_height: usize, rng: &mut LcgRng) -> Self {
        if data.len() <= 1 || current_height >= max_height {
            return Self {
                root: Some(Box::new(Node::Leaf { size: data.len() })),
            };
        }

        let root = Node::new_node(data, current_height, max_height, rng);
        Self {
            root: Some(Box::new(root)),
        }
    }

    fn path_length(&self, value: f64, current_height: usize) -> f64 {
        match &self.root {
            Some(node) => node.path_length(value, current_height),
            None => 0.0,
        }
    }
}

impl Node {
    fn new_node(
        data: &mut [f64],
        current_height: usize,
        max_height: usize,
        rng: &mut LcgRng,
    ) -> Self {
        let len = data.len();
        if len <= 1 || current_height >= max_height {
            Self::Leaf { size: len }
        } else {
            let mut min = data[0];
            let mut max = data[0];
            for &val in data.iter().skip(1) {
                if val < min {
                    min = val;
                }
                if val > max {
                    max = val;
                }
            }

            if (max - min).abs() < 1e-9 {
                return Self::Leaf { size: len };
            }

            let rand_factor = (rng.next_u32() as f64) / (u32::MAX as f64);
            let split_val = min + rand_factor * (max - min);

            let mut i = 0;
            let mut j = len;
            while i < j {
                if data[i] < split_val {
                    i += 1;
                } else {
                    j -= 1;
                    data.swap(i, j);
                }
            }

            if i == 0 || i == len {
                return Self::Leaf { size: len };
            }

            let (left_slice, right_slice) = data.split_at_mut(i);

            let left = Box::new(Self::new_node(
                left_slice,
                current_height + 1,
                max_height,
                rng,
            ));
            let right = Box::new(Self::new_node(
                right_slice,
                current_height + 1,
                max_height,
                rng,
            ));

            Self::Internal {
                split_val,
                left,
                right,
            }
        }
    }

    fn path_length(&self, value: f64, current_height: usize) -> f64 {
        match self {
            Self::Leaf { size } => {
                let n = *size;
                current_height as f64 + c_bst(n)
            }
            Self::Internal {
                split_val,
                left,
                right,
            } => {
                if value < *split_val {
                    left.path_length(value, current_height + 1)
                } else {
                    right.path_length(value, current_height + 1)
                }
            }
        }
    }
}

/// Helper function to compute average path length of unsuccessful BST search.
/// c(n) = 2 * (ln(n - 1) + 0.5772156649) - 2 * (n - 1) / n
fn c_bst(n: usize) -> f64 {
    if n <= 1 {
        0.0
    } else if n == 2 {
        1.0
    } else {
        let n_f = n as f64;
        let euler_gamma = 0.5772156649;
        2.0 * ((n_f - 1.0).ln() + euler_gamma) - (2.0 * (n_f - 1.0) / n_f)
    }
}

/// Simple Linear Congruential Generator (LCG) for deterministic, non-cryptographic rand
struct LcgRng {
    state: u64,
}

impl LcgRng {
    fn next_u32(&mut self) -> u32 {
        // POSIX LCG parameters
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
}

fn simple_lcg(seed: u64) -> LcgRng {
    LcgRng { state: seed }
}

/// Helper function to convert dynamic SlidingWindow elements into a Linfa Dataset
pub fn window_to_dataset(
    window: &crate::stats::SlidingWindow,
) -> Option<
    DatasetBase<Array2<f64>, ndarray::ArrayBase<ndarray::OwnedRepr<()>, ndarray::Dim<[usize; 1]>>>,
> {
    let values = window.values();
    let n = values.len();
    if n < 4 {
        return None;
    }
    let array = Array2::from_shape_vec((n, 1), values).ok()?;
    Some(DatasetBase::from(array))
}
