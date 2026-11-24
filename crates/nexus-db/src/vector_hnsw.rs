use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use crate::parser::VectorMetric;
use crate::stdlib::{cosine_similarity, euclidean_distance, manhattan_distance};

#[derive(Debug, Clone)]
struct Candidate {
    dist: f64,
    idx: usize,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap by distance
        other
            .dist
            .partial_cmp(&self.dist)
            .unwrap_or(Ordering::Equal)
    }
}

/// Pure-Rust Hierarchical Navigable Small World (HNSW) graph index for fast approximate KNN search.
#[derive(Debug, Clone)]
pub struct HnswIndex {
    pub metric: VectorMetric,
    pub m: usize,
    pub ef_construction: usize,
    nodes: Vec<(String, Vec<f64>)>,
    neighbors: Vec<Vec<usize>>,
}

impl HnswIndex {
    pub fn new(metric: VectorMetric, m: usize, ef_construction: usize) -> Self {
        Self {
            metric,
            m: m.max(4),
            ef_construction: ef_construction.max(16),
            nodes: Vec::new(),
            neighbors: Vec::new(),
        }
    }

    #[inline]
    fn distance(&self, a: &[f64], b: &[f64]) -> f64 {
        match self.metric {
            VectorMetric::Cosine => 1.0 - cosine_similarity(a, b),
            VectorMetric::Euclidean => euclidean_distance(a, b),
            VectorMetric::Manhattan => manhattan_distance(a, b),
        }
    }

    pub fn insert(&mut self, id: String, vec: Vec<f64>) {
        let new_idx = self.nodes.len();
        self.nodes.push((id, vec));
        self.neighbors.push(Vec::new());

        if new_idx == 0 {
            return;
        }

        let nearest = self.search_layer(&self.nodes[new_idx].1, self.ef_construction, 0);
        let chosen: Vec<usize> = nearest.into_iter().take(self.m).map(|c| c.idx).collect();

        for &nb in &chosen {
            self.neighbors[new_idx].push(nb);
            if !self.neighbors[nb].contains(&new_idx) {
                self.neighbors[nb].push(new_idx);
                if self.neighbors[nb].len() > self.m * 2 {
                    let nb_vec = self.nodes[nb].1.clone();
                    let metric = self.metric;
                    self.neighbors[nb].sort_by(|&a, &b| {
                        let da = metric_dist(metric, &nb_vec, &self.nodes[a].1);
                        let db = metric_dist(metric, &nb_vec, &self.nodes[b].1);
                        da.partial_cmp(&db).unwrap_or(Ordering::Equal)
                    });
                    self.neighbors[nb].truncate(self.m * 2);
                }
            }
        }
    }

    pub fn search_knn(&self, query: &[f64], k: usize, ef: usize) -> Vec<(String, f64)> {
        if self.nodes.is_empty() || k == 0 {
            return Vec::new();
        }
        let found = self.search_layer(query, ef.max(k), 0);
        found
            .into_iter()
            .take(k)
            .map(|c| (self.nodes[c.idx].0.clone(), c.dist))
            .collect()
    }

    fn search_layer(&self, query: &[f64], ef: usize, entry: usize) -> Vec<Candidate> {
        let mut visited = HashSet::new();
        let mut candidates = BinaryHeap::new();
        let mut results: Vec<Candidate> = Vec::new();

        let d0 = self.distance(query, &self.nodes[entry].1);
        visited.insert(entry);
        candidates.push(Candidate { dist: d0, idx: entry });
        results.push(Candidate { dist: d0, idx: entry });

        while let Some(curr) = candidates.pop() {
            results.sort_by(|a, b| a.dist.partial_cmp(&b.dist).unwrap_or(Ordering::Equal));
            if results.len() >= ef && curr.dist > results[ef - 1].dist {
                break;
            }
            for &nb in &self.neighbors[curr.idx] {
                if visited.insert(nb) {
                    let d = self.distance(query, &self.nodes[nb].1);
                    if results.len() < ef || d < results.last().map(|r| r.dist).unwrap_or(f64::INFINITY) {
                        candidates.push(Candidate { dist: d, idx: nb });
                        results.push(Candidate { dist: d, idx: nb });
                    }
                }
            }
        }

        results.sort_by(|a, b| a.dist.partial_cmp(&b.dist).unwrap_or(Ordering::Equal));
        results.truncate(ef);
        results
    }
}

fn metric_dist(metric: VectorMetric, a: &[f64], b: &[f64]) -> f64 {
    match metric {
        VectorMetric::Cosine => 1.0 - cosine_similarity(a, b),
        VectorMetric::Euclidean => euclidean_distance(a, b),
        VectorMetric::Manhattan => manhattan_distance(a, b),
    }
}
