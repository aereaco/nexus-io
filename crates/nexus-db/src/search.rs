use std::collections::HashMap;

use crate::stdlib::tokenize_fts;

/// Okapi BM25 scorer over a corpus of document texts (`k1 = 1.2`, `b = 0.75`).
pub struct Bm25Scorer {
    doc_count: f64,
    avg_dl: f64,
    df: HashMap<String, usize>,
}

impl Bm25Scorer {
    pub fn from_corpus<'a>(docs: impl Iterator<Item = &'a str>) -> Self {
        let mut df: HashMap<String, usize> = HashMap::new();
        let mut total_len = 0usize;
        let mut doc_count = 0usize;

        for text in docs {
            doc_count += 1;
            let tokens = tokenize_fts(text);
            total_len += tokens.len();
            let mut seen = std::collections::HashSet::new();
            for t in tokens {
                if seen.insert(t.clone()) {
                    *df.entry(t).or_insert(0) += 1;
                }
            }
        }

        let avg_dl = if doc_count > 0 {
            total_len as f64 / doc_count as f64
        } else {
            1.0
        };

        Self {
            doc_count: doc_count as f64,
            avg_dl,
            df,
        }
    }

    pub fn score(&self, doc_text: &str, query: &str) -> f64 {
        let k1 = 1.2;
        let b = 0.75;
        let doc_tokens = tokenize_fts(doc_text);
        let dl = doc_tokens.len() as f64;
        if dl == 0.0 {
            return 0.0;
        }

        let mut tf_map: HashMap<String, usize> = HashMap::new();
        for t in doc_tokens {
            *tf_map.entry(t).or_insert(0) += 1;
        }

        let mut score = 0.0;
        for qt in tokenize_fts(query) {
            let tf = *tf_map.get(&qt).unwrap_or(&0) as f64;
            if tf == 0.0 {
                continue;
            }
            let n_q = *self.df.get(&qt).unwrap_or(&0) as f64;
            let idf = ((self.doc_count - n_q + 0.5) / (n_q + 0.5) + 1.0).ln();
            let num = tf * (k1 + 1.0);
            let den = tf + k1 * (1.0 - b + b * (dl / self.avg_dl));
            score += idf * (num / den);
        }
        score
    }
}

/// Highlight matching query terms inside `text` using `prefix` and `suffix` markers (`search::highlight`).
pub fn highlight_terms(text: &str, query: &str, prefix: &str, suffix: &str) -> String {
    let q_terms = tokenize_fts(query);
    if q_terms.is_empty() {
        return text.to_string();
    }
    text.split_whitespace()
        .map(|word| {
            let clean = word
                .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_ascii_lowercase();
            if q_terms.contains(&clean) {
                format!("{}{}{}", prefix, word, suffix)
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
