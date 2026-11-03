//! Shared newest-first paging for the flows/alerts views: merge live
//! rows with view-local history, collapse inclusive-cursor repeats.

use std::collections::HashSet;

/// Maximum chained fetches per click while pages add nothing visible.
pub const MAX_CHAIN: usize = 5;

/// A row that pages by timestamp and dedupes by id.
pub trait PagedRow: Clone {
    /// Stable identity for boundary-repeat collapse.
    fn page_id(&self) -> String;
    /// Recency timestamp, newest first.
    fn last_seen_ms(&self) -> u64;
}

impl PagedRow for crate::dto::FlowRecord {
    fn page_id(&self) -> String {
        self.row_key()
    }

    fn last_seen_ms(&self) -> u64 {
        self.last_seen_unix_ms
    }
}

impl PagedRow for crate::dto::AlertView {
    fn page_id(&self) -> String {
        self.id.clone()
    }

    fn last_seen_ms(&self) -> u64 {
        self.last_seen_unix_ms
    }
}

/// Merge live rows with paged history, newest-first, deduped by id. Live
/// rows win ties, so live arrivals always shadow stale paged copies.
pub fn merge_rows<T: PagedRow>(live: &[T], history: &[T]) -> Vec<T> {
    let mut seen = HashSet::new();
    let mut merged = Vec::with_capacity(live.len() + history.len());
    for row in live.iter().chain(history.iter()) {
        if seen.insert(row.page_id()) {
            merged.push(row.clone());
        }
    }
    merged.sort_by_key(|row| std::cmp::Reverse(row.last_seen_ms()));
    merged
}

/// Append page rows the history lacks; returns the count actually added.
/// Boundary repeats from the inclusive cursor collapse here.
pub fn append_new_rows<T: PagedRow>(history: &mut Vec<T>, page: &[T]) -> usize {
    let mut ids: HashSet<String> = history.iter().map(PagedRow::page_id).collect();
    let mut added = 0;
    for row in page {
        if ids.insert(row.page_id()) {
            history.push(row.clone());
            added += 1;
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Row {
        id: &'static str,
        ms: u64,
        label: &'static str,
    }

    impl PagedRow for Row {
        fn page_id(&self) -> String {
            self.id.to_owned()
        }

        fn last_seen_ms(&self) -> u64 {
            self.ms
        }
    }

    #[test]
    fn merge_prefers_live_and_sorts_newest_first() {
        let live = vec![
            Row {
                id: "a",
                ms: 3000,
                label: "live",
            },
            Row {
                id: "b",
                ms: 1000,
                label: "live",
            },
        ];
        // Same id as the first live row: the stale copy collapses.
        let history = vec![
            Row {
                id: "a",
                ms: 3000,
                label: "stale",
            },
            Row {
                id: "c",
                ms: 2000,
                label: "history",
            },
        ];
        let merged = merge_rows(&live, &history);
        assert_eq!(merged.len(), 3);
        let ms: Vec<u64> = merged.iter().map(PagedRow::last_seen_ms).collect();
        assert_eq!(ms, vec![3000, 2000, 1000]);
        assert_eq!(merged[0].label, "live");
    }

    #[test]
    fn append_collapses_boundary_repeats() {
        let mut history = vec![Row {
            id: "a",
            ms: 2000,
            label: "h",
        }];
        // Inclusive cursor repeats the boundary row, then older rows.
        let page = vec![
            Row {
                id: "a",
                ms: 2000,
                label: "p",
            },
            Row {
                id: "b",
                ms: 1000,
                label: "p",
            },
        ];
        assert_eq!(append_new_rows(&mut history, &page), 1);
        assert_eq!(history.len(), 2);
        assert_eq!(append_new_rows(&mut history, &page), 0);
    }
}
