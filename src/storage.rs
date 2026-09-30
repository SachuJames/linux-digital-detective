//! Bounded in-memory event storage.
//!
//! The store caps how many events it retains so a runaway evidence set
//! cannot grow memory without bound. When the cap is hit, the oldest events
//! (by insertion order) are evicted first and the eviction is counted, so
//! the report can say so honestly instead of silently losing data.

use crate::events::Event;

/// Default cap: large enough for serious investigations, small enough to
/// stay well clear of memory trouble on modest machines.
pub const DEFAULT_CAP: usize = 2_000_000;

pub struct EventStore {
    events: Vec<Event>,
    cap: usize,
    pub evicted: u64,
}

impl EventStore {
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::new(),
            cap,
            evicted: 0,
        }
    }

    pub fn push(&mut self, event: Event) {
        if self.events.len() >= self.cap {
            // Evict from the front in chunks to keep it amortized.
            let drop = (self.cap / 10).max(1);
            self.events.drain(..drop.min(self.events.len()));
            self.evicted += drop as u64;
        }
        self.events.push(event);
    }

    pub fn extend(&mut self, events: Vec<Event>) {
        for e in events {
            self.push(e);
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TimestampPrecision;
    use chrono::{FixedOffset, TimeZone};

    fn ev(id: u64) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(id as i64, 0)
            .unwrap();
        Event::builder(id, dt, "test", "f", id)
            .precision(TimestampPrecision::Second)
            .message("m")
            .build()
    }

    #[test]
    fn evicts_oldest_first_and_counts() {
        let mut s = EventStore::new(10);
        for i in 0..25 {
            s.push(ev(i));
        }
        assert!(s.len() <= 10);
        assert!(s.evicted > 0);
        // The newest event survives.
        assert!(s.events().iter().any(|e| e.id == 24));
    }
}
