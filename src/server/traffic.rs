use std::sync::Arc;

use crate::accounting::{Accounting, UsageCounter};

#[derive(Clone)]
pub struct TrafficRecorder {
    counter: Arc<UsageCounter>,
    direction: TrafficDirection,
}

#[derive(Clone, Copy)]
enum TrafficDirection {
    Upload,
    Download,
}

impl TrafficRecorder {
    pub fn upload(accounting: Arc<Accounting>, uid: i64) -> Self {
        Self {
            counter: accounting.traffic_counter(uid),
            direction: TrafficDirection::Upload,
        }
    }

    pub fn download(accounting: Arc<Accounting>, uid: i64) -> Self {
        Self {
            counter: accounting.traffic_counter(uid),
            direction: TrafficDirection::Download,
        }
    }

    pub fn record(&self, bytes: u64) {
        match self.direction {
            TrafficDirection::Upload => self.counter.record_upload(bytes),
            TrafficDirection::Download => self.counter.record_download(bytes),
        }
    }
}
