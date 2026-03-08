use std::sync::Arc;

use crate::accounting::Accounting;

#[derive(Clone)]
pub struct TrafficRecorder {
    accounting: Arc<Accounting>,
    uid: i64,
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
            accounting,
            uid,
            direction: TrafficDirection::Upload,
        }
    }

    pub fn download(accounting: Arc<Accounting>, uid: i64) -> Self {
        Self {
            accounting,
            uid,
            direction: TrafficDirection::Download,
        }
    }

    pub fn record(&self, bytes: u64) {
        match self.direction {
            TrafficDirection::Upload => self.accounting.record_upload(self.uid, bytes),
            TrafficDirection::Download => self.accounting.record_download(self.uid, bytes),
        }
    }
}
