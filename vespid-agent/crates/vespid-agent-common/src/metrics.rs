use bytes::Bytes;
use chrono::{DateTime, Utc};
use prost::Message;
use snap::raw::Encoder as SnappyEncoder;

use crate::Metric;

pub const REMOTE_WRITE_CONTENT_TYPE: &str = "application/x-protobuf";
pub const REMOTE_WRITE_CONTENT_ENCODING: &str = "snappy";

#[derive(Debug, Clone)]
pub struct WriteRequestMetadata {
    pub agent_id: String,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct EncodedBatch {
    pub data: Bytes,
    pub compressed_size: usize,
    pub metric_count: usize,
}

impl EncodedBatch {
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            compressed_size: 0,
            metric_count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.metric_count == 0
    }
}

pub struct BatchEncoder {
    metrics: Vec<Metric>,
    capacity: usize,
}

impl BatchEncoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            metrics: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn add(&mut self, metric: Metric) -> bool {
        if self.metrics.len() >= self.capacity {
            return false;
        }
        self.metrics.push(metric);
        true
    }

    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
    }

    pub fn is_ready(&self) -> bool {
        self.metrics.len() >= self.capacity
    }

    pub fn encode(&mut self) -> crate::error::Result<EncodedBatch> {
        if self.metrics.is_empty() {
            return Ok(EncodedBatch::empty());
        }

        let request = crate::metrics_to_write_request(&self.metrics);
        let raw_bytes = request.encode_to_vec();
        let metric_count = self.metrics.len();
        self.metrics.clear();

        let compressed = SnappyEncoder::new()
            .compress_vec(&raw_bytes)
            .map_err(|e| crate::error::VespidAgentError::Snappy(e.to_string()))?;

        let compressed_size = raw_bytes.len();

        Ok(EncodedBatch {
            data: Bytes::from(compressed),
            compressed_size,
            metric_count,
        })
    }
}
