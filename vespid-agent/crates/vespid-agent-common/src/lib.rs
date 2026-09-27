pub mod error;
pub mod metrics;

pub mod prometheus {
    include!(concat!(env!("OUT_DIR"), "/prometheus.rs"));
}

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricLabel {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricSample {
    pub value: f64,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Metric {
    pub labels: Vec<MetricLabel>,
    pub sample: MetricSample,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricBatch {
    pub agent_id: String,
    pub hostname: String,
    pub collected_at: DateTime<Utc>,
    pub metrics: Vec<Metric>,
}

pub fn metric_to_timeseries(m: &Metric) -> prometheus::TimeSeries {
    prometheus::TimeSeries {
        labels: m
            .labels
            .iter()
            .map(|l| prometheus::Label {
                name: l.name.clone(),
                value: l.value.clone(),
            })
            .collect(),
        samples: vec![prometheus::Sample {
            value: m.sample.value,
            timestamp: m.sample.timestamp_ms,
        }],
        exemplars: vec![],
    }
}

pub fn metrics_to_write_request(metrics: &[Metric]) -> prometheus::WriteRequest {
    prometheus::WriteRequest {
        timeseries: metrics.iter().map(metric_to_timeseries).collect(),
    }
}
