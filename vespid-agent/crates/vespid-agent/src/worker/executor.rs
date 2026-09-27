use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckJob {
    pub job_id: i64,
    pub check_id: i64,
    pub check_name: String,
    pub check_type: String,
    pub target: String,
    pub check_config: serde_json::Value,
    pub timeout_secs: u64,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub job_id: i64,
    pub success: bool,
    pub duration_ms: u64,
    pub status_code: Option<u16>,
    pub error_message: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[async_trait]
pub trait CheckExecutor: Send + Sync {
    fn check_type(&self) -> &'static str;

    async fn execute(
        &self,
        target: &str,
        config: &serde_json::Value,
        timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult;
}
