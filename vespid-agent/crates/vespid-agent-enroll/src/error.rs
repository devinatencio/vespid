//! Errors for the enrollment crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnrollmentError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Enrollment rejected by server ({status}): {detail}")]
    Rejected { status: u16, detail: String },

    #[error("Enrollment is pending operator approval; not yet approved")]
    Pending,

    #[error("Enrollment is permanently disabled on the server")]
    Disabled,

    #[error("Node is already enrolled with a different key; rotate the existing one first")]
    AlreadyEnrolled,

    #[error("Rate limited by the server; retry after a backoff")]
    RateLimited,

    #[error("Missing or invalid credentials file: {0}")]
    InvalidCredentials(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, EnrollmentError>;
