use thiserror::Error;

#[derive(Error, Debug)]
pub enum VespidAgentError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Collection error: {0}")]
    Collection(String),

    #[error("Buffer error: {0}")]
    Buffer(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Enrollment error: {0}")]
    Enrollment(String),

    #[error("Protobuf error: {0}")]
    Protobuf(String),

    #[error("Snappy compression error: {0}")]
    Snappy(String),
}

pub type Result<T> = std::result::Result<T, VespidAgentError>;
