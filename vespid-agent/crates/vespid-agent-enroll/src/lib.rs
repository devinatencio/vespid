//! # vespid-agent-enroll
//!
//! Agent-side enrollment client for the Vespid Agent. Mirrors
//! the Python security agent's `enrollment_client.py` and reuses the
//! server's existing auto-enrollment flow (`POST /api/v1/enroll`).
//!
//! Lifecycle:
//!
//! 1. **Cold start** — `Runtime::new` calls
//!    [`EnrollmentClient::ensure_credentials`]. If the
//!    `credentials.json` file is missing (or its API key is empty), the
//!    client sends an enrollment request and persists the new key.
//! 2. **Operational 401** — when the `Shipper` gets a 401 from any
//!    `POST /api/v1/metrics/write` call, it calls
//!    [`EnrollmentClient::try_rotate`] which re-enrolls with the old key
//!    in the `X-Existing-Credentials` header. The server revokes the
//!    old key in place and returns a new one.
//! 3. **Manual approval mode** — if the server is in
//!    `manual_approval` mode, the client polls `/api/v1/enroll/status/<node_id>`
//!    with exponential backoff via [`EnrollmentClient::poll_until_approved`].
//!
//! All persistent state (the API key, server URL, asset_id, host_id,
//! enrollment timestamp) is stored in
//! `/var/lib/vespid-agent/credentials.json` with mode `0600`.
//! The host_id is the linkage key between the security agent's key
//! and the monitor agent's key on the same physical host.

pub mod client;
pub mod config;
pub mod credentials;
pub mod error;

pub use client::{EnrollmentClient, EnrollmentOutcome};
pub use config::EnrollmentConfig;
pub use credentials::Credentials;
pub use error::{EnrollmentError, Result};
