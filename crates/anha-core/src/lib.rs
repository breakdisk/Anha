//! Core types for the AI Namespace & @ai Handle Architecture (ANHA).
//!
//! This crate is dependency-light on purpose: it holds the data types and
//! validation logic that every other crate in the workspace shares, with no
//! networking, storage-engine, or cryptography backends pulled in here.

pub mod error;
pub mod handle;
pub mod key;
pub mod record;

pub use error::{Error, Result};
pub use handle::{Handle, HandleKind};
pub use key::record_key;
pub use record::{
    AccessPolicy, AdminRoles, AgentRecord, CallerProof, CryptoAlgorithm, KeySupersede, OrderItem,
    PaymentApproval, PaymentRequest, Platform, Pricing, RecordType, RelayMode, SpendingPolicy,
};
