//! The agent record: what a handle resolves to.
//!
//! NOTE: `signature` and `public_key` are carried as raw bytes here. This crate
//! does not verify them — signing/verification lives in a future `anha-crypto`
//! crate so the post-quantum backend can be swapped without touching core types.

use crate::error::{Error, Result};
use crate::handle::Handle;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Record type
// ---------------------------------------------------------------------------

/// Discriminates what kind of agent record this is.
///
/// Absent from JSON for `Standard` records so existing records are unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecordType {
    /// Regular agent handle (default).
    #[default]
    Standard,
    /// Brand apex record (`@brand.ai`); resolves directly to this agent.
    BrandApex,
    /// Personal identity + wallet record (`@name`).
    Personal,
    /// Alias record — the resolver follows `alias_of` to the canonical target.
    Alias,
}

fn is_standard_record_type(t: &RecordType) -> bool {
    *t == RecordType::Standard
}

// ---------------------------------------------------------------------------
// SpendingPolicy (Personal records)
// ---------------------------------------------------------------------------

/// Commerce authorisation policy embedded in a Personal identity record.
///
/// When a merchant sends a `PaymentRequest` to this identity, the wallet agent
/// checks the policy before issuing a one-time payment token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendingPolicy {
    /// Maximum USD amount that is auto-approved without human confirmation.
    pub max_per_transaction_usd: f64,
    /// Transactions at or above this threshold require explicit human approval.
    pub require_confirmation_above_usd: f64,
    /// Merchant handles permitted to request payment.
    /// Empty list = allow any verified agent (open wallet — use with caution).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_merchant_handles: Vec<String>,
    /// Category strings that are always blocked regardless of merchant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_categories: Vec<String>,
}

// ---------------------------------------------------------------------------
// Commerce protocol — PaymentRequest / PaymentApproval
// ---------------------------------------------------------------------------

/// One line item in a structured commerce order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderItem {
    /// Human-readable product name, e.g. `"Air Jordan 1 Size 7.5"`.
    pub name: String,
    /// Optional SKU or product code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<String>,
    /// Number of units ordered.
    pub quantity: u32,
    /// Price per unit in `currency`.
    pub unit_price: f64,
    /// ISO 4217 currency code, e.g. `"GBP"`.
    pub currency: String,
}

/// Structured payment request routed from a merchant agent to the payer's wallet.
///
/// Flow:
/// 1. Merchant receives an ANHA `CommerceRequest` and determines the price.
/// 2. Merchant embeds a `PaymentRequest` JSON block in its response between
///    `---ANHA_PAYMENT_REQUEST---` / `---END---` markers.
/// 3. ANHA parses it and routes it to the wallet agent at the payer's address.
/// 4. Wallet validates `SpendingPolicy`, charges via Stripe, returns `PaymentApproval`.
/// 5. ANHA routes `PaymentApproval` back to the merchant for order fulfillment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentRequest {
    /// Merchant ANHA handle, e.g. `"@nike"`.
    pub merchant_handle: String,
    /// Merchant's internal draft order ID.
    pub order_ref: String,
    /// Line items in this order.
    pub items: Vec<OrderItem>,
    /// Total amount to charge.
    pub amount: f64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Shipping address override — falls back to payer's `default_address`
    /// private capability when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shipping_address: Option<String>,
    /// Hex-encoded ML-KEM encapsulation key of the merchant agent.
    /// The wallet encrypts the `PaymentApproval` to this key so only the
    /// merchant can read the payment token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub merchant_kem_public_key: String,
}

/// Payment approval returned by the wallet agent after a successful charge.
///
/// Routed back through ANHA to the merchant, which then confirms the order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentApproval {
    /// Payment processor transaction ID, e.g. Stripe `pi_xxx`.
    pub payment_id: String,
    /// Actual amount charged.
    pub amount_charged: f64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Payer ANHA handle, e.g. `"@eduardcleofe"`.
    pub payer: String,
    /// The `order_ref` from the corresponding `PaymentRequest`.
    pub order_ref: String,
    /// `"succeeded"` | `"pending"` | `"requires_action"`.
    pub status: String,
}

// ---------------------------------------------------------------------------

/// The schema version understood by this build.
/// v2: ML-DSA-65 verifying keys (1952 B) + ML-KEM-768 encapsulation keys (1184 B).
///     Optionally carries `algorithm = ml_dsa44_ml_kem512` for IoT-tier records.
/// v1: Ed25519 + X25519 classical bridges (no longer issued).
pub const CURRENT_RECORD_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Crypto algorithm negotiation
// ---------------------------------------------------------------------------

fn is_default_algorithm(a: &CryptoAlgorithm) -> bool {
    *a == CryptoAlgorithm::MlDsa65MlKem768
}

/// Which post-quantum algorithm suite was used to sign and key this record.
///
/// The field is absent from JSON when the default (`ml_dsa65_ml_kem768`) is
/// used, preserving backward-compatibility with existing signed records.
/// Resolvers that encounter an unknown variant should reject the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CryptoAlgorithm {
    /// ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203) — server / cloud tier.
    /// Public key: 1952 B, signature: 3309 B, KEM ciphertext: 1088 B.
    #[default]
    MlDsa65MlKem768,
    /// ML-DSA-44 (FIPS 204) + ML-KEM-512 (FIPS 203) — IoT / constrained tier.
    /// Public key: 1312 B, signature: 2420 B, KEM ciphertext: 768 B.
    /// Suitable for ESP32-S3, Cortex-M33, and similar ≥ 512 KB SRAM devices.
    MlDsa44MlKem512,
}

// ---------------------------------------------------------------------------
// Platform routing (cross-platform agent communication)
// ---------------------------------------------------------------------------

/// Which AI platform hosts and runs this agent.
///
/// Controls how ANHA's routing tools reach the agent when the caller invokes
/// `send_message`:
/// - `Anha` (absent from JSON) — ANHA-native; reached via MCP at `addresses`.
/// - `Claude` — Anthropic Messages API.
/// - `Gemini` — Google Generative Language API.
/// - `OpenAi` — OpenAI Chat Completions API.
/// - `Meta` — Meta Llama API.
/// - `XAi` — xAI Grok API (OpenAI-compatible).
/// - `DeepSeek` — DeepSeek Chat API (OpenAI-compatible).
/// - `Mistral` — Mistral AI Chat API (OpenAI-compatible).
/// - `Nvidia` — Nvidia NIM API (OpenAI-compatible).
///
/// Absent from JSON for ANHA-native agents to preserve existing record signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// ANHA-native — reached via MCP ping at the addresses in the record.
    Anha,
    /// Claude (Anthropic) — reached via Anthropic Messages API.
    Claude,
    /// Gemini (Google) — reached via Google Generative Language API.
    Gemini,
    /// OpenAI — reached via OpenAI Chat Completions API.
    #[serde(rename = "openai")]
    OpenAi,
    /// Meta Llama — reached via Meta Llama API (OpenAI-compatible).
    Meta,
    /// xAI Grok — reached via xAI API (OpenAI-compatible).
    #[serde(rename = "xai")]
    XAi,
    /// DeepSeek — reached via DeepSeek Chat API (OpenAI-compatible).
    DeepSeek,
    /// Mistral AI — reached via Mistral Chat API (OpenAI-compatible).
    Mistral,
    /// Nvidia NIM — reached via Nvidia NIM API (OpenAI-compatible).
    Nvidia,
}

fn default_record_version() -> u32 {
    0 // absence of the field in JSON → version 0 (pre-versioning records)
}

fn is_version_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Schema version. Absent (= 0) in records created before versioning was added.
    /// Clients must reject records with a version higher than [`CURRENT_RECORD_VERSION`]
    /// — the record may contain required fields this build doesn't know about.
    #[serde(
        default = "default_record_version",
        skip_serializing_if = "is_version_zero"
    )]
    pub version: u32,
    pub handle: Handle,
    /// Hex-encoded ML-DSA verifying key — size depends on [`CryptoAlgorithm`]:
    /// - `ml_dsa65_ml_kem768` (default): 1952 bytes (3904 hex chars)
    /// - `ml_dsa44_ml_kem512` (IoT): 1312 bytes (2624 hex chars)
    pub public_key: String,
    /// Hex-encoded ML-KEM encapsulation key used for the Layer 2 KEM handshake.
    /// Size depends on [`CryptoAlgorithm`]:
    /// - `ml_dsa65_ml_kem768` (default): 1184 bytes (2368 hex chars)
    /// - `ml_dsa44_ml_kem512` (IoT): 800 bytes (1600 hex chars)
    ///
    /// Absent from JSON when empty (pre-KEM records) to preserve their signatures.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kem_public_key: String,
    /// Post-quantum algorithm suite used to sign and key this record.
    /// Absent from JSON for the default (`ml_dsa65_ml_kem768`) to preserve
    /// existing record signatures.
    #[serde(default, skip_serializing_if = "is_default_algorithm")]
    pub algorithm: CryptoAlgorithm,
    /// Network endpoints (multiaddrs, URLs, host:port).
    pub addresses: Vec<String>,
    /// Capability strings, e.g. "reasoning:chain-of-thought".
    pub capabilities: Vec<String>,
    /// Supported communication protocols, e.g. ["mcp", "a2a"].
    #[serde(default)]
    pub protocols: Vec<String>,
    /// Reputation in [0.0, 1.0]. Starts at 0.5 for new agents.
    pub reputation: f64,
    /// Unix seconds when registered.
    pub registered_at: i64,
    /// Seconds the record stays valid before renewal is required.
    pub ttl_secs: u64,
    #[serde(default)]
    pub pricing: Option<Pricing>,
    /// How to reach this agent when it is behind a firewall (RFC_ADDENDUM_FIREWALL §4).
    ///
    /// `None` (absent from JSON) — directly reachable; addresses are dialable.
    /// `Some(RelayMode::Circuit)` — addresses list a relay endpoint; the agent
    ///   holds an outbound circuit-relay reservation.
    /// `Some(RelayMode::StoreForward)` — relay queues for offline agents.
    ///
    /// `skip_serializing_if = Option::is_none` keeps the field absent from
    /// directly-reachable records, preserving existing signature bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_mode: Option<RelayMode>,
    /// Access control policy (Zero Trust L4 — RFC_ADDENDUM_ZERO_TRUST §3).
    /// Absent = `Public` (any authenticated agent may call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AccessPolicy>,
    /// RBAC policy for administrative operations on this record.
    /// Absent = only the record owner (matching `public_key`) may perform admin ops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_roles: Option<AdminRoles>,
    /// Key rotation proof linking the new public key to the previous one.
    /// Allows a resolver to accept records signed with `public_key` as a
    /// legitimate successor to `previous_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_supersede: Option<KeySupersede>,
    /// Capabilities that should not appear in the public DHT record.
    ///
    /// Each entry is `hex(ML-KEM-encrypt(plaintext_capability))` using the
    /// agent's own `kem_public_key` (ML-KEM-768 for full-tier, ML-KEM-512 for
    /// IoT-tier agents).  Frame: `[KEM-ciphertext | ChaCha20-Poly1305-ciphertext]`.
    /// Only the agent can decrypt these; resolvers carry them opaquely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_capabilities: Vec<String>,
    /// Revocation timestamp in Unix seconds (Zero Trust L5 — RFC_ADDENDUM_ZERO_TRUST §4).
    /// When set and `≤ now`, the record is treated as revoked by the resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// Hosting platform for cross-platform routing via ANHA's `send_message` tool.
    /// Absent from JSON for ANHA-native agents to preserve existing signatures.
    /// When `Some`, the router uses `api_endpoint` (or the platform default URL) to
    /// forward messages to the agent on its native platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// HTTP API endpoint for cross-platform routing.
    /// Absent = use the platform's standard endpoint URL.
    /// Example: `"https://api.openai.com/v1/chat/completions"`.
    /// Ignored when `platform` is absent or `Anha`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    /// Detached signature over the canonical record (verified elsewhere).
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Record type — controls resolver alias-following and commerce auth.
    /// Absent from JSON for `Standard` records (backward compat).
    #[serde(default, skip_serializing_if = "is_standard_record_type")]
    pub record_type: RecordType,
    /// For `Alias` records: the canonical handle this alias points to.
    /// The resolver follows this chain (max 2 hops) to the real AgentRecord.
    /// Absent from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
    /// For `Personal` records: per-merchant spending authorisation policy.
    /// Absent from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spending_policy: Option<SpendingPolicy>,
}

// ---------------------------------------------------------------------------
// Admin RBAC (enterprise gap — priority matrix item 4)
// ---------------------------------------------------------------------------

/// Role-based access control for administrative operations on an AgentRecord.
///
/// Each role lists the Ed25519 public keys (hex) or ANHA handles authorised
/// to perform that operation.  An empty list means "owner only".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AdminRoles {
    /// Who may revoke this handle (`anha revoke`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke: Vec<String>,
    /// Who may rotate the signing key (`anha rotate-key`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotate: Vec<String>,
    /// Who may update the access policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_admin: Vec<String>,
}

impl AdminRoles {
    /// Returns `true` if `actor_pk_hex` is authorised for the given role.
    /// An empty role list means only the record owner is authorised.
    pub fn is_authorised(role: &[String], actor_pk_hex: &str, owner_pk_hex: &str) -> bool {
        if role.is_empty() {
            actor_pk_hex == owner_pk_hex
        } else {
            role.iter().any(|r| r == actor_pk_hex)
        }
    }
}

// ---------------------------------------------------------------------------
// Key rotation / supersede (priority matrix gap 1)
// ---------------------------------------------------------------------------

/// Proof that the current `AgentRecord.public_key` is the authorised successor
/// to a previous signing key.
///
/// # How rotation works
///
/// 1. Generate a new seed and derive the new ML-DSA keypair.
/// 2. Sign `new_public_key_hex` bytes with the **old** signing key.
/// 3. Set `previous_public_key` and `previous_signature` in the record,
///    then sign the whole record with the **new** key.
/// 4. Publish.  Verifiers that still hold the old key can confirm the
///    rotation is legitimate; callers need no out-of-band notification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeySupersede {
    /// Hex-encoded ML-DSA verifying key that this record replaces.
    pub previous_public_key: String,
    /// ML-DSA signature (hex) by `previous_public_key` over
    /// `new_public_key_hex` bytes — proves the old key authorised the rotation.
    pub previous_signature: String,
}

// ---------------------------------------------------------------------------
// Zero Trust types (RFC_ADDENDUM_ZERO_TRUST)
// ---------------------------------------------------------------------------

/// Signed proof of caller identity embedded in every MCP request (L3).
///
/// The ML-DSA signature covers a canonical byte string that binds the proof
/// to a specific method, request id, nonce, and target agent handle, preventing
/// cross-request, cross-agent, and replay attacks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallerProof {
    /// Handle of the calling agent, e.g. `"@worker.acme.ai"`.
    pub handle: String,
    /// Hex-encoded ML-DSA verifying key (must match the resolved record).
    pub public_key: String,
    /// Anti-replay nonce: `(random_u32 << 32) | unix_secs_u32`.
    /// Valid within ±[`CallerProof::FRESHNESS_WINDOW_SECS`] of server clock.
    pub nonce: u64,
    /// Hex-encoded ML-DSA signature over [`CallerProof::signing_bytes`].
    pub signature: String,
}

impl CallerProof {
    /// Freshness window accepted by the server (5 minutes).
    pub const FRESHNESS_WINDOW_SECS: u64 = 300;

    /// Canonical byte string signed by the caller.
    ///
    /// Format (unambiguous, length-prefixed):
    /// `u32_be(len(method)) || method || u32_be(len(id)) || id
    ///  || u64_be(nonce) || u32_be(len(target)) || target`
    pub fn signing_bytes(method: &str, id: &str, nonce: u64, target_handle: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(method.len() as u32).to_be_bytes());
        buf.extend_from_slice(method.as_bytes());
        buf.extend_from_slice(&(id.len() as u32).to_be_bytes());
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(&nonce.to_be_bytes());
        buf.extend_from_slice(&(target_handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(target_handle.as_bytes());
        buf
    }

    /// Extract the Unix-seconds timestamp from the lower 32 bits of the nonce.
    pub fn nonce_unix_secs(nonce: u64) -> u64 {
        nonce & 0xFFFF_FFFF
    }

    /// True if the nonce timestamp is within the freshness window of `now_secs`.
    pub fn is_fresh(nonce: u64, now_secs: u64) -> bool {
        Self::nonce_unix_secs(nonce).abs_diff(now_secs) <= Self::FRESHNESS_WINDOW_SECS
    }
}

/// Access control policy for this agent (Zero Trust L4 — RFC_ADDENDUM_ZERO_TRUST §3).
///
/// Absent from JSON (`None`) is equivalent to [`AccessPolicy::Public`] and
/// preserves the canonical bytes of existing signed records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccessPolicy {
    /// Any authenticated agent may call (default).
    Public,
    /// Caller's `AgentRecord.capabilities` must contain at least one of these strings.
    RequireCapability { any_of: Vec<String> },
    /// Only agents whose handle appears in this list may call.
    AllowList { handles: Vec<String> },
}

impl AccessPolicy {
    /// Returns `true` when `caller_handle` / `caller_caps` satisfy the policy.
    pub fn allows(&self, caller_handle: &str, caller_caps: &[String]) -> bool {
        match self {
            Self::Public => true,
            Self::RequireCapability { any_of } => any_of.iter().any(|c| caller_caps.contains(c)),
            Self::AllowList { handles } => handles.iter().any(|h| h == caller_handle),
        }
    }
}

// ---------------------------------------------------------------------------

/// How to reach the agent when it cannot accept inbound connections directly
/// (RFC_ADDENDUM_FIREWALL §4).
///
/// `None` (absent from JSON) means the agent is directly reachable at the
/// advertised addresses — no relay is involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    /// Rung 3 — relay bridges an active outbound connection from the agent.
    /// The sender connects to the relay; traffic is tunnelled to the agent.
    Circuit,
    /// Relay queues messages when the agent is offline and delivers them when
    /// the outbound connection is re-established (DIDComm Pickup pattern).
    StoreForward,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pricing {
    pub base_rate_usd: f64,
    pub per_token_usd: f64,
}

impl AgentRecord {
    /// Construct a new record with sane defaults (reputation 0.5, empty signature).
    pub fn new(
        handle: Handle,
        public_key: impl Into<String>,
        addresses: Vec<String>,
        capabilities: Vec<String>,
        registered_at: i64,
        ttl_secs: u64,
    ) -> Self {
        Self {
            version: CURRENT_RECORD_VERSION,
            handle,
            public_key: public_key.into(),
            kem_public_key: String::new(),
            algorithm: CryptoAlgorithm::default(),
            addresses,
            capabilities,
            protocols: Vec::new(),
            reputation: 0.5,
            registered_at,
            ttl_secs,
            pricing: None,
            relay_mode: None,
            access_policy: None,
            admin_roles: None,
            key_supersede: None,
            private_capabilities: Vec::new(),
            revoked_at: None,
            platform: None,
            api_endpoint: None,
            signature: Vec::new(),
            record_type: RecordType::Standard,
            alias_of: None,
            spending_policy: None,
        }
    }

    /// Basic structural validation (does NOT check the signature).
    pub fn validate(&self) -> Result<()> {
        if self.version > CURRENT_RECORD_VERSION {
            return Err(Error::InvalidRecord(format!(
                "record version {} is newer than this client understands (max {})",
                self.version, CURRENT_RECORD_VERSION
            )));
        }

        // Alias records defer all content to their target — only alias_of is required.
        if self.record_type == RecordType::Alias {
            if self.alias_of.is_none() {
                return Err(Error::InvalidRecord(
                    "alias record missing alias_of field".into(),
                ));
            }
            return Ok(());
        }

        if self.public_key.is_empty() {
            return Err(Error::InvalidRecord("empty public_key".into()));
        }
        if self.addresses.is_empty() {
            return Err(Error::InvalidRecord("no addresses".into()));
        }
        if self.capabilities.is_empty() {
            return Err(Error::InvalidRecord("no capabilities".into()));
        }
        if !(0.0..=1.0).contains(&self.reputation) {
            return Err(Error::InvalidRecord(format!(
                "reputation out of range: {}",
                self.reputation
            )));
        }
        Ok(())
    }

    /// True if the record has passed its TTL relative to `now` (unix seconds).
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.registered_at + self.ttl_secs as i64
    }

    /// Canonical bytes used as the message for signing/verification.
    /// Excludes the signature field itself.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        Ok(serde_json::to_vec(&unsigned)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentRecord {
        AgentRecord::new(
            Handle::parse("@reasoning.acme.ai").unwrap(),
            "deadbeef",
            vec!["/ip4/192.0.2.100/tcp/50051".into()],
            vec!["reasoning:chain-of-thought".into()],
            1_718_000_000,
            3600,
        )
    }

    #[test]
    fn valid_record_passes() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn expiry_logic() {
        let r = sample();
        assert!(!r.is_expired(1_718_000_000));
        assert!(!r.is_expired(1_718_003_600));
        assert!(r.is_expired(1_718_003_601));
    }

    #[test]
    fn canonical_bytes_exclude_signature() {
        let mut r = sample();
        let before = r.canonical_bytes().unwrap();
        r.signature = vec![1, 2, 3, 4];
        let after = r.canonical_bytes().unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn record_round_trips_json() {
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        let back: AgentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn version_field_present_in_new_records() {
        let r = sample();
        assert_eq!(r.version, CURRENT_RECORD_VERSION);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"version\""), "version must appear in JSON");
    }

    #[test]
    fn kem_public_key_empty_absent_from_json() {
        // Records without a kem_public_key (pre-items-1-4) must serialise
        // without the field so canonical_bytes() is unchanged and the original
        // signature remains valid.
        let r = sample(); // new() sets kem_public_key = ""
        assert!(r.kem_public_key.is_empty());
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("kem_public_key"),
            "empty kem_public_key must not appear in JSON"
        );
    }

    #[test]
    fn kem_public_key_present_in_json_when_set() {
        let mut r = sample();
        r.kem_public_key = "deadbeef".into();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("kem_public_key"));
    }

    #[test]
    fn pre_kem_record_canonical_bytes_unchanged() {
        // Simulate a record stored before kem_public_key was added:
        // the JSON has no kem_public_key field.
        let json_without_kem = r#"{
            "version": 1,
            "handle": {"agent": "reasoning", "organization": "acme"},
            "public_key": "deadbeef",
            "addresses": ["/ip4/192.0.2.100/tcp/50051"],
            "capabilities": ["reasoning:chain-of-thought"],
            "protocols": [],
            "reputation": 0.5,
            "registered_at": 1718000000,
            "ttl_secs": 3600,
            "signature": []
        }"#;
        let record: AgentRecord = serde_json::from_str(json_without_kem).unwrap();
        assert!(record.kem_public_key.is_empty());
        // canonical_bytes must NOT include kem_public_key
        let canonical = String::from_utf8(record.canonical_bytes().unwrap()).unwrap();
        assert!(
            !canonical.contains("kem_public_key"),
            "canonical bytes must not include empty kem_public_key: {canonical}"
        );
    }

    #[test]
    fn version_zero_absent_from_json() {
        // Old records (version 0) must serialise without the version key
        // so existing stored data is not invalidated by a round-trip.
        let mut r = sample();
        r.version = 0;
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("\"version\""),
            "version 0 must not appear in JSON"
        );
        let back: AgentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 0);
    }

    #[test]
    fn future_version_rejected() {
        let mut r = sample();
        r.version = CURRENT_RECORD_VERSION + 1;
        assert!(r.validate().is_err());
    }

    #[test]
    fn default_algorithm_absent_from_json() {
        let r = sample();
        assert_eq!(r.algorithm, CryptoAlgorithm::MlDsa65MlKem768);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("algorithm"),
            "default algorithm must not appear in JSON to preserve existing signatures"
        );
    }

    #[test]
    fn iot_algorithm_present_in_json() {
        let mut r = sample();
        r.algorithm = CryptoAlgorithm::MlDsa44MlKem512;
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"algorithm\":\"ml_dsa44_ml_kem512\""));
    }

    #[test]
    fn algorithm_round_trips_json() {
        let mut r = sample();
        r.algorithm = CryptoAlgorithm::MlDsa44MlKem512;
        let json = serde_json::to_string(&r).unwrap();
        let back: AgentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.algorithm, CryptoAlgorithm::MlDsa44MlKem512);
    }

    #[test]
    fn missing_algorithm_defaults_to_full_tier() {
        // Records without an algorithm field (pre-IoT-tier) must default to ML-DSA-65.
        let json = r#"{
            "version": 2,
            "handle": {"agent": "reasoning", "organization": "acme"},
            "public_key": "deadbeef",
            "addresses": ["/ip4/192.0.2.100/tcp/50051"],
            "capabilities": ["reasoning:chain-of-thought"],
            "protocols": [],
            "reputation": 0.5,
            "registered_at": 1718000000,
            "ttl_secs": 3600,
            "signature": []
        }"#;
        let r: AgentRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.algorithm, CryptoAlgorithm::MlDsa65MlKem768);
    }

    // -----------------------------------------------------------------------
    // Platform field tests
    // -----------------------------------------------------------------------

    #[test]
    fn platform_absent_from_json_by_default() {
        let r = sample(); // platform: None
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("platform"),
            "platform must not appear in JSON when None: {json}"
        );
    }

    #[test]
    fn api_endpoint_absent_from_json_by_default() {
        let r = sample(); // api_endpoint: None
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("api_endpoint"),
            "api_endpoint must not appear in JSON when None: {json}"
        );
    }

    #[test]
    fn platform_present_in_json_when_set() {
        let mut r = sample();
        r.platform = Some(Platform::Claude);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"platform\":\"claude\""),
            "platform must appear in JSON: {json}"
        );
    }

    #[test]
    fn api_endpoint_present_in_json_when_set() {
        let mut r = sample();
        r.api_endpoint = Some("https://api.openai.com/v1/chat/completions".into());
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("api_endpoint"),
            "api_endpoint must appear in JSON when set: {json}"
        );
    }

    #[test]
    fn platform_round_trips_all_variants() {
        for platform in [
            Platform::Anha,
            Platform::Claude,
            Platform::Gemini,
            Platform::OpenAi,
            Platform::Meta,
        ] {
            let mut r = sample();
            r.platform = Some(platform.clone());
            let json = serde_json::to_string(&r).unwrap();
            let back: AgentRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(
                back.platform,
                Some(platform.clone()),
                "round-trip failed for {platform:?}"
            );
        }
    }

    #[test]
    fn openai_platform_serializes_as_openai() {
        let mut r = sample();
        r.platform = Some(Platform::OpenAi);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"platform\":\"openai\""),
            "OpenAi variant must serialize as 'openai': {json}"
        );
    }

    #[test]
    fn existing_record_canonical_bytes_unchanged_by_new_fields() {
        // A record with no platform/api_endpoint (the common case) must produce
        // the same canonical bytes as before the fields were introduced.
        let r = sample();
        assert!(r.platform.is_none());
        assert!(r.api_endpoint.is_none());
        let json = String::from_utf8(r.canonical_bytes().unwrap()).unwrap();
        assert!(
            !json.contains("platform"),
            "platform must not affect canonical bytes when None"
        );
        assert!(
            !json.contains("api_endpoint"),
            "api_endpoint must not affect canonical bytes when None"
        );
    }

    // ── RecordType / SpendingPolicy / alias_of ────────────────────────────

    #[test]
    fn record_type_absent_from_json_for_standard() {
        let r = sample();
        assert_eq!(r.record_type, RecordType::Standard);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("record_type"),
            "record_type must be absent for Standard: {json}"
        );
    }

    #[test]
    fn alias_record_type_present_in_json() {
        let mut r = sample();
        r.record_type = RecordType::Alias;
        r.alias_of = Some("@storefront.nike.ai".into());
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"record_type\":\"alias\""),
            "alias type missing: {json}"
        );
        assert!(json.contains("alias_of"), "alias_of missing: {json}");
    }

    #[test]
    fn alias_record_validate_requires_alias_of() {
        let mut r = sample();
        r.record_type = RecordType::Alias;
        // alias_of is None → must fail
        assert!(
            r.validate().is_err(),
            "alias record without alias_of must fail validation"
        );
        r.alias_of = Some("@storefront.nike.ai".into());
        assert!(r.validate().is_ok(), "alias record with alias_of must pass");
    }

    #[test]
    fn alias_record_skips_address_and_capability_checks() {
        let h = Handle::parse("@nike.ai").unwrap();
        let mut r = AgentRecord::new(h, "", vec![], vec![], 1_718_000_000, 3600);
        r.record_type = RecordType::Alias;
        r.alias_of = Some("@storefront.nike.ai".into());
        // empty public_key, addresses, capabilities — must still pass for Alias
        assert!(r.validate().is_ok());
    }

    #[test]
    fn personal_record_round_trips_spending_policy() {
        let mut r = sample();
        r.record_type = RecordType::Personal;
        r.spending_policy = Some(SpendingPolicy {
            max_per_transaction_usd: 500.0,
            require_confirmation_above_usd: 300.0,
            allowed_merchant_handles: vec!["@nike".into(), "@adidas.ai".into()],
            blocked_categories: vec!["gambling".into()],
        });
        let json = serde_json::to_string(&r).unwrap();
        let back: AgentRecord = serde_json::from_str(&json).unwrap();
        let sp = back.spending_policy.unwrap();
        assert_eq!(sp.max_per_transaction_usd, 500.0);
        assert_eq!(sp.allowed_merchant_handles, vec!["@nike", "@adidas.ai"]);
        assert_eq!(sp.blocked_categories, vec!["gambling"]);
    }

    // ── PaymentRequest / PaymentApproval / OrderItem ─────────────────────

    #[test]
    fn order_item_round_trips_json() {
        let item = OrderItem {
            name: "Air Jordan 1 Size 7.5".into(),
            sku: Some("AJ1-75".into()),
            quantity: 1,
            unit_price: 149.99,
            currency: "GBP".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: OrderItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn order_item_sku_absent_when_none() {
        let item = OrderItem {
            name: "Shoe".into(),
            sku: None,
            quantity: 1,
            unit_price: 50.0,
            currency: "USD".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(
            !json.contains("sku"),
            "sku must be absent when None: {json}"
        );
    }

    #[test]
    fn payment_request_round_trips_json() {
        let pr = PaymentRequest {
            merchant_handle: "@nike".into(),
            order_ref: "NKE-88421".into(),
            items: vec![OrderItem {
                name: "Air Jordan 1 Size 7.5".into(),
                sku: Some("AJ1-75".into()),
                quantity: 1,
                unit_price: 149.99,
                currency: "GBP".into(),
            }],
            amount: 149.99,
            currency: "GBP".into(),
            shipping_address: Some("10 St London SW1A 2AA".into()),
            merchant_kem_public_key: "deadbeef".into(),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let back: PaymentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(pr, back);
    }

    #[test]
    fn payment_request_optional_fields_absent_when_empty() {
        let pr = PaymentRequest {
            merchant_handle: "@nike".into(),
            order_ref: "NKE-001".into(),
            items: vec![],
            amount: 0.0,
            currency: "GBP".into(),
            shipping_address: None,
            merchant_kem_public_key: String::new(),
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(
            !json.contains("shipping_address"),
            "shipping_address must be absent: {json}"
        );
        assert!(
            !json.contains("merchant_kem_public_key"),
            "kem key must be absent: {json}"
        );
    }

    #[test]
    fn payment_approval_round_trips_json() {
        let pa = PaymentApproval {
            payment_id: "pi_3abc123".into(),
            amount_charged: 149.99,
            currency: "GBP".into(),
            payer: "@eduardcleofe".into(),
            order_ref: "NKE-88421".into(),
            status: "succeeded".into(),
        };
        let json = serde_json::to_string(&pa).unwrap();
        let back: PaymentApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(pa, back);
    }

    #[test]
    fn existing_record_unaffected_by_record_type_fields() {
        // Pre-existing JSON without record_type/alias_of/spending_policy must
        // deserialise with Standard defaults and produce unchanged canonical bytes.
        let json = r#"{
            "version": 2,
            "handle": {"agent": "reasoning", "organization": "acme"},
            "public_key": "deadbeef",
            "addresses": ["/ip4/192.0.2.100/tcp/50051"],
            "capabilities": ["reasoning:chain-of-thought"],
            "protocols": [],
            "reputation": 0.5,
            "registered_at": 1718000000,
            "ttl_secs": 3600,
            "signature": []
        }"#;
        let r: AgentRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.record_type, RecordType::Standard);
        assert!(r.alias_of.is_none());
        assert!(r.spending_policy.is_none());
        // Canonical bytes must not include the new fields
        let canonical = String::from_utf8(r.canonical_bytes().unwrap()).unwrap();
        assert!(
            !canonical.contains("record_type"),
            "record_type must be absent: {canonical}"
        );
        assert!(
            !canonical.contains("alias_of"),
            "alias_of must be absent: {canonical}"
        );
        assert!(
            !canonical.contains("spending_policy"),
            "spending_policy must be absent: {canonical}"
        );
    }

    #[test]
    fn record_with_platform_and_endpoint_round_trips() {
        let mut r = sample();
        r.platform = Some(Platform::Gemini);
        r.api_endpoint = Some("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent".into());
        let json = serde_json::to_string(&r).unwrap();
        let back: AgentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.platform, Some(Platform::Gemini));
        assert!(back.api_endpoint.unwrap().contains("gemini"));
    }
}
