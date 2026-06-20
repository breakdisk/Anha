//! The `@ai` handle type — three syntaxes supported:
//!
//! | Syntax          | Example              | Use case                    |
//! |-----------------|----------------------|-----------------------------|
//! | Standard        | `@agent.org.ai`      | Regular agent handle        |
//! | Brand apex      | `@nike.ai`           | Brand / vanity handle       |
//! | Short / personal| `@eduardcleofe`      | Personal identity / wallet  |

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// HandleKind
// ---------------------------------------------------------------------------

/// Discriminates the three supported handle syntaxes.
///
/// Absent from JSON for `Standard` handles so existing records round-trip
/// without gaining a new field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HandleKind {
    /// `@agent.org.ai` — standard multi-label handle (default).
    #[default]
    Standard,
    /// `@brand.ai` — brand apex (organisation only, no agent sublabel).
    BrandApex,
    /// `@name` — short / personal handle with no TLD.
    Short,
}

fn is_standard(k: &HandleKind) -> bool {
    *k == HandleKind::Standard
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// A parsed and validated ANHA handle.
///
/// Three syntaxes are accepted by [`Handle::parse`]:
///
/// - **Standard** `@agent.org.ai` — the original multi-label format.
///   `agent()` returns the agent sublabel, `organization()` returns the org.
/// - **Brand apex** `@brand.ai` — a single label plus the `.ai` TLD.
///   Both `agent()` and `organization()` return the brand name.
/// - **Short** `@name` — no TLD at all, used for personal identity handles.
///   `agent()` returns the name; `organization()` returns `""`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle {
    /// Absent from JSON for `Standard` handles to preserve existing records.
    #[serde(default, skip_serializing_if = "is_standard")]
    pub kind: HandleKind,
    /// Agent sublabel (Standard) or single name (BrandApex / Short).
    agent: String,
    /// Organisation label (Standard / BrandApex) or `""` (Short).
    organization: String,
}

impl Handle {
    /// Maximum length of the agent / brand / personal name label.
    pub const MAX_AGENT_LEN: usize = 32;
    /// Maximum length of the organisation label (per segment).
    pub const MAX_ORG_LEN: usize = 64;

    // ── Parsing ─────────────────────────────────────────────────────────────

    /// Parse any supported handle syntax.
    ///
    /// ```
    /// # use anha_core::Handle;
    /// let std  = Handle::parse("@agent.acme.ai").unwrap();
    /// let apex = Handle::parse("@nike.ai").unwrap();
    /// let short = Handle::parse("@eduardcleofe").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let stripped = input
            .strip_prefix('@')
            .ok_or_else(|| Error::InvalidHandle(format!("missing leading '@': {input}")))?;

        if stripped.is_empty() {
            return Err(Error::InvalidHandle("empty handle after '@'".into()));
        }

        // ── Short: no dot at all ─────────────────────────────────────────
        if !stripped.contains('.') {
            validate_label("handle", stripped, Self::MAX_AGENT_LEN)?;
            return Ok(Self {
                kind: HandleKind::Short,
                agent: stripped.to_owned(),
                organization: String::new(),
            });
        }

        // ── Must end in .ai from here ───────────────────────────────────
        let without_tld = stripped.strip_suffix(".ai").ok_or_else(|| {
            Error::InvalidHandle(format!(
                "must end in '.ai' or contain no TLD at all: {input}"
            ))
        })?;

        if without_tld.is_empty() {
            return Err(Error::InvalidHandle(format!(
                "empty label before '.ai': {input}"
            )));
        }

        // ── Brand apex: single label + .ai ──────────────────────────────
        if !without_tld.contains('.') {
            validate_label("brand", without_tld, Self::MAX_AGENT_LEN)?;
            return Ok(Self {
                kind: HandleKind::BrandApex,
                agent: without_tld.to_owned(),
                organization: without_tld.to_owned(),
            });
        }

        // ── Standard: @agent.org.ai ─────────────────────────────────────
        let (agent, organization) = without_tld
            .split_once('.')
            .ok_or_else(|| Error::InvalidHandle(format!("expected @agent.org.ai: {input}")))?;

        Self::new_standard(agent, organization)
    }

    // ── Constructors ────────────────────────────────────────────────────────

    /// Build a **standard** handle `@agent.org.ai` from separated parts.
    ///
    /// The organisation may contain dots (multi-segment org label is fine).
    pub fn new(agent: impl Into<String>, organization: impl Into<String>) -> Result<Self> {
        Self::new_standard(agent, organization)
    }

    /// Build a **brand apex** handle `@brand.ai`.
    pub fn new_brand_apex(brand: impl Into<String>) -> Result<Self> {
        let brand = brand.into();
        validate_label("brand", &brand, Self::MAX_AGENT_LEN)?;
        Ok(Self {
            kind: HandleKind::BrandApex,
            agent: brand.clone(),
            organization: brand,
        })
    }

    /// Build a **short / personal** handle `@name`.
    pub fn new_short(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_label("handle", &name, Self::MAX_AGENT_LEN)?;
        Ok(Self {
            kind: HandleKind::Short,
            agent: name,
            organization: String::new(),
        })
    }

    fn new_standard(agent: impl Into<String>, organization: impl Into<String>) -> Result<Self> {
        let agent = agent.into();
        let organization = organization.into();
        validate_label("agent", &agent, Self::MAX_AGENT_LEN)?;
        for segment in organization.split('.') {
            validate_label("organization", segment, Self::MAX_ORG_LEN)?;
        }
        Ok(Self {
            kind: HandleKind::Standard,
            agent,
            organization,
        })
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    /// The agent sublabel (Standard), brand name (BrandApex), or personal name (Short).
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// The organisation label (Standard / BrandApex) or `""` (Short).
    pub fn organization(&self) -> &str {
        &self.organization
    }

    pub fn kind(&self) -> &HandleKind {
        &self.kind
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            HandleKind::Standard => write!(f, "@{}.{}.ai", self.agent, self.organization),
            HandleKind::BrandApex => write!(f, "@{}.ai", self.agent),
            HandleKind::Short => write!(f, "@{}", self.agent),
        }
    }
}

// ---------------------------------------------------------------------------
// Label validation (shared)
// ---------------------------------------------------------------------------

/// A label is 1..=max ASCII alphanumeric-or-hyphen chars, no leading/trailing hyphen.
fn validate_label(kind: &str, label: &str, max: usize) -> Result<()> {
    if label.is_empty() {
        return Err(Error::InvalidHandle(format!("empty {kind} label")));
    }
    if label.len() > max {
        return Err(Error::InvalidHandle(format!(
            "{kind} label too long ({} > {max}): {label}",
            label.len()
        )));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(Error::InvalidHandle(format!(
            "{kind} label may not start or end with '-': {label}"
        )));
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(Error::InvalidHandle(format!(
            "{kind} label has invalid characters: {label}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Standard ─────────────────────────────────────────────────────────────

    #[test]
    fn parses_simple_handle() {
        let h = Handle::parse("@reasoning.acme.ai").unwrap();
        assert_eq!(h.agent(), "reasoning");
        assert_eq!(h.organization(), "acme");
        assert_eq!(h.to_string(), "@reasoning.acme.ai");
        assert_eq!(h.kind(), &HandleKind::Standard);
    }

    #[test]
    fn parses_multi_segment_org() {
        let h = Handle::parse("@code-gen-001.freelancer-marketplace.ai").unwrap();
        assert_eq!(h.agent(), "code-gen-001");
        assert_eq!(h.organization(), "freelancer-marketplace");
        assert_eq!(h.kind(), &HandleKind::Standard);
    }

    #[test]
    fn parses_org_with_dots() {
        let h = Handle::parse("@worker.field-ops.acme.ai").unwrap();
        assert_eq!(h.agent(), "worker");
        assert_eq!(h.organization(), "field-ops.acme");
        assert_eq!(h.kind(), &HandleKind::Standard);
    }

    #[test]
    fn round_trips_standard() {
        let original = "@nlp-analyzer.research.ai";
        let h = Handle::parse(original).unwrap();
        assert_eq!(Handle::parse(&h.to_string()).unwrap(), h);
    }

    // ── Brand apex ───────────────────────────────────────────────────────────

    #[test]
    fn parses_brand_apex() {
        let h = Handle::parse("@nike.ai").unwrap();
        assert_eq!(h.kind(), &HandleKind::BrandApex);
        assert_eq!(h.agent(), "nike");
        assert_eq!(h.organization(), "nike");
        assert_eq!(h.to_string(), "@nike.ai");
    }

    #[test]
    fn new_brand_apex_constructor() {
        let h = Handle::new_brand_apex("adidas").unwrap();
        assert_eq!(h.to_string(), "@adidas.ai");
        assert_eq!(h.kind(), &HandleKind::BrandApex);
    }

    #[test]
    fn brand_apex_round_trips() {
        let h = Handle::parse("@amazon.ai").unwrap();
        assert_eq!(Handle::parse(&h.to_string()).unwrap(), h);
    }

    // ── Short / personal ─────────────────────────────────────────────────────

    #[test]
    fn parses_short_handle() {
        let h = Handle::parse("@eduardcleofe").unwrap();
        assert_eq!(h.kind(), &HandleKind::Short);
        assert_eq!(h.agent(), "eduardcleofe");
        assert_eq!(h.organization(), "");
        assert_eq!(h.to_string(), "@eduardcleofe");
    }

    #[test]
    fn new_short_constructor() {
        let h = Handle::new_short("alice").unwrap();
        assert_eq!(h.to_string(), "@alice");
        assert_eq!(h.kind(), &HandleKind::Short);
    }

    #[test]
    fn short_handle_round_trips() {
        let h = Handle::parse("@testuser").unwrap();
        assert_eq!(Handle::parse(&h.to_string()).unwrap(), h);
    }

    // ── Error cases ──────────────────────────────────────────────────────────

    #[test]
    fn rejects_missing_at() {
        assert!(Handle::parse("reasoning.acme.ai").is_err());
    }

    #[test]
    fn rejects_missing_tld_with_dots() {
        // Has dots but doesn't end in .ai → error
        assert!(Handle::parse("@reasoning.acme").is_err());
    }

    #[test]
    fn rejects_leading_hyphen() {
        assert!(Handle::parse("@-bad.acme.ai").is_err());
    }

    #[test]
    fn rejects_empty_after_at() {
        assert!(Handle::parse("@").is_err());
    }

    #[test]
    fn rejects_empty_label_before_ai() {
        assert!(Handle::parse("@.ai").is_err());
    }

    // ── Kind absent from JSON for Standard ───────────────────────────────────

    #[test]
    fn standard_kind_absent_from_json() {
        let h = Handle::parse("@reasoning.acme.ai").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert!(
            !json.contains("kind"),
            "kind must be absent for Standard handles: {json}"
        );
    }

    #[test]
    fn brand_apex_kind_present_in_json() {
        let h = Handle::parse("@nike.ai").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert!(
            json.contains("brand_apex"),
            "kind must appear for BrandApex: {json}"
        );
    }

    #[test]
    fn short_kind_present_in_json() {
        let h = Handle::parse("@eduardcleofe").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert!(
            json.contains("short"),
            "kind must appear for Short handles: {json}"
        );
    }

    #[test]
    fn existing_standard_handle_deserializes_without_kind_field() {
        // Simulate a record stored before HandleKind was introduced — no `kind` field.
        let json = r#"{"agent":"reasoning","organization":"acme"}"#;
        let h: Handle = serde_json::from_str(json).unwrap();
        assert_eq!(h.kind(), &HandleKind::Standard);
        assert_eq!(h.to_string(), "@reasoning.acme.ai");
    }
}
