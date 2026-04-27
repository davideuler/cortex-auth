//! `pending_grants` — first-access human approval for an `(agent_id,
//! project_name, scope)` discover request.
//!
//! The first time an agent asks for a project's secrets, the server records
//! a `pending` row, returns 403 `pending_approval`, and notifies the
//! dashboard + outbound channels. After the operator approves the row, future
//! discovers within `auto_approval_until` whose requested scope is a subset
//! of the approved scope auto-pass. A scope expansion re-triggers approval.

use serde::{Deserialize, Serialize};

/// Auto-approval window applied when an admin approves a grant — subsequent
/// discovers from the same `(agent_id, project, namespace)` whose requested
/// scope is a subset of `approved_keys` auto-pass for this many days.
pub const AUTO_APPROVAL_WINDOW_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PendingGrant {
    pub id: String,
    pub agent_id: String,
    pub project_name: String,
    pub namespace: String,
    pub requested_keys: String,
    pub approved_keys: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub auto_approval_until: Option<String>,
    pub source_ip: Option<String>,
}

impl PendingGrant {
    pub fn requested_keys_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.requested_keys).unwrap_or_default()
    }

    pub fn approved_keys_vec(&self) -> Vec<String> {
        self.approved_keys
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    /// Returns true when this row is approved AND the auto-approval window is
    /// still in the future AND the supplied `requested` set is a subset of the
    /// approved set.
    pub fn covers(&self, requested: &[String]) -> bool {
        if self.status != "approved" {
            return false;
        }
        if let Some(until) = &self.auto_approval_until {
            if let Ok(t) = chrono::NaiveDateTime::parse_from_str(until, "%Y-%m-%d %H:%M:%S") {
                if t < chrono::Utc::now().naive_utc() {
                    return false;
                }
            }
        }
        let approved = self.approved_keys_vec();
        let approved_set: std::collections::HashSet<&str> =
            approved.iter().map(|s| s.as_str()).collect();
        requested.iter().all(|k| approved_set.contains(k.as_str()))
    }
}

#[derive(Debug, Serialize)]
pub struct PendingGrantListItem {
    pub id: String,
    pub agent_id: String,
    pub project_name: String,
    pub namespace: String,
    pub requested_keys: Vec<String>,
    pub approved_keys: Vec<String>,
    pub status: String,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub auto_approval_until: Option<String>,
    pub source_ip: Option<String>,
}

impl From<PendingGrant> for PendingGrantListItem {
    fn from(g: PendingGrant) -> Self {
        let requested_keys = g.requested_keys_vec();
        let approved_keys = g.approved_keys_vec();
        PendingGrantListItem {
            id: g.id,
            agent_id: g.agent_id,
            project_name: g.project_name,
            namespace: g.namespace,
            requested_keys,
            approved_keys,
            status: g.status,
            requested_at: g.requested_at,
            decided_at: g.decided_at,
            decided_by: g.decided_by,
            auto_approval_until: g.auto_approval_until,
            source_ip: g.source_ip,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ApproveGrantRequest {
    /// Subset of the requested_keys to actually grant. Defaults to the full
    /// requested set when omitted.
    pub approved_keys: Option<Vec<String>>,
}
