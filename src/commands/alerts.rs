use clap::{Subcommand, ValueEnum};

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::{FalconError, Result};

/// Alert status values for Alerts API v3.
#[derive(Debug, Clone, ValueEnum)]
pub enum AlertStatus {
    New,
    InProgress,
    Reopened,
    Closed,
}

impl AlertStatus {
    fn as_api_value(&self) -> &str {
        match self {
            Self::New => "new",
            Self::InProgress => "in_progress",
            Self::Reopened => "reopened",
            Self::Closed => "closed",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List alert IDs
    ///
    /// Returns alert composite IDs matching the specified filter criteria.
    /// Use these IDs with the `get` subcommand to retrieve full alert details.
    ///
    /// FQL filter examples:
    ///   --filter "type:'automated-lead'"            Automated Lead alerts only
    ///   --filter "aggregate_id:'<id>'"              Detections linked to a lead
    ///   --filter "status:'new'"                     Alerts with status new
    ///   --filter "status:'closed'"                  Alerts with status closed
    ///   --filter "severity:>=60"                    Severity >= 60
    ///   --filter "device.device_id:'<device_id>'"   Alerts for a specific device
    ///   --filter "type:'automated-lead'+status:'new'"  Combine with + (AND)
    ///
    /// Response fields:
    ///   resources  - array of alert composite ID strings
    ///   errors     - array of error objects (if any)
    List {
        /// FQL filter expression (e.g. "type:'automated-lead'", "aggregate_id:'<id>'")
        #[arg(long)]
        filter: Option<String>,

        /// Maximum number of results
        #[arg(long, default_value = "100")]
        limit: u32,

        /// Pagination offset
        #[arg(long)]
        offset: Option<String>,
    },
    /// Close alerts
    ///
    /// Shortcut for `update --status closed`. Closes one or more alerts
    /// and optionally adds a comment.
    Close {
        /// Alert composite ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,

        /// Comment to add to the alert
        #[arg(long)]
        comment: Option<String>,
    },
    /// Get alert details by composite ID
    ///
    /// Composite ID formats:
    ///   automated-lead:  <cid>:automated-lead:<cid>:<lead_id>
    ///   detection (ind): <cid>:ind:<device_id>:<process_id>-<pattern_id>-<offset>
    ///
    /// Response fields:
    ///   composite_id      - unique alert composite identifier
    ///   type              - alert type (e.g. "automated-lead")
    ///   aggregate_id      - links lead and its detections (use with list --filter)
    ///   status            - alert status
    ///   severity          - alert severity
    ///   tactic            - MITRE ATT&CK tactic
    ///   technique         - MITRE ATT&CK technique
    ///   device.device_id  - device identifier
    ///   created_timestamp - alert creation timestamp
    ///   updated_timestamp - alert update timestamp
    Get {
        /// Alert composite ID(s) (e.g. "<cid>:automated-lead:<cid>:<lead_id>")
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
    /// Update alert status, tags, assignment, and add comments
    ///
    /// Uses PATCH /alerts/entities/alerts/v3 to update alerts.
    ///
    /// Examples:
    ///   alert update --id <composite_id> --status closed --comment "false positive"
    ///   alert update --id <id1> <id2> --status closed
    ///   alert update --id <composite_id> --add-tag FP --add-tag reviewed
    ///   alert update --id <composite_id> --remove-tag FP
    ///   alert update --id <composite_id> --assigned-to-uuid <uuid>
    ///   alert update --id <composite_id> --assigned-to-user-id user@example.com
    ///   alert update --id <composite_id> --assigned-to-name "John Doe"
    ///   alert update --id <composite_id> --unassign
    Update {
        /// Alert composite ID(s) to update
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,

        /// New status
        #[arg(long)]
        status: Option<AlertStatus>,

        /// Comment to add
        #[arg(long)]
        comment: Option<String>,

        /// Add tag(s)
        #[arg(long, num_args = 1..)]
        add_tag: Vec<String>,

        /// Remove tag(s)
        #[arg(long, num_args = 1..)]
        remove_tag: Vec<String>,

        /// Remove tags by prefix
        #[arg(long)]
        remove_tags_by_prefix: Option<String>,

        /// Assign to user by UUID
        #[arg(long, group = "assign")]
        assigned_to_uuid: Option<String>,

        /// Assign to user by user ID (e.g. email)
        #[arg(long, group = "assign")]
        assigned_to_user_id: Option<String>,

        /// Assign to user by name
        #[arg(long, group = "assign")]
        assigned_to_name: Option<String>,

        /// Unassign from current user
        #[arg(long, group = "assign")]
        unassign: bool,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::List {
            filter,
            limit,
            offset,
        } => {
            let path = build_query_path(
                "/alerts/queries/alerts/v2",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "composite_ids": id });
            client.post("/alerts/entities/alerts/v2", &body).await
        }
        Action::Update {
            id,
            status,
            comment,
            add_tag,
            remove_tag,
            remove_tags_by_prefix,
            assigned_to_uuid,
            assigned_to_user_id,
            assigned_to_name,
            unassign,
        } => {
            update_alerts(
                client,
                &id,
                UpdateParams {
                    status: status.as_ref(),
                    comment: comment.as_deref(),
                    add_tag: &add_tag,
                    remove_tag: &remove_tag,
                    remove_tags_by_prefix: remove_tags_by_prefix.as_deref(),
                    assigned_to_uuid: assigned_to_uuid.as_deref(),
                    assigned_to_user_id: assigned_to_user_id.as_deref(),
                    assigned_to_name: assigned_to_name.as_deref(),
                    unassign,
                },
            )
            .await
        }
        Action::Close { id, comment } => {
            update_alerts(
                client,
                &id,
                UpdateParams {
                    status: Some(&AlertStatus::Closed),
                    comment: comment.as_deref(),
                    ..Default::default()
                },
            )
            .await
        }
    }
}

#[derive(Default)]
struct UpdateParams<'a> {
    status: Option<&'a AlertStatus>,
    comment: Option<&'a str>,
    add_tag: &'a [String],
    remove_tag: &'a [String],
    remove_tags_by_prefix: Option<&'a str>,
    assigned_to_uuid: Option<&'a str>,
    assigned_to_user_id: Option<&'a str>,
    assigned_to_name: Option<&'a str>,
    unassign: bool,
}

async fn update_alerts(
    client: &FalconClient,
    ids: &[String],
    params: UpdateParams<'_>,
) -> Result<serde_json::Value> {
    let has_action = params.status.is_some()
        || params.comment.is_some()
        || !params.add_tag.is_empty()
        || !params.remove_tag.is_empty()
        || params.remove_tags_by_prefix.is_some()
        || params.assigned_to_uuid.is_some()
        || params.assigned_to_user_id.is_some()
        || params.assigned_to_name.is_some()
        || params.unassign;
    if !has_action {
        return Err(FalconError::Api(
            "at least one update option is required (e.g. --status, --comment, --add-tag)"
                .to_string(),
        ));
    }

    let mut action_parameters = Vec::new();
    if let Some(s) = params.status {
        action_parameters
            .push(serde_json::json!({"name": "update_status", "value": s.as_api_value()}));
    }
    if let Some(c) = params.comment {
        action_parameters.push(serde_json::json!({"name": "append_comment", "value": c}));
    }
    for tag in params.add_tag {
        action_parameters.push(serde_json::json!({"name": "add_tag", "value": tag}));
    }
    for tag in params.remove_tag {
        action_parameters.push(serde_json::json!({"name": "remove_tag", "value": tag}));
    }
    if let Some(prefix) = params.remove_tags_by_prefix {
        action_parameters
            .push(serde_json::json!({"name": "remove_tags_by_prefix", "value": prefix}));
    }
    if let Some(uuid) = params.assigned_to_uuid {
        action_parameters.push(serde_json::json!({"name": "assign_to_uuid", "value": uuid}));
    }
    if let Some(user_id) = params.assigned_to_user_id {
        action_parameters.push(serde_json::json!({"name": "assign_to_user_id", "value": user_id}));
    }
    if let Some(name) = params.assigned_to_name {
        action_parameters.push(serde_json::json!({"name": "assign_to_name", "value": name}));
    }
    if params.unassign {
        action_parameters.push(serde_json::json!({"name": "unassign", "value": ""}));
    }
    let body = serde_json::json!({
        "composite_ids": ids,
        "action_parameters": action_parameters,
    });
    client.patch("/alerts/entities/alerts/v3", &body).await
}
