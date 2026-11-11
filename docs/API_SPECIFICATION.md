# API specification

ContextOS serves one JSON API under `/api/v1` (FastAPI). The machine-readable contract is the
OpenAPI document the running server publishes at `/api/openapi.json` (interactive docs at
`/api/docs`). The endpoint inventory below — **163 operations in 22 route modules** — was generated
from the application's routes (method, path, permission dependency, request and response models,
first docstring paragraph) and then checked by hand; regenerate it after adding routes (see
[DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md#add-an-endpoint)).

Related: [INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md) (event envelope and the
integration calls in depth), [DATA_MODEL.md](DATA_MODEL.md), [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Conventions

- **Authentication** (`backend/app/api/deps.py`): browser users send the httpOnly session cookie
  (or `Authorization: Bearer ctxs_…`); integrations send `Authorization: Bearer ctxk_…`. Unsafe
  methods authenticated by cookie must carry `X-Requested-With: contextos` (403 otherwise).
  `X-ContextOS-Org: <org id>` picks the organisation for a user who belongs to several.
- **Permissions**: the "Permission" column names the permission the route requires. Users get
  permissions from their role (`owner`, `admin`: all; `security_analyst`: `read`, `write`,
  `approve`, `policy:manage`, `trust:manage`; `developer`: `read`, `write`; `viewer`: `read`).
  API keys carry only the scopes `ingest`, `decide` and `read`, so they can never call a `write`,
  `approve`, `policy:manage`, `trust:manage` or `admin` route. "signed-in user" routes refuse API
  keys. "public" routes need no credential.
- **Tenancy**: every id is resolved inside the caller's organisation. Another organisation's id —
  in the path, query or body — answers **404**, exactly like an id that does not exist.
- **Lists** return `Page[T]` = `{items, total, limit, offset}`; `limit` 1–500 (default 50),
  `offset` ≥ 0. A few small catalogues return plain lists (`list` below).
- **Simulation data**: lists and metrics leave out Simulation Lab rows unless
  `include_simulated=true` (agents, sessions, findings, incidents, approvals, context, trust
  sources/destinations/summary, overview). Workspace analytics uses `include_simulations`; the event
  list takes `is_simulation`. Simulated rows are labelled in every response that includes them.
- **Errors**: `{"error": {"code", "message", "details"}}` with codes `bad_request` (400),
  `unauthenticated` (401), `forbidden` (403), `attribution_rejected` (403), `not_found` (404),
  `conflict` (409), `payload_too_large` (413), `validation_failed` (422), `rate_limited` (429, repeated
  failed sign-ins), `decision_failed` (500),
  `internal_error` (500).
- **State changes** write an audit entry and publish a live notification (ids only) on
  `GET /stream` after commit.
- **Exports** (`/incidents/{id}/export`, `/audit/export`, `/workspace/ai/context-packs/{id}/export`,
  `/workspace/ai/prompts/{id}/export`) are file downloads of already-redacted data, passed through
  redaction again; incident, audit and context-pack exports are recorded in the audit chain.

## Endpoint inventory

Paths are relative to `/api/v1`. Status is 200 unless shown.

### Health and authentication

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/health` | public | — | `dict` | Liveness: `{"status": "ok"}`. |
| GET | `/ready` | public | — | `dict` | Readiness: also checks the database (`{"status", "database"}`). |
| GET | `/auth/setup-status` | public | — | `SetupStatusOut` | `needs_setup` is true until the first organisation exists. |
| POST | `/auth/setup` | public | `SetupIn` | `MeOut` (201) | First run only: create the organisation and its owner, seed defaults and sign in. |
| POST | `/auth/login` | public | `LoginIn` | `MeOut` | Email + password sign-in; sets the httpOnly session cookie. |
| POST | `/auth/logout` | public | — | — (204) | Revoke the current session (if any) and clear the cookie. Idempotent. |
| GET | `/auth/me` | signed-in user | — | `MeOut` | Current user, organisation, role and permissions. |

### Organisation administration

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/org` | `read` | — | `OrgOut` | The caller's organisation with its effective settings. |
| PATCH | `/org/settings` | `admin` | `OrgSettingsPatch` | `OrgOut` | Name, `retention_days`, `fail_mode`, `default_decision`, `approval_timeout_s`, `store_previews` (audited). |
| GET | `/org/members` | `read` | — | `Page[MemberOut]` | Members with roles. |
| POST | `/org/members` | `admin` | `MemberCreate` | `MemberOut` (201) | Add a member (creates the user when new). |
| PATCH | `/org/members/{membership_id}` | `admin` | `MemberRoleUpdate` | `MemberOut` | Change a member's role (409 for the last owner). |
| DELETE | `/org/members/{membership_id}` | `admin` | — | — (204) | Remove a member (409 for the last owner). |
| GET | `/org/api-keys` | `admin` | — | `Page[ApiKeyOut]` | API keys (prefix, scopes, bound agent, last use); never the key. |
| POST | `/org/api-keys` | `admin` | `ApiKeyCreate` | `ApiKeyCreated` (201) | Create a key; the raw `ctxk_…` value is returned once. |
| DELETE | `/org/api-keys/{key_id}` | `admin` | — | — (204) | Revoke a key. |

### Integration endpoints (events, decisions, approvals, scan, live stream)

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| POST | `/events` | `ingest` | `EventBatch` | `EventBatchOut` | Record events as observed. Per-event results: `accepted` \| `duplicate` \| `rejected`. |
| POST | `/decide` | `decide` | `EventEnvelope` | `DecisionResponse` | Policy decision for a `tool.requested` event, returned before the tool runs. |
| GET | `/decide/approvals/{approval_id}` | `decide` | — | `ApprovalPollOut` | Integration polls an approval (status, note, expiry; lazy expiry persisted). |
| POST | `/decide/approvals/{approval_id}/cancel` | `decide` | `ApprovalCancelIn` | `ApprovalPollOut` | Withdraw a pending approval the integration is no longer waiting for (idempotent; 409 once a person decided it or it expired). The held call is recorded as cancelled. |
| POST | `/scan` | `read` | `ScanIn` | `ScanOut` | Run secret and prompt-injection detection on content without storing anything. |
| GET | `/events` | `read` | — | `Page[IngestedEventOut]` | Ingested events (redacted), filterable by agent, session, type, time, status, `is_simulation`. |
| GET | `/events/{event_id}` | `read` | — | `IngestedEventDetailOut` | One ingested event with its redacted payload and `refs`. |
| GET | `/stream` | `read` | — | — | Server-Sent Events: small notifications ({"type", "id", ...}); clients refetch details. |

### Agents and sessions

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/agents` | `read` | — | `AgentPage` | Agent inventory with session, finding and tool counts. Simulation Lab agents are hidden unless `include_simulated` is true (`facets.simulated` says how many exist). |
| POST | `/agents` | `write` | `AgentCreate` | `AgentDetailOut` (201) | Pre-register an agent with its declared tools. Integrations reporting the same name attach to it. |
| GET | `/agents/graph` | `read` | — | `AgentGraphOut` | Agents and the delegation/messaging relationships observed between them. |
| GET | `/agents/{agent_id}` | `read` | — | `AgentDetailOut` | Agent detail: declared configuration, counts, risk. |
| PATCH | `/agents/{agent_id}` | `write` (+ `policy:manage` for `environment`, `labels`, `status`) | `AgentPatch` | `AgentDetailOut` | Edit description, owner, declared capabilities; fields policies evaluate (environment, labels, status incl. `quarantined`) need `policy:manage` too. |
| GET | `/agents/{agent_id}/sessions` | `read` | — | `Page[SessionSummaryOut]` | The agent's sessions. |
| GET | `/agents/{agent_id}/tools` | `read` | — | `Page[AgentToolOut]` | Observed tools (usage, server-side category and risk, decision breakdown) plus declared tools that have not been observed yet. |
| GET | `/agents/{agent_id}/posture` | `read` | — | `AgentPostureOut` | Explainable 0-100 posture (higher is better), computed now from persisted configuration and activity. |
| GET | `/sessions` | `read` | — | `Page[SessionSummaryOut]` | Sessions (filters: agent, status, `min_risk`, `trifecta`, text, `include_simulated`). |
| GET | `/sessions/{session_id}` | `read` | — | `SessionDetailOut` | Session with its risk state (lethal-trifecta conditions and their evidence), parent/child sessions and counts. |
| GET | `/sessions/{session_id}/timeline` | `read` | — | `TimelinePage` | Events in server sequence order with plain-language titles and links to the records they produced. |

### Context and provenance

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/context/facets` | `read` | — | `ContextFacetsOut` | Item counts by trust, sensitivity and source type for the given filters (each facet ignores its own filter, so selecting a trust level does not hide the other levels' counts). |
| GET | `/context/items` | `read` | — | `Page[ContextItemSummaryOut]` | Context that entered the organisation's agents, newest first (by server receive time). |
| GET | `/context/items/{item_id}` | `read` | — | `ContextItemDetailOut` | One context item: redacted preview, detections with explanations, findings and observed provenance. |
| GET | `/context/items/{item_id}/receipt` | `read` | — | `ContextReceiptOut` | The signed Context Receipt, re-verified now, with a plain-language statement of what it proves. |
| GET | `/context/sources` | `read` | — | `Page[ContextSourceSummaryOut]` | Where context came from, with how much each source delivered and what it triggered. |
| GET | `/context/sources/{source_id}` | `read` | — | `ContextSourceDetailOut` | A source with its trust explanation, recent items, findings and the agents that consumed it. |
| GET | `/provenance/graph` | `read` | — | `ProvenanceGraphOut` | Observed-relationship graph for a scope (session, agent, source, finding, …) with risky paths. |
| GET | `/provenance/scopes` | `read` | — | `ScopeOptionsOut` | Scopes the graph can be opened on. |
| GET | `/provenance/nodes/{node_type}/{node_id:path}` | `read` | — | `NodeDetailOut` | Inspector detail for one graph node. |

### Trust Centre

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/trust/summary` | `read` | — | `TrustSummaryOut` | Counts per trust level, sources with findings and recent downgrades (from the audit trail). |
| GET | `/trust/rules` | `read` | — | `Page[TrustRuleOut]` | Rules in evaluation order: priority, then the more restrictive level, then the more specific pattern. |
| POST | `/trust/rules/test` | `read` | `RuleTestIn` | `RuleTestOut` | Dry run: how an identifier would be classified (optionally with an unsaved draft rule). |
| POST | `/trust/rules` | `trust:manage` | `TrustRuleCreate` | `TrustRuleOut` (201) | Create a trust rule. |
| GET | `/trust/rules/{rule_id}` | `read` | — | `TrustRuleOut` | One trust rule. |
| PATCH | `/trust/rules/{rule_id}` | `trust:manage` | `TrustRulePatch` | `TrustRuleOut` | Edit a trust rule. |
| DELETE | `/trust/rules/{rule_id}` | `trust:manage` | — | `RuleDeleteOut` | Delete a trust rule; affected sources and destinations are re-assessed (counts returned). |
| GET | `/trust/sources` | `read` | — | `Page[TrustSourceOut]` | Sources with trust level, reasons and evidence (`include_simulated`). |
| GET | `/trust/sources/{source_id}` | `read` | — | `TrustSourceDetailOut` | Source trust detail: assessment, history, findings. |
| PATCH | `/trust/sources/{source_id}` | `trust:manage` | `SourceClassifyIn` | `TrustSourceDetailOut` | Manual classification. Overrides trust rules; recorded evidence can still keep it SUSPICIOUS. |
| POST | `/trust/sources/{source_id}/reassess` | `trust:manage` | — | `TrustSourceDetailOut` | Re-run the classification with current rules and findings (`reset_manual` clears a manual classification). |
| POST | `/trust/destinations/verify` | `read` | `DestinationVerifyIn` | `DestinationVerifyOut` | Dry run of every destination check. Looks at the name/address only: no DNS lookup or connection. |
| GET | `/trust/destinations` | `read` | — | `Page[TrustDestinationOut]` | Outbound destinations with classification and checks (`include_simulated`). |
| GET | `/trust/destinations/{destination_id}` | `read` | — | `TrustDestinationDetailOut` | Destination detail: checks performed, transfers, blocked calls. |
| PATCH | `/trust/destinations/{destination_id}` | `trust:manage` | `DestinationClassifyIn` | `TrustDestinationDetailOut` | Pin the classification with an exact-match destination rule (created or updated). |

### Findings

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/findings` | `read` | — | `Page[FindingSummaryOut]` | Findings, most severe first and then most recently seen. |
| GET | `/findings/stats` | `read` | — | `FindingStatsOut` | Open backlog, new findings in the window (by severity, category and status, trend, top sources) and mean time to resolve. |
| GET | `/findings/{finding_id}` | `read` | — | `FindingDetailOut` | A finding with its evidence resolved to records, the related agent, session, source, context item, tool call, decision, destination, incident and remediation tasks, and its triage history. |
| PATCH | `/findings/{finding_id}` | `write` | `FindingUpdateIn` | `FindingDetailOut` | Triage: acknowledge, resolve, mark false positive (a reason is required) or reopen; or edit the resolution note of a closed finding. Invalid transitions return 409. |
| POST | `/findings/{finding_id}/incident` | `write` | `FindingIncidentIn` | `FindingIncidentOut` | Attach the finding to an existing open incident, or open a new incident for it. |

### Policies

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/policies/fields` | `read` | — | `list` | Every field a condition may reference (`FIELD_CATALOG`), with type, description and valid ops. |
| GET | `/policies/operators` | `read` | — | `list` | Condition operators with their plain-English label and the kind of value they take. |
| POST | `/policies/validate` | `read` | `ValidateIn` | `ValidateOut` | Validate a condition/restriction draft; returns errors and the plain-English explanation. |
| POST | `/policies/test` | `read` | `PolicyTestIn` | `PolicyTestOut` | Dry run: evaluate a draft and/or saved policies against an input. Nothing is persisted. |
| GET | `/policies/recent-decisions` | `read` | — | `Page[DecisionSummaryOut]` | Recorded decisions to use as dry-run test inputs (their redacted input snapshots). |
| GET | `/policies` | `read` | — | `Page[PolicyOut]` | Policies ordered by evaluation precedence, each with its last-7-days match statistics. |
| POST | `/policies` | `policy:manage` | `PolicyCreate` | `PolicyOut` (201) | Create a policy (validated). |
| GET | `/policies/{policy_id}` | `read` | — | `PolicyOut` | One policy. |
| PATCH | `/policies/{policy_id}` | `policy:manage` | `PolicyPatch` | `PolicyOut` | Edit a policy (`version` increments). |
| DELETE | `/policies/{policy_id}` | `policy:manage` | — | — (204) | Delete a custom policy; built-ins answer 409 (disable them instead). |
| GET | `/policies/{policy_id}/decisions` | `read` | — | `Page[PolicyDecisionMatchOut]` | Recorded decisions in which this policy matched (enforce or monitor), newest first. |

### Approvals

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/approvals` | `read` | — | `Page[ApprovalOut]` | The pending queue (oldest first: closest to timing out) or the decision history. |
| GET | `/approvals/{approval_id}` | `read` | — | `ApprovalDetailOut` | Everything a reviewer needs: the redacted arguments, resources (sensitive ones flagged), the destination and the checks run on it, why the policy paused the call, the session's trifecta evidence … |
| POST | `/approvals/{approval_id}/decide` | `approve` | `ApprovalDecideIn` | `ApprovalDetailOut` | Approve or reject a pending request. 409 when it is no longer pending (already decided, or expired). The integration that paused the call receives the outcome on its next poll. |

### Incidents

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/incidents` | `read` | — | `Page[IncidentSummaryOut]` | Incidents with finding counts and primary agent. `priority` lists active, severe incidents first. |
| POST | `/incidents` | `write` | `IncidentCreateIn` | `IncidentDetailOut` (201) | Open an incident, optionally grouping existing findings (it is at least as severe as the worst one). |
| GET | `/incidents/{incident_id}` | `read` | — | `IncidentDetailOut` | The investigator's view: findings, involved agents/sessions/sources/destinations, activity and tasks. |
| PATCH | `/incidents/{incident_id}` | `write` | `IncidentUpdateIn` | `IncidentDetailOut` | Change status (validated transitions; closing needs a resolution), severity, assignee or resolution. |
| POST | `/incidents/{incident_id}/notes` | `write` | `NoteIn` | `ActivityOut` (201) | Add an investigation note. Secrets in the text are redacted before it is stored. |
| POST | `/incidents/{incident_id}/findings` | `write` | `LinkFindingsIn` | `LinkFindingsOut` | Attach findings to an active incident (all or nothing). |
| GET | `/incidents/{incident_id}/timeline` | `read` | — | `IncidentTimelineOut` | Merged, chronological entries: involved sessions' events, findings, policy decisions, approvals and incident activity. Server-time order; an observed sequence, not causation. |
| GET | `/incidents/{incident_id}/export` | `read` | — | — | Evidence bundle (JSON download). The export is recorded in the incident activity and the audit chain, including the bundle's SHA-256. |

### Replay and Simulation Lab

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/replay/sessions/{session_id}` | `read` | — | `ReplayOut` | The session's recorded events as replayable steps, in server sequence order, with the recorded outcome of each decision and session risk recomputed from recorded events after every step. |
| POST | `/replay/counterfactual` | `read` | `CounterfactualIn` | `CounterfactualOut` | SIMULATION: re-evaluate every recorded policy decision of the session against its recorded input snapshot under a hypothetical policy set. Outcomes are hypothetical, not historical fact. |
| GET | `/simulations/scenarios` | `read` | — | `ScenarioList` | Simulation Lab scenario catalogue. |
| GET | `/simulations/scenarios/{scenario_id}` | `read` | — | `ScenarioOut` | One scenario: steps and expectations. |
| POST | `/simulations/runs` | `write` (user) / `ingest` (key) | `RunIn` | `SimulationRunOut` (201) | Run one scenario through the real pipeline (`is_simulation`). |
| GET | `/simulations/runs` | `read` | — | `Page[SimulationRunOut]` | Run history. |
| GET | `/simulations/runs/{run_id}` | `read` | — | `SimulationRunOut` | One run with per-check results and evidence ids. |
| POST | `/simulations/suites` | `write` (user) / `ingest` (key) | `SuiteIn` | `SuiteOut` (201) | Run several scenarios as a regression suite. |
| GET | `/simulations/suites` | `read` | — | `Page[SuiteSummaryOut]` | Suite runs. |
| GET | `/simulations/suites/compare` | `read` | — | `SuiteCompareOut` | Compare two suite runs check by check. |
| GET | `/simulations/suites/{suite_run_id}` | `read` | — | `SuiteOut` | One suite run with its runs. |

### Overview, integrations and audit

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/overview/nav-counts` | `read` (no agent-bound key) | — | `NavCountsOut` | Sidebar badges: pending approvals (not past their deadline), open incidents and open findings. Simulation Lab rows are not counted. |
| GET | `/overview` | `read` (no agent-bound key) | — | `OverviewOut` | Current posture (agents, sessions, lethal-trifecta sessions, source trust, open findings, approvals and incidents), the window's decisions and enforcement coverage, event / finding / decision series, the riskiest agents … |
| GET | `/integrations` | `read` | — | `IntegrationsOut` | Connected integrations (connected = an event in the last 24 hours) and the capability catalog. |
| GET | `/integrations/{kind}/setup` | `read` | — | `SetupGuideOut` | Step-by-step setup for one integration kind. Planned kinds return their interim path. |
| GET | `/audit` | `read` | — | `Page[AuditEventOut]` | Audit entries of the caller's organisation, newest first. |
| GET | `/audit/verify` | `read` | — | `AuditVerifyOut` | Recompute the organisation's hash chain from the first entry to the recorded head. |
| GET | `/audit/export` | `admin` | — | — | The full chain as JSON Lines (oldest first). Admin only; recorded as `audit.exported`. |

### Engineering Workspace: boards

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/workspace/boards/templates` | `read` | — | `list` | Column layouts a new board can start from. |
| GET | `/workspace/boards` | `read` | — | `Page[BoardSummaryOut]` | Boards (default first) with column and task counts. |
| POST | `/workspace/boards` | `write` | `BoardCreate` | `BoardDetailOut` (201) | Create a board from a template. |
| GET | `/workspace/boards/{board_id}` | `read` | — | `BoardDetailOut` | The board with its ordered columns and the (non-archived) task cards in each column. |
| PATCH | `/workspace/boards/{board_id}` | `write` | `BoardPatch` | `BoardDetailOut` | Edit or restore (`archived: false`) a board. |
| DELETE | `/workspace/boards/{board_id}` | `write` | — | — (204) | Archive (soft-delete) a board. Restore with `PATCH {"archived": false}`. |
| POST | `/workspace/boards/{board_id}/duplicate` | `write` | `BoardDuplicate` | `BoardDetailOut` (201) | Copy settings and columns (automation remapped). Tasks are not copied. |
| POST | `/workspace/boards/{board_id}/columns` | `write` | `ColumnCreate` | `ColumnOut` (201) | Add a column. |
| POST | `/workspace/boards/{board_id}/columns/reorder` | `write` | `ColumnReorder` | `list` | Reorder columns. |
| PATCH | `/workspace/boards/{board_id}/columns/{column_id}` | `write` | `ColumnPatch` | `ColumnOut` | Edit a column (WIP limit, `requires_verification`, automation). |
| DELETE | `/workspace/boards/{board_id}/columns/{column_id}` | `write` | — | `ColumnDeleteOut` | Delete a column. Refused while it holds tasks unless `move_to` names another column of the board. |

### Engineering Workspace: tasks

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/workspace/tasks` | `read` | — | `Page[TaskCardOut]` | Task cards with filters (board, column, assignee, type, priority, label, status key, finding, incident, text). |
| POST | `/workspace/tasks` | `write` | `TaskCreate` | `TaskDetailOut` (201) | Create a task. |
| GET | `/workspace/tasks/labels` | `read` | — | `list` | Labels. |
| POST | `/workspace/tasks/labels` | `write` | `LabelCreate` | `LabelOut` (201) | Create a label. |
| POST | `/workspace/tasks/from-finding` | `write` | `FromFindingIn` | `FromFindingOut` | Create (or return the existing open) remediation task for a finding. 201 when created, 200 otherwise. |
| POST | `/workspace/tasks/from-incident` | `write` | `FromIncidentIn` | `FromIncidentOut` | Remediation tasks for an incident (`mode`: `per_finding` or `parent_with_subtasks`). |
| PATCH | `/workspace/tasks/comments/{comment_id}` | `write` | `CommentPatch` | `CommentOut` | Edit your comment (redacted). |
| DELETE | `/workspace/tasks/comments/{comment_id}` | `write` | — | — (204) | Delete a comment. |
| DELETE | `/workspace/tasks/dependencies/{dependency_id}` | `write` | — | — (204) | Remove a dependency. |
| DELETE | `/workspace/tasks/refs/{ref_id}` | `write` | — | — (204) | Remove a context reference. |
| DELETE | `/workspace/tasks/attachments/{attachment_id}` | `write` | — | — (204) | Remove an attachment. |
| PATCH | `/workspace/tasks/fix-attempts/{attempt_id}` | `write` | `FixAttemptPatch` | `FixAttemptOut` | Update a fix attempt (status, branch, commit, PR). |
| GET | `/workspace/tasks/{task_id}` | `read` | — | `TaskDetailOut` | Task detail: refs, comments, dependencies, attachments, links, attempts, verifications, activity. |
| PATCH | `/workspace/tasks/{task_id}` | `write` | `TaskPatch` | `TaskDetailOut` | Edit or restore (`archived: false`) a task. |
| DELETE | `/workspace/tasks/{task_id}` | `write` | — | — (204) | Archive (soft-delete). Restore with `PATCH {"archived": false}`. |
| POST | `/workspace/tasks/{task_id}/move` | `write` | `TaskMove` | `TaskCardOut` | Move to a column/position (WIP limit unless `override_wip`; `requires_verification` columns need a passed verification). |
| PUT | `/workspace/tasks/{task_id}/assignees` | `write` | `AssigneesPut` | `list` | Replace assignees (members only). |
| POST | `/workspace/tasks/{task_id}/comments` | `write` | `CommentCreate` | `CommentOut` (201) | Comment (redacted before storage). |
| POST | `/workspace/tasks/{task_id}/dependencies` | `write` | `DependencyCreate` | `DependencyOut` (201) | Add a dependency (`blocks` cycles refused). |
| POST | `/workspace/tasks/{task_id}/refs` | `write` | `RefCreate` | `RefOut` (201) | Reference a finding, incident, session, event, … by id. |
| POST | `/workspace/tasks/{task_id}/attachments` | `write` | `AttachmentCreate` | `AttachmentOut` (201) | Attach a link, log, stack trace or note (≤ 100 KB, redacted). |
| POST | `/workspace/tasks/{task_id}/links` | `write` | `LinkCreate` | `dict` (201) | Link a branch, commit, pull request or deployment. Returns every link of the task, grouped by kind. |
| DELETE | `/workspace/tasks/{task_id}/links/{kind}/{index}` | `write` | — | `dict` | Remove a branch/commit/PR/deployment link. |
| POST | `/workspace/tasks/{task_id}/fix-attempts` | `write` | `FixAttemptCreate` | `FixAttemptOut` (201) | Record a fix attempt (optionally from a generated prompt). |
| POST | `/workspace/tasks/{task_id}/verifications` | `write` | `VerificationCreate` | `VerificationOut` (201) | Record a verification (`test_run`, `code_review`, `manual`, `deployment`, `simulation`, `replay`). |
| POST | `/workspace/tasks/{task_id}/verify-with-simulation` | `write` | `VerifyWithSimulationIn` | `VerificationOut` (201) | Run a Simulation Lab scenario through the real pipeline and record it as verification evidence. |

### Engineering Workspace: AI fix context

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/workspace/ai/modes` | `read` | — | `ModesOut` | Prompt modes, agent presets, options and pack profiles; with `task_id`, `suggested_profiles` per mode. |
| POST | `/workspace/ai/context-packs` | `write` | `ContextPackCreate` | `ContextPackOut` (201) | Build and store a token-budgeted context pack for a task. |
| GET | `/workspace/ai/context-packs` | `read` | — | `Page[ContextPackSummaryOut]` | Stored context packs. |
| GET | `/workspace/ai/context-packs/{pack_id}` | `read` | — | `ContextPackOut` | One context pack. |
| GET | `/workspace/ai/context-packs/{pack_id}/export` | `read` | — | — | The pack as a JSON download (redacted again). Audited as `context_pack.exported`. |
| PATCH | `/workspace/ai/context-packs/{pack_id}` | `write` | `ContextPackPatch` | `ContextPackOut` | Include/exclude pack items. |
| DELETE | `/workspace/ai/context-packs/{pack_id}` | `write` | — | — (204) | Delete a pack. |
| POST | `/workspace/ai/fix-context` | `read` | `FixContextRequest` | `FixContextOut` | Generate a fix-context prompt. `save=true` needs `write` and answers 201 with the stored prompt id. |
| GET | `/workspace/ai/prompts` | `read` | — | `Page[PromptSummaryOut]` | Saved fix-context prompts. |
| GET | `/workspace/ai/prompts/{prompt_id}` | `read` | — | `PromptOut` | One saved prompt with sections. |
| PATCH | `/workspace/ai/prompts/{prompt_id}` | `write` | `PromptPatch` | `PromptOut` | Edit/remove sections or change options (`version += 1`). |
| POST | `/workspace/ai/prompts/{prompt_id}/regenerate-section` | `write` | `RegenerateSectionIn` | `PromptOut` | Rebuild one section from current records. |
| GET | `/workspace/ai/prompts/{prompt_id}/export` | `read` | — | — | Download as Markdown or JSON (`format=markdown\|json`). |
| GET | `/workspace/ai/templates` | `read` | — | `list` | Prompt templates (built-in and custom). |
| POST | `/workspace/ai/templates` | `write` | `TemplateCreate` | `TemplateOut` (201) | Create a template. |
| GET | `/workspace/ai/templates/{template_id}` | `read` | — | `TemplateOut` | One template. |
| PATCH | `/workspace/ai/templates/{template_id}` | `write` | `TemplatePatch` | `TemplateOut` | Edit a custom template (`builtin:<mode>` templates are read-only). |
| DELETE | `/workspace/ai/templates/{template_id}` | `write` | — | — (204) | Delete a custom template. |
| POST | `/workspace/ai/breakdown` | `read` | `BreakdownIn` | `BreakdownOut` | Deterministic subtask drafts for a task (nothing stored). |
| POST | `/workspace/ai/breakdown/apply` | `write` | `BreakdownApplyIn` | `BreakdownApplyOut` (201) | Create the (edited) subtask drafts with dependencies. |

### Engineering Workspace: analytics

| Method | Path | Permission | Request | Response | Purpose |
|---|---|---|---|---|---|
| GET | `/workspace/analytics` | `read` | — | `EngineeringAnalyticsOut` | Engineering analytics from persisted tasks and findings (`include_simulations`). |
| GET | `/workspace/analytics/remediation` | `read` | — | `RemediationPageOut` | Findings with their remediation state (task, attempts, verification). |

## Notes on selected endpoints

- `POST /events` never blocks anything: every event is recorded as **observed**. Only
  `POST /decide` returns a decision before a tool runs; its `enforcement` is `enforced` for the
  `claude_code`, `mcp_gateway` and `python_sdk` integrations and `advisory` otherwise.
- `POST /decide/approvals/{approval_id}/cancel` body `{"reason": "…"}` (optional, ≤ 500
  characters). Idempotent for `cancelled`; 409 with `details.status` when the approval was already
  approved, rejected or expired.
- `POST /scan` returns `hits` (rule id, category, title, severity, confidence, explanation,
  redacted excerpt, technique) and `secrets` as positions only (`type`, `start`, `end`,
  `confidence`); the secret values and their fingerprints are never returned. Nothing is stored.
- `POST /simulations/runs` and `POST /simulations/suites` write simulated events through the real
  pipeline, so they need `write` for a signed-in user or the `ingest` scope for an API key (the
  `contextos simulate` CLI). A key bound to one agent may only simulate that agent.
- `POST /replay/counterfactual` is a **simulation**: decisions are re-evaluated against the
  recorded `input_snapshot` under a hypothetical policy set (`policy_set.base` `current`/`none`,
  `disable_policy_ids`, `overrides`, `add_policies`); nothing is persisted.
- `GET /integrations` returns `connected` integrations (an event in the last 24 hours;
  `stale_after_hours: 24`, `stale_after_minutes: 1440`) and the capability `catalog` (supported and
  planned kinds with their enforced/advisory/observed capabilities).
- `GET /trust/sources` and `GET /trust/sources/{source_id}` are the Trust Centre's view of
  sources (assessment, reasons, evidence); `GET /context/sources/{source_id}` is the Context
  Explorer's view (items delivered, consuming agents).
- `GET /workspace/ai/modes?task_id=…` adds `suggested_profiles` (the context-pack profile suggested
  for each prompt mode for that task).
- `POST /workspace/ai/fix-context` is deterministic and runs on the server; no external AI provider
  is called.
- `GET /stream` is Server-Sent Events: messages `{"type", "id", …ids}` (types in
  `frontend/src/hooks/useLiveEvents.ts`) and a ping every 15 seconds. It delivers notifications from
  the API process the browser is connected to.
