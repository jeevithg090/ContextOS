"""Shared domain vocabulary. Persisted as plain strings for database portability.

These enums are the single source of truth for classification values across engines, API
schemas and the frontend (mirrored in ``frontend/src/lib/domain.ts``).
"""

from __future__ import annotations

from enum import StrEnum


class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"  # first-party / explicitly trusted; may provide instructions
    APPROVED = "APPROVED"  # approved for the listed capabilities only (e.g. read, not instruct)
    EXTERNAL = "EXTERNAL"  # known third-party; content is data, never instructions
    UNKNOWN = "UNKNOWN"  # never classified
    SUSPICIOUS = "SUSPICIOUS"  # evidence of malicious or manipulative content
    BLOCKED = "BLOCKED"  # must not be consumed / contacted


# Lower rank = less trustworthy. Used to compute "lowest trust in session".
TRUST_RANK: dict[str, int] = {
    TrustLevel.BLOCKED: 0,
    TrustLevel.SUSPICIOUS: 1,
    TrustLevel.UNKNOWN: 2,
    TrustLevel.EXTERNAL: 3,
    TrustLevel.APPROVED: 4,
    TrustLevel.TRUSTED: 5,
}

UNTRUSTED_LEVELS = {TrustLevel.BLOCKED, TrustLevel.SUSPICIOUS, TrustLevel.UNKNOWN, TrustLevel.EXTERNAL}


class TrustCapability(StrEnum):
    READ = "read"  # content may be consumed as data
    INSTRUCT = "instruct"  # content may direct agent behaviour
    EXECUTE = "execute"  # content may trigger tool execution
    CREDENTIAL_ACCESS = "credential_access"  # content may lead to credential access
    SEND = "send"  # (destinations) data may be sent here


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RESTRICT = "RESTRICT"
    AUDIT = "AUDIT"


# Higher wins when several policies match.
DECISION_PRECEDENCE: dict[str, int] = {
    Decision.ALLOW: 0,
    Decision.AUDIT: 1,
    Decision.RESTRICT: 2,
    Decision.REQUIRE_APPROVAL: 3,
    Decision.DENY: 4,
}


class PolicyMode(StrEnum):
    ENFORCE = "enforce"  # decision is returned to the integration and enforced where supported
    MONITOR = "monitor"  # decision is recorded only (dry run); never affects the returned outcome


class EnforcementMode(StrEnum):
    ENFORCED = "enforced"  # decision was returned at a real execution boundary that honours it
    ADVISORY = "advisory"  # decision returned, but the integration may not honour it
    OBSERVED = "observed"  # event reported after the fact; nothing could be prevented


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CREDENTIAL_ACCESS = "credential_access"
    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105 (a name, not a credential)
    EXFILTRATION = "exfiltration"
    UNTRUSTED_SOURCE = "untrusted_source"
    SUSPICIOUS_TOOL_USE = "suspicious_tool_use"
    DANGEROUS_PERMISSIONS = "dangerous_permissions"
    LETHAL_TRIFECTA = "lethal_trifecta"
    ANOMALY = "anomaly"
    CROSS_AGENT_CONTAMINATION = "cross_agent_contamination"
    POLICY_VIOLATION = "policy_violation"
    DESTINATION_RISK = "destination_risk"
    PERMISSION_ESCALATION = "permission_escalation"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class SourceType(StrEnum):
    WEB = "web"
    REPOSITORY = "repository"
    FILE = "file"
    DOCUMENT = "document"
    EMAIL = "email"
    API = "api"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    BROWSER = "browser"
    DATABASE = "database"
    USER_UPLOAD = "user_upload"
    USER_PROMPT = "user_prompt"
    TOOL_OUTPUT = "tool_output"
    AGENT_OUTPUT = "agent_output"
    SYSTEM = "system"
    OTHER = "other"


class ToolCategory(StrEnum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL = "shell"
    HTTP = "http"
    BROWSER = "browser"
    EMAIL = "email"
    MESSAGING = "messaging"
    DATABASE = "database"
    CODE_EXECUTION = "code_execution"
    INFRASTRUCTURE = "infrastructure"
    AGENT_DELEGATION = "agent_delegation"
    SEARCH = "search"
    MCP = "mcp"
    OTHER = "other"


# Categories that can move data out of the environment (the trifecta's "outbound channel").
OUTBOUND_CATEGORIES = {
    ToolCategory.HTTP,
    ToolCategory.BROWSER,
    ToolCategory.EMAIL,
    ToolCategory.MESSAGING,
    ToolCategory.SHELL,
    ToolCategory.CODE_EXECUTION,
    ToolCategory.INFRASTRUCTURE,
    ToolCategory.MCP,
}


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"  # noqa: S105 (a name, not a credential)


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(StrEnum):
    READ = "read"  # view all org security data
    WRITE = "write"  # triage findings, manage incidents, tasks
    APPROVE = "approve"  # decide approval requests
    POLICY_MANAGE = "policy:manage"
    TRUST_MANAGE = "trust:manage"
    ADMIN = "admin"  # users, API keys, org settings, integrations
    INGEST = "ingest"  # API keys: submit events
    DECIDE = "decide"  # API keys: synchronous policy decisions


ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.OWNER: {p.value for p in Permission},
    Role.ADMIN: {p.value for p in Permission},
    Role.SECURITY_ANALYST: {
        Permission.READ,
        Permission.WRITE,
        Permission.APPROVE,
        Permission.POLICY_MANAGE,
        Permission.TRUST_MANAGE,
    },
    Role.DEVELOPER: {Permission.READ, Permission.WRITE},
    Role.VIEWER: {Permission.READ},
}

# Scopes an API key may carry.
API_KEY_SCOPES = {Permission.INGEST.value, Permission.DECIDE.value, Permission.READ.value}


class EventType(StrEnum):
    SESSION_STARTED = "session.started"
    SESSION_ENDED = "session.ended"
    PROMPT_SUBMITTED = "prompt.submitted"
    CONTEXT_INGESTED = "context.ingested"
    TOOL_REQUESTED = "tool.requested"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    AGENT_DELEGATED = "agent.delegated"
    AGENT_MESSAGE = "agent.message"
    MCP_SERVER_CONNECTED = "mcp.server_connected"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ProvenanceNodeType(StrEnum):
    SOURCE = "source"
    CONTEXT_ITEM = "context_item"
    SESSION = "session"
    AGENT = "agent"
    TOOL = "tool"
    TOOL_INVOCATION = "tool_invocation"
    RESOURCE = "resource"
    DESTINATION = "destination"
    FINDING = "finding"
    POLICY_DECISION = "policy_decision"


class ProvenanceRelation(StrEnum):
    SOURCE_PRODUCED_ITEM = "source_produced_item"  # source -> context_item
    ITEM_ENTERED_SESSION = "item_entered_session"  # context_item -> session
    SESSION_INVOKED_TOOL = "session_invoked_tool"  # session -> tool_invocation
    INVOCATION_USED_TOOL = "invocation_used_tool"  # tool_invocation -> tool
    INVOCATION_ACCESSED_RESOURCE = "invocation_accessed_resource"  # tool_invocation -> resource
    INVOCATION_SENT_TO = "invocation_sent_to"  # tool_invocation -> destination
    INVOCATION_RETURNED_ITEM = "invocation_returned_item"  # tool_invocation -> context_item
    AGENT_RAN_SESSION = "agent_ran_session"  # agent -> session
    SESSION_DELEGATED_TO = "session_delegated_to"  # session -> session
    AGENT_MESSAGED = "agent_messaged"  # session -> context_item (message)
    ITEM_TRIGGERED_FINDING = "item_triggered_finding"  # context_item -> finding
    INVOCATION_DECIDED_BY = "invocation_decided_by"  # tool_invocation -> policy_decision


class TaskPriority(StrEnum):
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class TaskType(StrEnum):
    SECURITY_VULNERABILITY = "security_vulnerability"
    PROMPT_INJECTION = "prompt_injection"
    AGENT_MISCONFIGURATION = "agent_misconfiguration"
    DATA_EXPOSURE = "data_exposure"
    INTEGRATION_BUG = "integration_bug"
    BACKEND = "backend"
    FRONTEND = "frontend"
    PERFORMANCE = "performance"
    FEATURE = "feature"
    TECH_DEBT = "tech_debt"
    TASK = "task"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
