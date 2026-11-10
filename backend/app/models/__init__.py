"""Importing this package registers every table on ``Base.metadata`` (Alembic + tests rely on it)."""

from app.models.agent import Agent, AgentRelationship, AgentSession
from app.models.context import ContextItem, ContextSource, ProvenanceEdge
from app.models.org import ApiKey, AuthSession, Membership, Organization, User
from app.models.platform import AuditEvent, IngestedEvent, Integration, SimulationRun
from app.models.security import (
    Approval,
    Incident,
    IncidentActivity,
    PolicyDecision,
    SecurityFinding,
    SecurityPolicy,
    TrustRule,
)
from app.models.tool import Destination, Tool, ToolInvocation
from app.models.workspace import (
    Board,
    BoardColumn,
    ContextPack,
    FixAttempt,
    GeneratedPrompt,
    PromptTemplate,
    Task,
    TaskActivity,
    TaskAssignment,
    TaskAttachment,
    TaskComment,
    TaskContextReference,
    TaskDependency,
    TaskLabel,
    TaskLabelLink,
    VerificationRun,
)

__all__ = [
    "Agent", "AgentRelationship", "AgentSession", "ApiKey", "Approval", "AuditEvent", "AuthSession", "Board",
    "BoardColumn", "ContextItem", "ContextPack", "ContextSource", "Destination", "FixAttempt", "GeneratedPrompt",
    "Incident", "IncidentActivity", "IngestedEvent", "Integration", "Membership", "Organization", "PolicyDecision",
    "PromptTemplate", "ProvenanceEdge", "SecurityFinding", "SecurityPolicy", "SimulationRun", "Task",
    "TaskActivity", "TaskAssignment", "TaskAttachment", "TaskComment", "TaskContextReference", "TaskDependency",
    "TaskLabel", "TaskLabelLink", "Tool", "ToolInvocation", "TrustRule", "User", "VerificationRun",
]
