"""Board templates: the column layouts a new board can start from.

Each column carries a semantic ``status_key`` (used by analytics and workflow rules regardless of
the column's display name), a colour *token name* (never a raw hex value, so themes stay
consistent), an optional WIP limit, and two workflow flags:

- ``is_done_column`` — tasks here count as completed.
- ``requires_verification`` — moving a task INTO this column requires a passed verification run.
"""

from __future__ import annotations

import copy
from typing import Any

DEFAULT_TEMPLATE = "software_development"

STATUS_KEYS: tuple[str, ...] = (
    "backlog",
    "todo",
    "investigating",
    "ready",
    "in_progress",
    "review",
    "testing",
    "verified",
    "done",
)

COLOR_TOKENS: tuple[str, ...] = (
    "slate",
    "accent",
    "trusted",
    "approved",
    "external",
    "suspicious",
    "blocked",
    "high",
    "medium",
    "low",
)


def _col(
    name: str,
    status_key: str,
    color: str,
    description: str,
    *,
    wip_limit: int | None = None,
    done: bool = False,
    verify: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "color": color,
        "status_key": status_key,
        "wip_limit": wip_limit,
        "is_done_column": done,
        "requires_verification": verify,
    }


BOARD_TEMPLATES: dict[str, dict[str, Any]] = {
    "software_development": {
        "name": "Software development",
        "description": "General engineering flow from backlog through review and testing to done.",
        "columns": [
            _col("Backlog", "backlog", "slate", "Captured work that has not been prioritised yet."),
            _col("To Do", "todo", "slate", "Prioritised and ready to be picked up."),
            _col(
                "Investigating",
                "investigating",
                "external",
                "Reproducing the problem and gathering evidence.",
            ),
            _col("Ready for Fix", "ready", "approved", "Root cause understood; the fix can start."),
            _col("In Progress", "in_progress", "accent", "Being implemented.", wip_limit=5),
            _col("Code Review", "review", "medium", "Change is up for review.", wip_limit=5),
            _col("Testing", "testing", "low", "Being tested before release."),
            _col("Done", "done", "trusted", "Shipped and complete.", done=True),
        ],
    },
    "security_remediation": {
        "name": "Security remediation",
        "description": "Findings move from triage to a fix that is independently verified before it is closed.",
        "columns": [
            _col("Triage", "backlog", "high", "New findings awaiting severity and ownership decisions."),
            _col("Investigating", "investigating", "suspicious", "Confirming impact and root cause."),
            _col("Fix Planned", "ready", "approved", "Root cause confirmed and a fix approach agreed."),
            _col("In Progress", "in_progress", "accent", "Fix being implemented.", wip_limit=5),
            _col("Review", "review", "medium", "Fix under code and security review."),
            _col("Testing", "testing", "low", "Regression and adversarial tests running."),
            _col(
                "Verified",
                "verified",
                "trusted",
                "A passed verification run proves the fix. Entering this column requires one.",
                verify=True,
            ),
            _col("Done", "done", "trusted", "Verified fix released; finding can be resolved.", done=True),
        ],
    },
    "incident_response": {
        "name": "Incident response",
        "description": "Work items for an active incident: contain first, then remediate, review and close.",
        "columns": [
            _col("Reported", "backlog", "blocked", "Signals and reports not yet triaged."),
            _col("Triage", "todo", "high", "Assessing scope, severity and owner."),
            _col(
                "Investigating",
                "investigating",
                "suspicious",
                "Establishing what happened and what is affected.",
            ),
            _col(
                "Containing",
                "in_progress",
                "accent",
                "Stopping further impact (revoking access, blocking destinations).",
                wip_limit=3,
            ),
            _col("Remediating", "review", "medium", "Fixing the underlying cause and reviewing the change."),
            _col(
                "Verified",
                "verified",
                "trusted",
                "Containment and fix confirmed by a passed verification run.",
                verify=True,
            ),
            _col("Closed", "done", "trusted", "Post-incident actions recorded; incident closed.", done=True),
        ],
    },
    "bug_tracking": {
        "name": "Bug tracking",
        "description": "Report, confirm, fix and QA defects.",
        "columns": [
            _col("Reported", "backlog", "slate", "New bug reports, not yet confirmed."),
            _col("Confirmed", "todo", "high", "Reproduced and prioritised."),
            _col("Investigating", "investigating", "external", "Looking for the root cause."),
            _col("In Progress", "in_progress", "accent", "Fix being implemented.", wip_limit=5),
            _col("Code Review", "review", "medium", "Fix under review."),
            _col("QA", "testing", "low", "Verifying the fix and checking for regressions."),
            _col("Done", "done", "trusted", "Fixed and released.", done=True),
        ],
    },
    "feature_development": {
        "name": "Feature development",
        "description": "From idea and specification through build, review and release.",
        "columns": [
            _col("Ideas", "backlog", "slate", "Proposals not yet specified."),
            _col("Specified", "todo", "external", "Requirements and acceptance criteria written."),
            _col("Ready for Development", "ready", "approved", "Design agreed; ready to build."),
            _col("In Progress", "in_progress", "accent", "Being built.", wip_limit=5),
            _col("Code Review", "review", "medium", "Under review."),
            _col("Testing", "testing", "low", "Being tested against the acceptance criteria."),
            _col("Released", "done", "trusted", "Available to users.", done=True),
        ],
    },
    "technical_debt": {
        "name": "Technical debt",
        "description": "Identify, scope and pay down debt without changing behaviour.",
        "columns": [
            _col("Identified", "backlog", "slate", "Debt noticed and written down."),
            _col("Prioritised", "todo", "medium", "Worth paying down now."),
            _col("Scoped", "ready", "approved", "Change scoped with characterisation tests identified."),
            _col("In Progress", "in_progress", "accent", "Being refactored.", wip_limit=3),
            _col("Review", "review", "external", "Refactor under review; behaviour must be unchanged."),
            _col("Done", "done", "trusted", "Merged with tests passing.", done=True),
        ],
    },
    "research_experiments": {
        "name": "Research & experiments",
        "description": "Questions turned into experiments with recorded conclusions.",
        "columns": [
            _col("Questions", "backlog", "slate", "Open questions and hypotheses worth testing."),
            _col("Planned", "todo", "external", "Experiment designed with a success measure."),
            _col("Running", "in_progress", "accent", "Experiment in progress.", wip_limit=3),
            _col("Analysing", "review", "medium", "Results being analysed."),
            _col("Concluded", "done", "trusted", "Conclusion and evidence recorded.", done=True),
        ],
    },
}


def validate_columns(columns: list[dict[str, Any]]) -> list[str]:
    """Plain-language problems with a column layout (empty list = valid). Used for custom boards too."""
    errors: list[str] = []
    if not columns:
        return ["A board needs at least one column."]
    seen: set[str] = set()
    for index, col in enumerate(columns):
        label = f"Column {index + 1}"
        name = col.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label} needs a name.")
        elif len(name) > 100:
            errors.append(f"{label} name is longer than 100 characters.")
        elif name.strip().lower() in seen:
            errors.append(f"Column name '{name}' is used more than once.")
        else:
            seen.add(name.strip().lower())
        if col.get("status_key") not in STATUS_KEYS:
            errors.append(f"{label} has an unknown status_key {col.get('status_key')!r}.")
        color = col.get("color")
        if color not in COLOR_TOKENS and not (isinstance(color, str) and _is_hex(color)):
            errors.append(f"{label} colour must be a token name ({', '.join(COLOR_TOKENS)}) or #rrggbb.")
        wip = col.get("wip_limit")
        if wip is not None and (not isinstance(wip, int) or isinstance(wip, bool) or wip < 1):
            errors.append(f"{label} WIP limit must be a positive whole number or empty.")
        for flag in ("is_done_column", "requires_verification"):
            if not isinstance(col.get(flag, False), bool):
                errors.append(f"{label} {flag} must be true or false.")
        if col.get("is_done_column") and col.get("status_key") != "done":
            errors.append(f"{label} is marked as a done column but its status_key is not 'done'.")
    if not any(c.get("is_done_column") for c in columns):
        errors.append("At least one column must be marked as a done column.")
    return errors


def _is_hex(value: str) -> bool:
    return (
        len(value) == 7 and value.startswith("#") and all(ch in "0123456789abcdefABCDEF" for ch in value[1:])
    )


def get_template(key: str) -> dict[str, Any]:
    """Deep copy of a template (safe for callers to mutate). Raises ``KeyError`` for unknown keys."""
    if key not in BOARD_TEMPLATES:
        raise KeyError(f"Unknown board template {key!r}; expected one of: {', '.join(BOARD_TEMPLATES)}")
    return {"key": key, **copy.deepcopy(BOARD_TEMPLATES[key])}


def list_templates() -> list[dict[str, Any]]:
    """Template catalogue for pickers: key, name, description and column names."""
    return [
        {
            "key": key,
            "name": tpl["name"],
            "description": tpl["description"],
            "columns": [c["name"] for c in tpl["columns"]],
            "requires_verification": any(c["requires_verification"] for c in tpl["columns"]),
        }
        for key, tpl in BOARD_TEMPLATES.items()
    ]
