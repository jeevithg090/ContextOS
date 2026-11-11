"""Trust Centre: trust rules, source classification, destination verification.

Authorisation: reading, dry-run rule tests and destination verification need ``read``; creating,
editing and deleting rules, classifying or re-assessing sources and classifying destinations need
``trust:manage``. Every lookup is scoped to the caller's organisation (404 otherwise).

Static paths are registered before ``/{id}`` paths so they are never captured as an id.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.common import Page
from app.schemas.trust import (
    CapabilityName,
    DestinationClassifyIn,
    DestinationKindName,
    DestinationVerifyIn,
    DestinationVerifyOut,
    RuleDeleteOut,
    RuleTestIn,
    RuleTestOut,
    SourceClassifyIn,
    SourceTypeName,
    TrustDestinationDetailOut,
    TrustDestinationOut,
    TrustLevelName,
    TrustRuleCreate,
    TrustRuleOut,
    TrustRulePatch,
    TrustSourceDetailOut,
    TrustSourceOut,
    TrustSummaryOut,
)
from app.services import (
    trust_service,
    trust_service_destinations,
    trust_service_dryrun,
    trust_service_sources,
    trust_service_summary,
)
from app.services.trust_service_common import Actor, make_actor

router = APIRouter(prefix="/trust", tags=["trust"])

READ = Depends(require(Permission.READ.value))
MANAGE = Depends(require(Permission.TRUST_MANAGE.value))

SourceSort = Literal[
    "last_seen", "-last_seen", "first_seen", "-first_seen", "observations", "-observations", "findings", "-findings",
    "trust", "-trust", "identifier", "-identifier",
]
DestinationSort = Literal[
    "last_seen", "-last_seen", "first_seen", "-first_seen", "transfers", "-transfers", "blocked", "-blocked",
    "sensitive", "-sensitive", "identifier", "-identifier",
]


def _actor(db: Session, principal: Principal) -> Actor:
    return make_actor(db, principal.actor_type, principal.actor_id)


# ----------------------------------------------------------------------------- summary


@router.get("/summary", response_model=TrustSummaryOut)
def get_summary(principal: Principal = READ, db: Session = Depends(get_db)) -> TrustSummaryOut:
    """Counts per trust level, sources with findings and recent downgrades (from the audit trail)."""
    return TrustSummaryOut.model_validate(trust_service_summary.summary(db, principal.org_id))


# ----------------------------------------------------------------------------- rules


@router.get("/rules", response_model=Page[TrustRuleOut])
def list_rules(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    applies_to: Literal["source", "destination"] | None = None,
    enabled: bool | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(500, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Page[TrustRuleOut]:
    """Rules in evaluation order: priority, then the more restrictive level, then the more specific pattern."""
    rows = trust_service.list_rules(db, principal.org_id, applies_to=applies_to, enabled=enabled, q=q)
    usage = trust_service.rule_usage(db, principal.org_id)
    page = rows[offset : offset + limit]
    return Page(items=[TrustRuleOut.model_validate(trust_service.rule_out(r, usage)) for r in page],
                total=len(rows), limit=limit, offset=offset)


@router.post("/rules/test", response_model=RuleTestOut)
def test_rule(body: RuleTestIn, principal: Principal = READ, db: Session = Depends(get_db)) -> RuleTestOut:
    """Dry run: how an identifier would be classified (optionally with an unsaved draft rule)."""
    return RuleTestOut.model_validate(trust_service_dryrun.run_rule_test(db, principal.org_id, body.model_dump()))


@router.post("/rules", response_model=TrustRuleOut, status_code=201)
def create_rule(body: TrustRuleCreate, principal: Principal = MANAGE, db: Session = Depends(get_db)) -> TrustRuleOut:
    row, result = trust_service.create_rule(db, principal.org_id, _actor(db, principal), body.model_dump())
    db.commit()
    return TrustRuleOut.model_validate(trust_service.rule_out(row, trust_service.rule_usage(db, principal.org_id), result))


@router.get("/rules/{rule_id}", response_model=TrustRuleOut)
def get_rule(rule_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> TrustRuleOut:
    row = trust_service.get_rule(db, principal.org_id, rule_id)
    return TrustRuleOut.model_validate(trust_service.rule_out(row, trust_service.rule_usage(db, principal.org_id)))


@router.patch("/rules/{rule_id}", response_model=TrustRuleOut)
def update_rule(
    rule_id: str, body: TrustRulePatch, principal: Principal = MANAGE, db: Session = Depends(get_db)
) -> TrustRuleOut:
    row = trust_service.get_rule(db, principal.org_id, rule_id)
    row, result = trust_service.update_rule(db, principal.org_id, _actor(db, principal), row,
                                            body.model_dump(exclude_unset=True))
    db.commit()
    return TrustRuleOut.model_validate(trust_service.rule_out(row, trust_service.rule_usage(db, principal.org_id), result))


@router.delete("/rules/{rule_id}", response_model=RuleDeleteOut)
def delete_rule(rule_id: str, principal: Principal = MANAGE, db: Session = Depends(get_db)) -> RuleDeleteOut:
    row = trust_service.get_rule(db, principal.org_id, rule_id)
    result = trust_service.delete_rule(db, principal.org_id, _actor(db, principal), row)
    db.commit()
    return RuleDeleteOut.model_validate({"id": rule_id, "reassessment": result})


# ----------------------------------------------------------------------------- sources


@router.get("/sources", response_model=Page[TrustSourceOut])
def list_sources(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    trust_level: list[TrustLevelName] | None = Query(None),
    source_type: SourceTypeName | None = None,
    q: str | None = Query(None, max_length=200),
    manual: bool | None = None,
    has_findings: bool | None = None,
    capability: CapabilityName | None = None,
    sort: SourceSort = "-last_seen",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[TrustSourceOut]:
    rows, total = trust_service_sources.list_sources(
        db, principal.org_id, trust_levels=list(trust_level or []), source_type=source_type, q=q, manual=manual,
        has_findings=has_findings, capability=capability, sort=sort, limit=limit, offset=offset,
    )
    items = trust_service_sources.sources_out(db, principal.org_id, rows)
    return Page(items=[TrustSourceOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


@router.get("/sources/{source_id}", response_model=TrustSourceDetailOut)
def get_source(source_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> TrustSourceDetailOut:
    row = trust_service_sources.get_source(db, principal.org_id, source_id)
    return TrustSourceDetailOut.model_validate(trust_service_sources.source_detail(db, principal.org_id, row))


@router.patch("/sources/{source_id}", response_model=TrustSourceDetailOut)
def classify_source(
    source_id: str, body: SourceClassifyIn, principal: Principal = MANAGE, db: Session = Depends(get_db)
) -> TrustSourceDetailOut:
    """Manual classification. Overrides trust rules; recorded evidence can still keep it SUSPICIOUS."""
    row = trust_service_sources.get_source(db, principal.org_id, source_id)
    trust_service_sources.classify_source(db, principal.org_id, _actor(db, principal), row, level=body.trust_level,
                                          capabilities=body.capabilities, note=body.note)
    db.commit()
    return TrustSourceDetailOut.model_validate(trust_service_sources.source_detail(db, principal.org_id, row))


@router.post("/sources/{source_id}/reassess", response_model=TrustSourceDetailOut)
def reassess_source(
    source_id: str, principal: Principal = MANAGE, db: Session = Depends(get_db), reset_manual: bool = False,
) -> TrustSourceDetailOut:
    """Re-run the classification with current rules and findings (``reset_manual`` clears a manual classification)."""
    row = trust_service_sources.get_source(db, principal.org_id, source_id)
    trust_service_sources.reassess_source(db, principal.org_id, _actor(db, principal), row, reset_manual=reset_manual)
    db.commit()
    return TrustSourceDetailOut.model_validate(trust_service_sources.source_detail(db, principal.org_id, row))


# ----------------------------------------------------------------------------- destinations


@router.post("/destinations/verify", response_model=DestinationVerifyOut)
def verify_destination(
    body: DestinationVerifyIn, principal: Principal = READ, db: Session = Depends(get_db)
) -> DestinationVerifyOut:
    """Dry run of every destination check. Looks at the name/address only: no DNS lookup or connection."""
    return DestinationVerifyOut.model_validate(
        trust_service_dryrun.verify_destination(db, principal.org_id, body.kind, body.identifier)
    )


@router.get("/destinations", response_model=Page[TrustDestinationOut])
def list_destinations(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    classification: list[TrustLevelName] | None = Query(None),
    kind: DestinationKindName | None = None,
    q: str | None = Query(None, max_length=200),
    has_blocked: bool | None = None,
    sort: DestinationSort = "-last_seen",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[TrustDestinationOut]:
    rows, total = trust_service_destinations.list_destinations(
        db, principal.org_id, classifications=list(classification or []), kind=kind, q=q, has_blocked=has_blocked,
        sort=sort, limit=limit, offset=offset,
    )
    items = trust_service_destinations.destinations_out(db, principal.org_id, rows)
    return Page(items=[TrustDestinationOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


@router.get("/destinations/{destination_id}", response_model=TrustDestinationDetailOut)
def get_destination(
    destination_id: str, principal: Principal = READ, db: Session = Depends(get_db)
) -> TrustDestinationDetailOut:
    row = trust_service_destinations.get_destination(db, principal.org_id, destination_id)
    return TrustDestinationDetailOut.model_validate(trust_service_destinations.destination_detail(db, principal.org_id, row))


@router.patch("/destinations/{destination_id}", response_model=TrustDestinationDetailOut)
def classify_destination(
    destination_id: str, body: DestinationClassifyIn, principal: Principal = MANAGE, db: Session = Depends(get_db)
) -> TrustDestinationDetailOut:
    """Pin the classification with an exact-match destination rule (created or updated)."""
    row = trust_service_destinations.get_destination(db, principal.org_id, destination_id)
    trust_service_destinations.classify_destination(db, principal.org_id, _actor(db, principal), row,
                                                    classification=body.classification, note=body.note)
    db.commit()
    return TrustDestinationDetailOut.model_validate(trust_service_destinations.destination_detail(db, principal.org_id, row))

