"""Organisation configuration (policies, trust rules) for the ingestion pipeline, cached per process.

Loading and converting every enabled policy and trust rule on each ``/decide`` call is the largest
fixed cost of a decision. Specs are cached per organisation and revalidated on EVERY request with
one aggregate query (row count + latest ``updated_at``) against the database, so an edit, a
disable or a delete made by any API process takes effect on the next event — the cache never
serves configuration the database no longer has.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.engines.policy import PolicySpec
from app.engines.trust import TrustRuleSpec
from app.models import SecurityPolicy, TrustRule
from app.services.loaders import load_policy_specs, load_trust_rule_specs

MAX_ORGS = 1000
_lock = threading.Lock()
# (org id, kind) -> (version, specs). Specs are treated as read-only by the pipeline.
_cache: OrderedDict[tuple[str, str], tuple[tuple[Any, ...], Any]] = OrderedDict()


def _version(db: Session, model: type[SecurityPolicy] | type[TrustRule], org_id: str) -> tuple[Any, ...]:
    count, latest = db.execute(
        select(func.count(model.id), func.max(model.updated_at)).where(model.organization_id == org_id)
    ).one()
    return int(count or 0), str(latest) if latest is not None else None


def _cached(key: tuple[str, str], version: tuple[Any, ...], load: Callable[[], Any]) -> Any:
    with _lock:
        hit = _cache.get(key)
        if hit is not None and hit[0] == version:
            _cache.move_to_end(key)
            return hit[1]
    specs = load()
    with _lock:
        _cache[key] = (version, specs)
        _cache.move_to_end(key)
        while len(_cache) > MAX_ORGS * 2:
            _cache.popitem(last=False)
    return specs


def policy_specs(db: Session, org_id: str) -> list[PolicySpec]:
    version = _version(db, SecurityPolicy, org_id)
    return list(_cached((org_id, "policies"), version, lambda: tuple(load_policy_specs(db, org_id))))


def trust_rule_specs(db: Session, org_id: str, applies_to: str) -> list[TrustRuleSpec]:
    """Enabled rules for ``applies_to`` ("source" | "destination"), including rules for both."""
    version = _version(db, TrustRule, org_id)
    rules = _cached((org_id, "trust_rules"), version, lambda: tuple(load_trust_rule_specs(db, org_id)))
    return [r for r in rules if r.applies_to in (applies_to, "both")]
