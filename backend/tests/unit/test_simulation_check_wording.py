"""Simulation Lab expectation text reads as English ("an instruction_override …", "a secret_exposure …")."""

from __future__ import annotations

import pytest

from app.simulations.checks import finding
from app.simulations.model import RunView


@pytest.mark.parametrize(("category", "article"), [
    ("instruction_override", "an"), ("prompt_injection", "a"), ("exfiltration", "an"), ("secret_exposure", "a"),
])
def test_finding_expectation_uses_the_right_article(category, article):
    view = RunView(db=None, org_id="org_x", run_id="run_x", session_ids=[], outcomes={}, vars=None,  # type: ignore[arg-type]
                   audit_seq_before=0)
    result = finding("why", categories=(category,)).check(view)
    assert result.expected.startswith(f"{article} {category} finding")
    assert result.passed is False  # no sessions, no findings
