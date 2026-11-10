"""Section builders describing the work: hypotheses, implementation, constraints, criteria, tests, verification."""

from __future__ import annotations

from app.workspace.fix_input import BuildContext, criteria, ref
from app.workspace.hypotheses import derive_hypotheses
from app.workspace.modes import (
    APPROVAL_GATES,
    AUTONOMY_INSTRUCTIONS,
    NO_MODIFY,
    PromptMode,
    RequiredTesting,
    SecurityLevel,
)
from app.workspace.section import Parts
from app.workspace.text import bullets, clean, code, inline, numbered, quote

HYPOTHESIS_PREFACE = (
    "These are hypotheses, derived deterministically from recorded finding categories and evidence. None of them is "
    "confirmed. Confirm or rule out each one with evidence before acting on it."
)
FAKE_SECRETS = "Use obviously fake credentials in tests and fixtures; never real secrets."

_IMPLEMENT_STEPS: dict[PromptMode, list[str]] = {
    PromptMode.IMPLEMENT_FIX: [
        "Reproduce the issue with a failing automated test.",
        "Confirm the root cause against the hypotheses above; record the evidence.",
        "Implement the smallest change that removes the root cause.",
        "Make the failing test pass and run the related test suites.",
        "Report as described under Verification and reporting.",
    ],
    PromptMode.SECURITY_HARDEN: [
        "Reproduce the vulnerability with a failing test that uses the recorded evidence pattern.",
        "Confirm the root cause and identify every entry point that reaches the same weakness.",
        "Fix the root cause so the check fails closed, then close each alternative entry point.",
        "Add adversarial tests for bypass variants and confirm they are rejected.",
        "Report the bypasses you tested and their results.",
    ],
    PromptMode.REFACTOR: [
        "Add characterisation tests for the behaviour you are about to restructure (if not already covered).",
        "Refactor in small steps, running the tests after each one.",
        "Confirm that public interfaces and observable behaviour are unchanged.",
    ],
    PromptMode.TEST_AND_VERIFY: [
        "Write tests that encode the expected behaviour and the acceptance criteria.",
        "Run them against the current code and record which pass and which fail.",
        "Report any failing test as a defect with its output; do not fix production code.",
    ],
    PromptMode.FULL_AUTONOMOUS_REMEDIATION: [
        "Investigate and reproduce the issue with a failing automated test.",
        "Confirm the root cause; if the evidence contradicts every hypothesis, stop and report instead of guessing.",
        "Implement the fix, add regression and (for security issues) adversarial tests.",
        "Run the required test suites until they pass.",
        "Stop at every human-approval gate listed under Constraints.",
        "Report as described under Verification and reporting.",
    ],
}

_PLAN_CONTENTS = [
    "The confirmed or most likely root cause, with the evidence you checked.",
    "Each file to change (only files you confirmed exist; mark new files as new) and the change in each.",
    "Tests to add or update, including a regression test and, for security issues, adversarial cases.",
    "Migration, configuration or rollout concerns.",
    "Risks, open questions, and how to roll the change back.",
]

_ADVERSARIAL: dict[str, str] = {
    "prompt_injection": "variants of the recorded payload (encodings, casing, whitespace, other languages, payloads "
                        "nested in tool output) must be treated as data, not instructions",
    "instruction_override": "lower-trust content must not override system or developer instructions in any position",
    "credential_access": "attempts to read credential paths (.env, SSH keys, cloud credential files), including "
                         "traversal and symlink variants, must be refused",
    "secret_exposure": "fake credentials in real provider formats must be redacted in every output channel "
                       "(responses, logs, exports)",
    "exfiltration": "sensitive data sent to unverified destinations must be blocked or require approval, including "
                    "lookalike domains and IP-literal URLs",
    "destination_risk": "lookalike, IP-literal and redirecting destinations must not be treated as trusted",
    "lethal_trifecta": "a session combining private data, untrusted content and an outbound call must trigger policy",
    "dangerous_permissions": "the agent must not use capabilities beyond its configured scope",
    "permission_escalation": "capabilities must not be gained through delegation or tool-returned credentials",
    "cross_agent_contamination": "untrusted output must keep its trust label when passed to another agent",
    "suspicious_tool_use": "dangerous argument patterns (shell metacharacters, destructive flags) must be flagged",
    "untrusted_source": "unclassified sources must be treated as untrusted data",
    "policy_violation": "allow, deny and approval paths must be tested at the enforcement boundary",
}


def root_cause_hypotheses(ctx: BuildContext, p: Parts) -> None:
    d = ctx.data
    found = derive_hypotheses(task=ctx.task, findings=d.findings, policies=d.policies,
                              previous_attempts=d.previous_attempts, verification_runs=d.verification_runs)
    if not found:
        p.add("hypothesis", "No hypotheses could be derived from the recorded evidence. After reproducing the issue, "
                            "state your own hypotheses explicitly as hypotheses, with the evidence for and against each.")
        return
    blocks = [HYPOTHESIS_PREFACE]
    for i, h in enumerate(found, start=1):
        lines = [f"{i}. **Hypothesis {i} (confidence: {h.confidence}):** {h.statement}",
                 f"   - Basis: {h.basis}", f"   - How to test: {h.how_to_test}"]
        if h.sources:
            lines.append("   - Records: " + ", ".join(code(s) for s in h.sources))
        blocks.append("\n".join(lines))
        p.source(*h.sources)
    p.add("hypothesis", "\n\n".join(blocks))


def required_implementation(ctx: BuildContext, p: Parts) -> None:
    mode = ctx.mode
    p.add("instruction", f"**Deliverable:** {mode.deliverable}")
    if mode.key == PromptMode.IMPLEMENTATION_PLAN:
        p.add("instruction", f"{NO_MODIFY} Do not implement anything. Your plan must cover:\n\n" + numbered(_PLAN_CONTENTS))
    elif not mode.may_modify_files:
        p.add("instruction", f"Not applicable in this mode. {NO_MODIFY} " + " ".join(mode.instructions[1:]))
    elif not ctx.options.allow_code_changes:
        p.add("instruction", f"Code changes are disabled for this task. {NO_MODIFY} Describe the change you would make "
                             "as a proposed diff in your report instead of applying it.")
    else:
        p.add("instruction", numbered(_IMPLEMENT_STEPS.get(mode.key, list(mode.instructions))))
    guidance = [f for f in ctx.sorted_findings()[: ctx.limits["findings"]] if f.get("remediation")]
    if guidance:
        p.add("recommendation", "Remediation guidance recorded on the linked findings (verify before applying):\n\n"
              + bullets([f"{inline(f.get('title') or 'Finding', 160)}: {inline(f['remediation'], 400)}" for f in guidance]))
        p.source(*(ref("finding", f) for f in guidance))


def constraints(ctx: BuildContext, p: Parts) -> None:
    o = ctx.options
    rules: list[str] = []
    if not ctx.may_modify:
        rules.append(f"**{NO_MODIFY}**" + ("" if ctx.mode.may_modify_files else " This mode is read-only."))
    else:
        rules.append(AUTONOMY_INSTRUCTIONS[o.autonomy])
    if o.allow_architecture_changes:
        rules.append("Architectural changes are permitted only where the fix needs them; justify each one.")
    else:
        rules.append("Do not change the architecture: no new services, layers, frameworks, datastores or public API "
                     "contracts. If the fix needs one, stop and explain why.")
    rules.append("Never print, log, commit or transmit secrets or credentials. " + FAKE_SECRETS)
    if o.security_requirements == SecurityLevel.STRICT:
        rules.append("Security requirements are strict: fail closed on errors, validate input at every trust boundary, "
                     "keep least privilege, and never disable or weaken existing security checks or tests.")
    p.add("instruction", bullets(rules))
    if ctx.may_modify:
        p.add("instruction", bullets(list(APPROVAL_GATES)), title="Require explicit human approval before")
    if o.constraints:
        p.add("instruction", bullets([inline(c, 500) for c in o.constraints]), title="Constraints from the requester")
    failed = [a for a in ctx.data.previous_attempts if str(a.get("status")) in ("failed", "abandoned")]
    if failed:
        p.add("fact", "Earlier attempts that did not resolve the task; do not simply repeat them:\n\n" + bullets(
            [f"{code(str(a.get('id') or '?'))} ({inline(a.get('status'), 20)})"
             + (f": {inline(a.get('notes'), 300)}" if a.get("notes") else "") for a in failed[:10]]))
        p.source(*(ref("fix_attempt", a) for a in failed))
    if o.extra_instructions:
        p.add("instruction", quote(clean(o.extra_instructions, limit=4000)), title="Additional instructions from the requester")


def acceptance_criteria(ctx: BuildContext, p: Parts) -> None:
    items = criteria(ctx.task)
    if items:
        p.add("fact", "Acceptance criteria recorded on the task:\n\n" + "\n".join(
            f"- [{'x' if done else ' '}] {inline(text, 400)}" + (" (already marked done on the task)" if done else "")
            for text, done in items))
        p.source(ctx.task_ref)
    derived: list[str] = []
    for f in ctx.sorted_findings()[: ctx.limits["findings"]]:
        if f.get("id"):
            derived.append(f"The behaviour behind finding {code(str(f['id']))} ({inline(f.get('title') or '', 120)}) "
                           "no longer reproduces with the recorded evidence.")
    if ctx.mode.may_modify_files and ctx.mode.key not in (PromptMode.REFACTOR, PromptMode.TEST_AND_VERIFY):
        derived.append("A regression test fails before the change and passes after it.")
    if ctx.mode.key == PromptMode.REFACTOR:
        derived.append("Observable behaviour is unchanged: the same tests pass before and after.")
    if ctx.is_security and ctx.mode.may_modify_files:
        derived.append("Adversarial variants of the issue are rejected (see Testing requirements).")
    if ctx.mode.may_modify_files:
        derived.append("Existing tests that cover the changed code still pass.")
    if derived:
        p.add("recommendation", "Suggested additional criteria (derived by ContextOS from the linked records; confirm "
                                "with the task owner):\n\n" + "\n".join(f"- [ ] {d}" for d in derived))
    if not ctx.mode.may_modify_files:
        p.add("instruction", "In this mode, do not implement anything to satisfy these criteria. Report how each one "
                             "could be verified once a fix exists.")
    if not p:
        p.add("assumption", "No acceptance criteria are recorded. Propose concrete, testable criteria in your report.")


def testing_requirements(ctx: BuildContext, p: Parts) -> None:
    level = ctx.options.testing_requirements
    writes_tests = ctx.may_modify
    verb = "Add" if writes_tests else "Specify (do not write)"
    rules: list[str] = []
    if level == RequiredTesting.NONE:
        rules.append("No new automated tests are required. Run the existing tests that cover the code involved and "
                     "report the results.")
    else:
        rules.append(f"{verb} unit tests for the changed or investigated behaviour, including a regression test.")
        if level in (RequiredTesting.UNIT_INTEGRATION, RequiredTesting.FULL_REGRESSION):
            rules.append(f"{verb} integration tests across the affected boundary (API, database or integration contract).")
        if level == RequiredTesting.FULL_REGRESSION:
            rules.append("Run the full test suite and report the exact commands with pass/fail counts.")
    if not writes_tests:
        rules.append("You may run existing tests that do not modify shared state.")
    p.add("instruction", bullets(rules))
    strict = ctx.options.security_requirements == SecurityLevel.STRICT
    cats = [c for c in ctx.categories() if c in _ADVERSARIAL]
    if cats or strict:
        lines = [f"{c.replace('_', ' ').capitalize()}: {_ADVERSARIAL[c]}." for c in cats]
        if strict and not cats:
            lines.append("Cover malformed, oversized and boundary-value input, and error paths that must fail closed.")
        lines.append(FAKE_SECRETS)
        p.add("instruction", bullets(lines), title=f"Adversarial and security tests ({verb.lower()})")


def verification(ctx: BuildContext, p: Parts) -> None:
    report = [
        "Files changed (with a one-line reason each)" if ctx.may_modify else "Confirmation that no files were modified",
        "Root cause (or investigation result) and the evidence for it: file:line references you actually opened",
        "Exact commands you ran and their results, with pass/fail counts for test runs",
        "Status of each acceptance criterion: met, not met, or not verifiable — with evidence",
        "References from this prompt that turned out to be wrong or missing, and anything you could not verify",
    ]
    p.add("instruction", "Finish with a report containing:\n\n" + numbered(report))
    p.add("instruction", "Saying the work is complete is not verification. In ContextOS a task counts as verified only "
                         "when a passed verification run is recorded against it; your report is the evidence for "
                         "that run.")
    runs = ctx.data.verification_runs
    if runs:
        p.add("evidence", "Earlier verification runs for this task:\n\n" + bullets(
            [f"{code(str(r.get('id') or '?'))} ({inline(r.get('kind') or 'run', 30)}): {inline(r.get('status'), 20)}"
             + (f" — {inline(r.get('summary'), 200)}" if r.get("summary") else "") for r in runs[:10]]))
        p.source(*(ref("verification_run", r) for r in runs[:10]))

