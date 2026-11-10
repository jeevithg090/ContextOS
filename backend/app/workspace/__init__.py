"""Engineering Workspace logic (pure: no database, no FastAPI).

- ``templates``    board column templates and column validation
- ``modes``        prompt modes, agent presets, generation options
- ``context_pack`` token-budgeted, verified repository context (safe file access in ``repo_files``)
- ``fix_context``  fix-context sections, regeneration and rendering (``render``, ``sections_*``)
- ``hypotheses``   deterministic, labelled root-cause hypotheses
- ``breakdown``    deterministic subtask drafts

The workspace services load org-scoped records, call these functions, and persist the results.
"""
