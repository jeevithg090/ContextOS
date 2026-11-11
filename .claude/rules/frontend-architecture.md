---
paths:
  - "frontend/src/**/*.{ts,tsx}"
  - "frontend/tailwind.config.js"
  - "frontend/src/styles/**"
---

# Frontend architecture (React 18 + TS + Vite + Tailwind + TanStack Query)

- Each feature owns `src/features/<feature>/`; pages are lazy-loaded from `src/app/routes.tsx`,
  navigation lives in `src/app/nav.ts`.
- Data access only through TanStack Query hooks in `src/features/<feature>/api.ts` (sub-features
  such as `features/workspace/ai/api.ts` may have their own). Hooks call `api.get/post/patch/…` from
  `@/lib/api`; never call `fetch` in components (file downloads in `api.ts` may, as
  `features/audit/api.ts` does). Start `api.ts` with a doc comment naming its backend contract
  (`backend/app/api/routes/<area>.py`) and the routes it uses (see `features/intelligence/api.ts`).
- Query keys start with the feature name (`["findings", "list", …]`) so the SSE invalidation map in
  `src/hooks/useLiveEvents.ts` refreshes them. Mutations invalidate every key whose data they change.
- Do not retry 404/403 (`ApiError.status`): another organisation's id is a definitive "not found".
- Types for API payloads live in `features/<feature>/types.ts` and mirror the backend `*Out` schemas;
  domain vocabularies (trust levels, severities, decisions, statuses) come from `@/lib/domain`.
- Colour: semantic Tailwind tokens only (`bg-surface`, `bg-surface-2`, `text-fg`, `text-fg-muted`,
  `border-border`, `trust-*`, `sev-*`, `dec-*`, `ok`, `warn`, `danger`, `accent`). In feature code
  never use raw palette classes (`text-red-500`, `bg-gray-800`), hex/rgb literals or inline colour
  styles; CSS-variable tokens (`rgb(var(--accent))`) are fine, and only the design-system layer
  (`src/components/ui`, `src/styles/index.css`, `tailwind.config.js`) defines colours. Status → colour
  is decided only in `src/lib/domain.ts` (`TONE_CLASSES`).
- Status display: `TrustBadge`, `SeverityBadge`, `DecisionBadge`, `EnforcementBadge`, `StatusBadge`,
  `SimulationBadge` from `@/components/ui`. Do not hand-roll badges.
- Every view renders loading (`LoadingRows`/`Skeleton`/`Spinner`), error (`ErrorState` with
  `onRetry`), and empty (`EmptyState` explaining how data appears) states. No placeholder copy,
  no buttons without a working handler, no hard-coded metrics or sample rows.
- Shared display pieces come from `@/components/data` (`DataTable`, `RedactedText`, `EvidenceList`,
  `Timeline`, `JsonView`, `FilterBar`, `Pagination`, `EntityLink`, charts, …); reuse before writing
  new ones.
- Show redacted placeholders (`[REDACTED:…]`) as returned — never try to reconstruct content.
  Label simulated rows with `SimulationBadge`, counterfactual results as simulations, and
  provenance edges as observed relationships, not causes.
- Keep components < ~500 lines; split into subfolders (`detail/`, `forms/`, `graph/`, …) as
  existing features do.
- Tests: `src/features/<feature>/__tests__/*.test.ts(x)` (Vitest + Testing Library, jsdom).
- Verify: `cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run src/features/<feature>`.
