/**
 * Router for component tests: a MemoryRouter with the same React Router v7 future flags the app
 * uses (src/app/routeTree.tsx), so tests exercise production routing behaviour and do not print
 * the v6 deprecation warnings.
 */
import type { ComponentProps } from "react";
import { MemoryRouter } from "react-router-dom";

export const TEST_ROUTER_FUTURE = { v7_startTransition: true, v7_relativeSplatPath: true } as const;

export function TestRouter(props: Omit<ComponentProps<typeof MemoryRouter>, "future">) {
  return <MemoryRouter future={TEST_ROUTER_FUTURE} {...props} />;
}
