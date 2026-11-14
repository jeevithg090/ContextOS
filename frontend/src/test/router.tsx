/**
 * Router for component tests: a MemoryRouter, so page tests render inside the same React Router
 * context the app uses (src/app/routeTree.tsx).
 */
import type { ComponentProps } from "react";
import { MemoryRouter } from "react-router-dom";

export function TestRouter(props: ComponentProps<typeof MemoryRouter>) {
  return <MemoryRouter {...props} />;
}
