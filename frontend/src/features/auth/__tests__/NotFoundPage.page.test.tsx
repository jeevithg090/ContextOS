import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { currentLocation, renderPage, stubApi } from "@/test/pageHarness";
import { NotFoundPage } from "../NotFoundPage";

afterEach(() => vi.unstubAllGlobals());

describe("NotFoundPage", () => {
  it("explains a missing page without calling the API and links back to the overview", async () => {
    // A static page: no loading, error or data states, and no request.
    const api = stubApi(() => undefined);
    renderPage(<NotFoundPage />, { path: "/no/such/page", routePath: "/no/such/page" });
    expect(screen.getByText("Page not found")).toBeInTheDocument();
    expect(screen.getByText(/belongs to another organisation/)).toBeInTheDocument();
    const back = screen.getByRole("link", { name: "Back to overview" });
    expect(back).toHaveAttribute("href", "/");
    fireEvent.click(back);
    await waitFor(() => expect(currentLocation()).toBe("/"));
    expect(api.calls).toHaveLength(0);
  });
});
