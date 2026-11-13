import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hang, notFound, renderPage, serverError, stubApi, type ApiRoute } from "@/test/pageHarness";
import { ContextReceiptPage } from "../ContextReceiptPage";
import type { ContextReceipt } from "../types";
import { RECEIPT } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

afterEach(() => vi.unstubAllGlobals());

const receiptRoute = (receipt: ContextReceipt = RECEIPT): ApiRoute => (c) => (c.path === `/context/items/${receipt.receipt.context_item_id}/receipt` ? { body: receipt } : undefined);
const renderReceipt = (id = "ctx_readme") => renderPage(<ContextReceiptPage />, { path: `/context/${id}`, routePath: "/context/:itemId" });

describe("ContextReceiptPage", () => {
  it("shows a loading state with the way back to the explorer", () => {
    stubApi(() => hang);
    renderReceipt();
    expect(screen.getByLabelText("Loading receipt")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("link", { name: /Context Explorer/ })).toHaveAttribute("href", "/context");
  });

  it("says the receipt was not found for an unknown or foreign item, without retrying", async () => {
    const api = stubApi((c) => (c.path === "/context/items/ctx_foreign/receipt" ? notFound("Context item 'ctx_foreign'") : undefined));
    renderReceipt("ctx_foreign");
    expect(await screen.findByText("Receipt not found")).toBeInTheDocument();
    expect(screen.getByText("No context item with this id exists in your organisation.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the Context Explorer" })).toHaveAttribute("href", "/context");
    expect(api.gets("/context/items/ctx_foreign/receipt")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi((c) => (c.path.endsWith("/receipt") ? serverError("Receipt signing key unavailable") : undefined));
    renderReceipt();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Receipt signing key unavailable")).toBeInTheDocument();
  });

  it("shows the verified receipt: signed fields, trust then and now, what it proves and does not", async () => {
    stubApi(receiptRoute());
    renderReceipt();
    expect(await screen.findByRole("heading", { name: "Vendor setup guide" })).toBeInTheDocument();
    expect(screen.getByText(RECEIPT.statement.summary)).toBeInTheDocument();
    expect(screen.getByText("Signature valid").closest("[role=status]")).toHaveTextContent(RECEIPT.verification.explanation);

    expect(within(screen.getByRole("list", { name: "What the receipt proves" })).getByText(RECEIPT.statement.proves[0])).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "What the receipt does not prove" })).getByText("That the model acted on this content.")).toBeInTheDocument();
    expect(screen.getAllByText("d".repeat(64)).length).toBeGreaterThan(0);
    expect(screen.getByText("4,210 characters")).toBeInTheDocument();

    const aside = screen.getByRole("complementary", { name: "Receipt context" });
    expect(within(aside).getByText("External")).toBeInTheDocument();
    expect(within(aside).getByText("Suspicious")).toBeInTheDocument();
    expect(within(aside).getByText("reclassified since")).toBeInTheDocument();
    expect(within(aside).getByRole("link", { name: "Agent payments-coder" })).toHaveAttribute("href", "/agents/agt_payments");
    expect(within(aside).getByRole("link", { name: "Tool call WebFetch" })).toHaveAttribute("href", "/sessions/ses_main?invocation=inv_fetch_docs");
    expect(within(aside).getByRole("link", { name: "Open in Context Explorer" })).toHaveAttribute("href", "/context?item=ctx_readme");
    expect(within(aside).getByRole("link", { name: "Finding Instruction override in fetched page" })).toHaveAttribute("href", "/intelligence/fnd_inj");
    expect(within(aside).getByText("e".repeat(64))).toBeInTheDocument();
  });

  it("lists later events as an observed sequence with honest enforcement labels", async () => {
    const api = stubApi(receiptRoute());
    renderReceipt();
    const events = await screen.findByRole("list", { name: "Events after this item" });
    expect(screen.getByText(/observed sequence, not evidence that this item caused them/)).toBeInTheDocument();
    const denied = within(events).getByText("WebFetch to collector.example denied before it ran").closest("li") as HTMLElement;
    expect(within(denied).getByText("Deny")).toBeInTheDocument();
    expect(within(denied).getByText("Enforced")).toBeInTheDocument();
    const observed = within(events).getByText("Bash curl to upload.example violated policy (observed)").closest("li") as HTMLElement;
    expect(within(observed).getByText("Observed only")).toBeInTheDocument();
    expect(observed.textContent).not.toMatch(/\bblocked\b/i);

    fireEvent.click(screen.getByRole("button", { name: "Show more events" }));
    await waitFor(() => expect(api.gets("/context/items/ctx_readme/receipt").at(-1)?.query.get("events_limit")).toBe("50"));
  });

  it("flags a tampered receipt and an empty session history", async () => {
    stubApi(
      receiptRoute({
        ...RECEIPT,
        signature_valid: false,
        verification: { ...RECEIPT.verification, status: "invalid", explanation: "The stored fields no longer match the signature." },
        related: { ...RECEIPT.related, findings: [], subsequent_events: [], more_subsequent_events: false },
      }),
    );
    renderReceipt();
    expect((await screen.findByText(/^Signature INVALID/)).closest("[role=alert]")).toHaveTextContent("HMAC-SHA256");
    expect(screen.getByText("The stored fields no longer match the signature.")).toBeInTheDocument();
    expect(screen.getByText("Nothing was recorded in this session after this item.")).toBeInTheDocument();
    expect(screen.getByText("No findings were raised from this content.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show more events" })).not.toBeInTheDocument();
  });
});
