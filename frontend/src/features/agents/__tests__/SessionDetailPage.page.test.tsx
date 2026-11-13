import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hang, notFound, renderPage, serverError, stubApi, type ApiRoute } from "@/test/pageHarness";
import { SessionDetailPage } from "../SessionDetailPage";
import type { SessionDetail, TimelineEntry } from "../types";
import { SESSION_DETAIL, TIMELINE_ENTRIES, timelinePage } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

afterEach(() => vi.unstubAllGlobals());

function routes(session: SessionDetail = SESSION_DETAIL, entries: TimelineEntry[] = TIMELINE_ENTRIES): ApiRoute {
  return (c) => {
    if (c.path === `/sessions/${session.id}`) return { body: session };
    if (c.path === `/sessions/${session.id}/timeline`) return { body: timelinePage(entries) };
    return undefined;
  };
}

const renderSession = (id = "ses_main") => renderPage(<SessionDetailPage />, { path: `/sessions/${id}`, routePath: "/sessions/:sessionId" });

/** The timeline entry whose title is `title`. */
function entry(title: string): HTMLElement {
  const timeline = screen.getByRole("list", { name: "Session timeline" });
  return within(timeline).getByText(title).closest("li") as HTMLElement;
}

describe("SessionDetailPage", () => {
  it("shows a loading state while the session loads", () => {
    stubApi(() => hang);
    renderSession();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("says the session was not found for an unknown or foreign id", async () => {
    const api = stubApi((c) => (c.path === "/sessions/ses_foreign" ? notFound("Session 'ses_foreign'") : undefined));
    renderSession("ses_foreign");
    expect(await screen.findByText("Session not found")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to agents" })).toHaveAttribute("href", "/agents");
    expect(api.gets("/sessions/ses_foreign")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi((c) => (c.path === "/sessions/ses_main" ? serverError("Session store unavailable") : undefined));
    renderSession();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Session store unavailable")).toBeInTheDocument();
  });

  it("shows the session's facts, risk, delegation, findings and links to replay and provenance", async () => {
    stubApi(routes());
    renderSession();
    expect(await screen.findByRole("heading", { name: /sess-7f3a/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Replay/ })).toHaveAttribute("href", "/replay/ses_main");
    expect(screen.getByRole("link", { name: /Provenance graph/ })).toHaveAttribute("href", "/provenance?session=ses_main");
    expect(screen.getByRole("link", { name: "Agent payments-coder" })).toHaveAttribute("href", "/agents/agt_payments");
    expect(screen.getByText("Run by", { exact: false })).toBeInTheDocument();

    expect(screen.getByText("5 (2 untrusted)")).toBeInTheDocument();
    expect(screen.getByText("Pending approvals").nextSibling).toHaveTextContent("1");
    expect(screen.getByText("Open findings").nextSibling).toHaveTextContent("2");
    expect(screen.getByText("/work/payments")).toBeInTheDocument();
    expect(screen.getByText(SESSION_DETAIL.risk.summary)).toBeInTheDocument();
    expect(screen.getByText("All three conditions present")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Why the risk score is 72" })).toBeInTheDocument();
    expect(screen.getByText("Credential read from .env")).toBeInTheDocument();

    const delegation = screen.getByRole("region", { name: "Delegation" });
    expect(within(delegation).getByText("Delegated to")).toBeInTheDocument();
    expect(within(delegation).getByRole("link", { name: "Session sess-child-1" })).toHaveAttribute("href", "/sessions/ses_child");

    const findings = screen.getByRole("region", { name: "Findings" });
    expect(within(findings).getByText("2 open of 3 in this session.")).toBeInTheDocument();
    expect(within(findings).getByRole("link", { name: "Finding Credential sent to an unclassified host" })).toHaveAttribute("href", "/intelligence/fnd_exfil");
  });

  it("labels each timeline decision with how it was enforced and only calls an enforced denial blocked", async () => {
    stubApi(routes());
    renderSession();
    expect(await screen.findByText("WebFetch to collector.example")).toBeInTheDocument();
    expect(screen.getByText("3 events")).toBeInTheDocument();

    const enforced = entry("WebFetch to collector.example");
    expect(within(enforced).getByText("Deny")).toBeInTheDocument();
    expect(within(enforced).getByText("Enforced")).toBeInTheDocument();
    expect(within(enforced).getByRole("link", { name: "Policy decision Replay decision" })).toHaveAttribute("href", "/replay/ses_main?decision=pdc_deny");

    const advisory = entry("Bash curl to upload.example");
    expect(within(advisory).getByText("Deny")).toBeInTheDocument();
    expect(within(advisory).getByText("Advisory")).toBeInTheDocument();
    expect(within(advisory).getByText("Would have been denied; the integration may not honour it.")).toBeInTheDocument();
    expect(advisory.textContent).not.toMatch(/\bblocked\b/i);

    const read = entry("Read .env");
    expect(within(read).getByRole("link", { name: "Context item Context receipt" })).toHaveAttribute("href", "/context/ctx_env");
    expect(within(read).getByText("Trusted")).toBeInTheDocument();
  });

  it("explains an empty timeline and a session without findings or delegation", async () => {
    const quiet: SessionDetail = {
      ...SESSION_DETAIL,
      children: [],
      child_count: 0,
      findings: [],
      counts: { ...SESSION_DETAIL.counts, findings_open: 0, findings_total: 0, approvals_pending: 0, decisions: {} },
    };
    stubApi(routes(quiet, []));
    renderSession();
    expect(await screen.findByText("No events recorded for this session yet.")).toBeInTheDocument();
    expect(screen.getByText("No findings were raised in this session.")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Delegation" })).not.toBeInTheDocument();
    expect(screen.queryByText("Pending approvals")).not.toBeInTheDocument();
  });

  it("shows the timeline's own error without hiding the session", async () => {
    stubApi((c) => (c.path.endsWith("/timeline") ? serverError("Timeline unavailable") : routes()(c)));
    renderSession();
    expect(await screen.findByText("Timeline unavailable")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /sess-7f3a/ })).toBeInTheDocument();
  });
});
