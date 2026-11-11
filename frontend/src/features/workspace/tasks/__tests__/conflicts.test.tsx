import { fireEvent, screen, waitFor } from "@testing-library/react";
import { ApiError } from "@/lib/api";
import { renderWithProviders } from "../../boards/__tests__/testUtils";
import { useWorkflowConflicts } from "../useWorkflowConflicts";

const WIP_MESSAGE = "'Fixing' has a WIP limit of 1 and already holds 1 task. Finish or move work out of it first, or override the limit explicitly (the override is recorded on the task).";
const GATE_MESSAGE = "CTX-3 cannot move into 'Verified': it needs passed verification evidence ('Verified' requires it; current verification status is 'unverified').";

function Harness({ error, override }: { error: unknown; override?: () => Promise<unknown> }) {
  const { report, dialog } = useWorkflowConflicts();
  return (
    <>
      <button type="button" onClick={() => report(error, { title: "CTX-3 was not moved", override })}>
        trigger
      </button>
      {dialog}
    </>
  );
}

describe("workflow conflict reporting", () => {
  it("offers an explicit WIP override that retries with the server's explanation shown", async () => {
    const override = vi.fn(() => Promise.resolve());
    renderWithProviders(<Harness error={new ApiError(409, "conflict", WIP_MESSAGE, { reason: "wip_limit_exceeded", wip_limit: 1 })} override={override} />);
    fireEvent.click(screen.getByText("trigger"));
    expect(await screen.findByText(WIP_MESSAGE)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Override WIP limit" }));
    await waitFor(() => expect(override).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("WIP limit overridden")).toBeInTheDocument();
  });

  it("explains a verification gate refusal without offering a way around it", async () => {
    renderWithProviders(<Harness error={new ApiError(409, "conflict", GATE_MESSAGE, { reason: "verification_required" })} override={() => Promise.resolve()} />);
    fireEvent.click(screen.getByText("trigger"));
    expect(await screen.findByText("CTX-3 was not moved: passed verification required")).toBeInTheDocument();
    expect(screen.getByText(GATE_MESSAGE)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Override WIP limit" })).not.toBeInTheDocument();
  });

  it("falls back to the error message for other failures", async () => {
    renderWithProviders(<Harness error={new ApiError(0, "network_error", "Cannot reach the ContextOS API. Is the backend running?")} />);
    fireEvent.click(screen.getByText("trigger"));
    expect(await screen.findByText("Cannot reach the ContextOS API. Is the backend running?")).toBeInTheDocument();
  });
});
