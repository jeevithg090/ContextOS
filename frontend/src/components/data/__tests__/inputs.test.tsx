import { act, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { SearchInput } from "../SearchInput";
import { SegmentedControl } from "../SegmentedControl";
import { JsonView } from "../JsonView";
import { EvidenceList } from "../EvidenceList";
import { ConfirmDialog } from "../ConfirmDialog";
import { TestRouter } from "@/test/router";

describe("SearchInput", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("debounces changes, clears immediately and focuses on '/'", () => {
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} debounceMs={200} />);
    const box = screen.getByRole("searchbox", { name: "Search" });

    fireEvent.change(box, { target: { value: "cur" } });
    fireEvent.change(box, { target: { value: "curl" } });
    expect(onChange).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(200));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenLastCalledWith("curl");

    fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(onChange).toHaveBeenLastCalledWith("");
    act(() => vi.advanceTimersByTime(500));
    expect(onChange).toHaveBeenCalledTimes(2);

    act(() => box.blur());
    act(() => {
      fireEvent.keyDown(window, { key: "/" });
    });
    expect(document.activeElement).toBe(box);
  });

  it("reflects external value resets without echoing them", () => {
    const onChange = vi.fn();
    const { rerender } = render(<SearchInput value="abc" onChange={onChange} />);
    expect(screen.getByRole("searchbox")).toHaveValue("abc");
    rerender(<SearchInput value="" onChange={onChange} />);
    expect(screen.getByRole("searchbox")).toHaveValue("");
    act(() => vi.advanceTimersByTime(1000));
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("SegmentedControl", () => {
  function Harness() {
    const [v, setV] = useState<"list" | "board" | "graph">("list");
    return (
      <SegmentedControl
        aria-label="View"
        value={v}
        onChange={setV}
        options={[
          { value: "list", label: "List" },
          { value: "board", label: "Board", disabled: true },
          { value: "graph", label: "Graph" },
        ]}
      />
    );
  }

  it("uses radio semantics and skips disabled options with arrow keys", () => {
    render(<Harness />);
    const list = screen.getByRole("radio", { name: "List" });
    expect(list).toHaveAttribute("aria-checked", "true");
    fireEvent.keyDown(list, { key: "ArrowRight" });
    expect(screen.getByRole("radio", { name: "Graph" })).toHaveAttribute("aria-checked", "true");
  });
});

describe("JsonView", () => {
  it("marks redacted strings and collapses nested objects", () => {
    render(<JsonView value={{ api_key: "[REDACTED:api_key:ab12cd34]", nested: { deep: { value: 1 } }, list: [1, 2] }} defaultExpandDepth={1} />);
    const marker = screen.getByText("[REDACTED:api_key:ab12cd34]");
    expect(marker).toHaveAttribute("data-redacted", "true");
    const nested = screen.getByRole("button", { name: /Expand nested/ });
    expect(nested).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(nested);
    expect(screen.getByRole("button", { name: /Collapse nested/ })).toHaveAttribute("aria-expanded", "true");
    expect(screen.queryByText(/"value"/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getByText(/"value"/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(screen.getByRole("button", { name: /Expand nested/ })).toHaveAttribute("aria-expanded", "false");
  });
});

describe("EvidenceList", () => {
  it("renders linked evidence, quoted excerpts and skips malformed entries", () => {
    render(
      <TestRouter>
        <EvidenceList
          sessionId="ses_1"
          evidence={[
            { type: "context_item", id: "ctx_1", excerpt: "ignore previous instructions, key [REDACTED:aws_key:1234abcd]", detail: "Instruction override phrase from an EXTERNAL source." },
            { type: "tool_invocation", id: "tin_1" },
            null,
            { nope: true },
          ]}
        />
      </TestRouter>,
    );
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByRole("link", { name: /Context item/ })).toHaveAttribute("href", "/context/ctx_1");
    expect(screen.getByRole("link", { name: /Tool call/ })).toHaveAttribute("href", "/sessions/ses_1?invocation=tin_1");
    expect(screen.getByText("[REDACTED:aws_key:1234abcd]")).toHaveAttribute("data-redacted", "true");
    expect(screen.getByText(/Instruction override phrase/)).toBeInTheDocument();
  });
});

describe("ConfirmDialog", () => {
  it("stays open and shows the error when the async action fails", async () => {
    const onOpenChange = vi.fn();
    const onConfirm = vi.fn().mockRejectedValue(new Error("Permission denied"));
    render(<ConfirmDialog open onOpenChange={onOpenChange} title="Revoke key" confirmLabel="Revoke" destructive onConfirm={onConfirm} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    });
    expect(onConfirm).toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("Permission denied");
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it("requires typed confirmation text when configured, then closes on success", async () => {
    const onOpenChange = vi.fn();
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(<ConfirmDialog open onOpenChange={onOpenChange} title="Delete board" confirmLabel="Delete" destructive requireText="payments" onConfirm={onConfirm} />);
    const button = screen.getByRole("button", { name: "Delete" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "payments" } });
    expect(button).toBeEnabled();
    await act(async () => {
      fireEvent.click(button);
    });
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
