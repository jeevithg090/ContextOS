import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { TooltipProvider } from "@/components/ui";
import { KpiTile, formatHours, percent } from "../KpiTile";
import { RemediationPipeline } from "../RemediationPipeline";
import { TaskRowList } from "../TaskRowList";
import { oneOf } from "../useUrlState";
import type { TaskCard } from "../../types";

describe("analytics helpers", () => {
  it("formats durations and ratios without inventing values", () => {
    expect(formatHours(null)).toBe("—");
    expect(formatHours(0.5)).toBe("30 min");
    expect(formatHours(7.25)).toBe("7.3 h");
    expect(formatHours(30)).toBe("30 h");
    expect(formatHours(72)).toBe("3.0 d");
    expect(percent({ numerator: 0, denominator: 0, rate: null })).toBe("—");
    expect(percent({ numerator: 1, denominator: 3, rate: 0.3333 })).toBe("33%");
  });

  it("accepts only allowed URL values", () => {
    expect(oneOf("30d", ["7d", "30d"] as const, "7d")).toBe("30d");
    expect(oneOf("1000d", ["7d", "30d"] as const, "7d")).toBe("7d");
    expect(oneOf("", ["a", "b"] as const)).toBeUndefined();
  });
});

describe("KpiTile", () => {
  it("shows the value, what was counted and the definition", () => {
    render(
      <MemoryRouter>
        <TooltipProvider>
          <KpiTile label="Remediation completion" value="50%" detail="2 of 4 findings with a linked task" definition="Done ÷ linked." href="/work/remediation" hrefLabel="Pipeline" />
        </TooltipProvider>
      </MemoryRouter>,
    );
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("2 of 4 findings with a linked task")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /How "Remediation completion" is calculated: Done ÷ linked\./ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Pipeline/ })).toHaveAttribute("href", "/work/remediation");
  });
});

describe("RemediationPipeline", () => {
  it("shows a count per stage and toggles the stage filter", () => {
    const onSelect = vi.fn();
    const counts = { no_task: 3, task_open: 2, task_done_unverified: 1, verified: 0 };
    const { rerender } = render(<RemediationPipeline counts={counts} selected={undefined} onSelect={onSelect} loading={false} />);
    const noTask = screen.getByRole("button", { name: /No task/ });
    expect(noTask).toHaveAttribute("aria-pressed", "false");
    expect(noTask).toHaveTextContent("3");
    expect(screen.getByRole("button", { name: /Verified/ })).toHaveTextContent("0");
    fireEvent.click(noTask);
    expect(onSelect).toHaveBeenLastCalledWith("no_task");

    rerender(<RemediationPipeline counts={counts} selected="no_task" onSelect={onSelect} loading={false} />);
    const selected = screen.getByRole("button", { name: /No task/ });
    expect(selected).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(selected);
    expect(onSelect).toHaveBeenLastCalledWith(undefined);
  });
});

describe("TaskRowList", () => {
  const task: TaskCard = {
    id: "tsk_1", key: "CTX-7", number: 7, board_id: "brd_1", column_id: "col_1", column_name: "In Progress", status_key: "in_progress",
    is_done: false, position: 0, title: "Rotate the leaked deploy key", task_type: "security_vulnerability", priority: "urgent",
    severity: "critical", labels: [], assignees: [], due_date: "2020-01-01T00:00:00Z", is_overdue: true, parent_task_id: null,
    subtasks_total: 0, subtasks_done: 0, blocked_by_open: 1, verification_status: "failed", related_finding_id: null,
    related_incident_id: null, related_agent_id: null, created_at: "2020-01-01T00:00:00Z", updated_at: "2020-01-01T00:00:00Z",
    completed_at: null, archived_at: null,
  };

  it("links each row to its task page and marks overdue work", () => {
    render(
      <MemoryRouter>
        <TaskRowList tasks={[task]} aria-label="My tasks" />
      </MemoryRouter>,
    );
    const row = screen.getByRole("link", { name: /CTX-7/ });
    expect(row).toHaveAttribute("href", "/work/tasks/tsk_1");
    expect(row).toHaveTextContent("Blocked");
    expect(row).toHaveTextContent("Urgent");
    expect(row).toHaveTextContent("(overdue)");
  });

  it("drops badges in the compact layout", () => {
    render(
      <MemoryRouter>
        <TaskRowList tasks={[task]} compact aria-label="Due soon" />
      </MemoryRouter>,
    );
    const row = screen.getByRole("link", { name: /CTX-7/ });
    expect(row).not.toHaveTextContent("Urgent");
    expect(row).not.toHaveTextContent("Blocked");
  });
});
